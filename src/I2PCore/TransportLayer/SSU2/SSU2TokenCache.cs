using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     SSU2 anti-DoS tokens, per <see cref="SSU2Host" />.
///
///     <para>
///         Batch 4-2a (docs/PRODUCTION-PLAN.md). A token is a 64-bit opaque value issued by the
///         <b>responder</b> and presented by the <b>initiator</b> in its Session Request header.
///         It proves the initiator can receive at the address it claims, so the responder need
///         not do an X25519 exchange for a spoofed packet. It is <b>not</b> a key and never
///         enters the Noise state.
///     </para>
///     <para>
///         <b>Two maps, deliberately.</b> Tokens we issued and tokens a peer issued to us have
///         different lifetimes and different trust: one we must accept, the other we must
///         present. Conflating them would let a peer's own token be replayed back at it.
///     </para>
///     <para>
///         <b>Per host, not static.</b> Batch 3-3 gave <see cref="SSU2Host" /> an instance
///         constructor precisely so two hosts can coexist in one process, and Phase 8's
///         de-singleton work depends on that staying true. A static cache here would re-break it.
///     </para>
///     <para>
///         Expiry is <see cref="TickCounter" />, never <c>DateTime</c> — see CLAUDE.md. Entries
///         expire on read as well as on the periodic sweep, because the socket-free test host
///         runs no worker thread to sweep with.
///     </para>
/// </summary>
internal sealed class SSU2TokenCache
{
    /// <summary>
    ///     A Retry carries no expiry field, so lifetime is local policy on both sides rather than
    ///     anything on the wire. We hold a peer's token for less time than we honour our own, so
    ///     we never present one the peer has already dropped.
    /// </summary>
    internal static readonly TickSpan DefaultIssuedLifetime = TickSpan.Minutes( 60 );

    internal static readonly TickSpan DefaultReceivedLifetime = TickSpan.Minutes( 50 );

    /// <summary>
    ///     The issued map is keyed by an unauthenticated remote endpoint, so it is a
    ///     memory-amplification target. Refuse beyond this rather than evicting, so a flood
    ///     cannot displace legitimate entries.
    /// </summary>
    internal const int MaxEntries = 5000;

    private readonly TickSpan _issuedLifetime;
    private readonly TickSpan _receivedLifetime;

    // Keyed on address *and* port: IPEndPoint has value equality, and address-only keying would
    // let anything behind the same NAT spend another host's token.
    private readonly ConcurrentDictionary<IPEndPoint, Entry> _issued = new();
    private readonly ConcurrentDictionary<IPEndPoint, Entry> _received = new();

    internal SSU2TokenCache( TickSpan issuedLifetime = null, TickSpan receivedLifetime = null )
    {
        _issuedLifetime = issuedLifetime ?? DefaultIssuedLifetime;
        _receivedLifetime = receivedLifetime ?? DefaultReceivedLifetime;
    }

    internal int IssuedCount => _issued.Count;
    internal int ReceivedCount => _received.Count;

    /// <summary>
    ///     Mint a token for <paramref name="remote" />, remember it, and return it. Replaces any
    ///     previous token for that endpoint — a peer asking again is a peer that lost the last one.
    /// </summary>
    internal ulong Issue( IPEndPoint remote )
    {
        // Idempotent while the token is still valid. Minting a fresh one on every ask would
        // invalidate a token already in flight: a peer that re-sends a Session Request before our
        // Retry reaches it would then present a token we had just replaced, and be answered with
        // yet another Retry. Observed exactly that as a token exchange that never converged.
        if ( TryGet( _issued, remote, _issuedLifetime, out var existing ) ) return existing;

        if ( _issued.Count >= MaxEntries && !_issued.ContainsKey( remote ) )
        {
            Logging.LogDebug(
                $"SSU2TokenCache: refusing to issue a token to {remote}; at the {MaxEntries} cap" );
            return 0;
        }

        var token = NewToken();
        _issued[remote] = new Entry( token, TickCounter.Now );

        return token;
    }

    /// <summary>
    ///     Whether <paramref name="token" /> is one we issued to this endpoint and has not
    ///     expired. A zero token means "none", and is never valid.
    /// </summary>
    internal bool IsOurs( IPEndPoint remote, ulong token )
    {
        if ( token == 0 ) return false;

        return TryGet( _issued, remote, _issuedLifetime, out var stored ) && stored == token;
    }

    /// <summary>Remember a token a peer issued to us, for our next Session Request.</summary>
    internal void StoreReceived( IPEndPoint remote, ulong token )
    {
        if ( token == 0 ) return;

        if ( _received.Count >= MaxEntries && !_received.ContainsKey( remote ) )
        {
            Logging.LogDebug( $"SSU2TokenCache: dropping a token from {remote}; at the {MaxEntries} cap" );
            return;
        }

        _received[remote] = new Entry( token, TickCounter.Now );
    }

    /// <summary>
    ///     The token to put in a Session Request to <paramref name="remote" />, or 0 for "I have
    ///     none" — which is the correct on-the-wire value, not an error.
    /// </summary>
    internal ulong GetOutgoing( IPEndPoint remote )
    {
        return TryGet( _received, remote, _receivedLifetime, out var token ) ? token : 0;
    }

    /// <summary>Drop expired entries. Cheap enough to run from the host's worker loop.</summary>
    internal void Prune()
    {
        Sweep( _issued, _issuedLifetime );
        Sweep( _received, _receivedLifetime );
    }

    private static void Sweep( ConcurrentDictionary<IPEndPoint, Entry> map, TickSpan lifetime )
    {
        foreach ( var key in map
                     .Where( kv => kv.Value.Stored.DeltaToNow > lifetime )
                     .Select( kv => kv.Key )
                     .ToArray() )
            map.TryRemove( key, out _ );
    }

    private static bool TryGet(
        ConcurrentDictionary<IPEndPoint, Entry> map, IPEndPoint remote, TickSpan lifetime, out ulong token )
    {
        token = 0;

        if ( !map.TryGetValue( remote, out var entry ) ) return false;

        if ( entry.Stored.DeltaToNow > lifetime )
        {
            // Expire on read, so correctness does not depend on the sweep having run.
            map.TryRemove( remote, out _ );
            return false;
        }

        token = entry.Token;
        return true;
    }

    /// <summary>
    ///     CSPRNG, the same idiom as <c>SSU2Session.LocalConnectionId</c>. A token is
    ///     unauthenticated anti-replay state, so it must not come from a predictable source;
    ///     batch 1-3's <c>NoSystemRandomUnderI2PCore</c> scan enforces that repo-wide. Zero means
    ///     "no token" on the wire, so it is regenerated rather than issued.
    ///
    ///     <para>
    ///         The wording here avoids naming the banned constructor literally: that scan does not
    ///         strip comments, so prose describing the rule trips it. Recorded as a follow-up in
    ///         docs/PRODUCTION-PLAN.md rather than widening this batch.
    ///     </para>
    /// </summary>
    private static ulong NewToken()
    {
        ulong token;
        do
        {
            token = BufUtils.RandomUint() | ( (ulong)BufUtils.RandomUint() << 32 );
        } while ( token == 0 );

        return token;
    }

    private readonly record struct Entry( ulong Token, TickCounter Stored );
}
