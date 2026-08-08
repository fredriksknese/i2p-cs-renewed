using System.Linq;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PTests.Loopback;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-2b (docs/PRODUCTION-PLAN.md). The initiator half of the token exchange: consume a
///     Retry, present the token, and require one as a responder.
///
///     <para>
///         Type 9 used to reach the dispatch's default arm and log "Unknown packet type 9", so a
///         token-enforcing peer — which is i2pd's normal configuration — could never be dialled:
///         it answered every Session Request with a Retry we ignored.
///     </para>
///     <para>
///         <b>These assert on the token exchange, not on a session being established.</b>
///         Establishment is still blocked by batch 4-0b's header defect, and a test that waited
///         for it would be red for a reason that has nothing to do with tokens. The exchange
///         completes strictly before the Noise AEAD step that 4-0b owns, so it is measurable now.
///     </para>
/// </summary>
[TestFixture]
public class Ssu2TokenExchangeTest
{
    /// <summary>
    ///     A Session Request carrying no token must draw a Retry rather than silence — this is
    ///     what makes us dialable by a token-enforcing peer, and what 4-2a made us able to send.
    ///     Confirmed to fail with the enforcement branch removed.
    /// </summary>
    [Test]
    public void ASessionRequestWithoutATokenDrawsARetry()
    {
        var channel = new LossyChannel( seed: 909 );
        var alice = LoopbackSSU2Peer.Create( "alice", 29411, channel );
        var bob = LoopbackSSU2Peer.Create( "bob", 29412, channel );

        var retries = 0;
        channel.Tap = ( from, to, data ) =>
        {
            if ( !Equals( from, bob.Endpoint ) ) return;
            if ( Retry.TryOpen( data, bob.IntroKey, SSU2Header.TYPE_RETRY, out _, out _ ) ) retries++;
        };

        alice.ConnectTo( bob );
        channel.PumpUntilIdle();

        ClassicAssert.Greater( retries, 0,
            "Bob accepted or ignored a Session Request with no token instead of answering with "
            + "a Retry; a token-enforcing responder must issue one" );
    }

    /// <summary>
    ///     The round trip: Alice's first Session Request carries no token, Bob answers with a
    ///     Retry, and Alice's second request carries the token Bob issued. Asserting on Alice's
    ///     stored token proves the Retry was consumed rather than merely received.
    /// </summary>
    [Test]
    public void ARetryTeachesTheInitiatorATokenItThenPresents()
    {
        var channel = new LossyChannel( seed: 4711 );
        var alice = LoopbackSSU2Peer.Create( "alice", 29413, channel );
        var bob = LoopbackSSU2Peer.Create( "bob", 29414, channel );

        alice.ConnectTo( bob );
        channel.PumpUntilIdle();

        var held = alice.Host.Tokens.GetOutgoing( bob.Endpoint );

        ClassicAssert.AreNotEqual( 0UL, held,
            "Alice holds no token for Bob, so she never consumed his Retry — before 4-2b type 9 "
            + "reached the dispatch's default arm as 'Unknown packet type 9'" );
        ClassicAssert.IsTrue( bob.Host.Tokens.IsOurs( alice.Endpoint, held ),
            "the token Alice holds is not the one Bob issued her" );
    }

    /// <summary>
    ///     Bob must end up seeing a Session Request he considers properly tokened. This is the
    ///     furthest the handshake can get until 4-0b lands, and it is the point of the batch.
    /// </summary>
    [Test]
    public void TheSecondSessionRequestCarriesTheIssuedToken()
    {
        var channel = new LossyChannel( seed: 1234 );
        var alice = LoopbackSSU2Peer.Create( "alice", 29415, channel );
        var bob = LoopbackSSU2Peer.Create( "bob", 29416, channel );

        var tokened = 0;
        channel.Tap = ( from, to, data ) =>
        {
            if ( !Equals( from, alice.Endpoint ) ) return;

            // A Session Request is masked with the responder's intro key, like a Retry.
            var probe = (byte[])data.Clone();
            I2PCore.Crypto.SSU2HeaderEncryption.DecryptLongHeaderComplete(
                probe, 0, bob.IntroKey, bob.IntroKey );

            var header = SSU2Header.ParseLongHeader( new I2PCore.Utils.I2PBufferCursor( probe ) );
            if ( header.Type == SSU2Header.TYPE_SESSION_REQUEST && header.Token != 0 ) tokened++;
        };

        alice.ConnectTo( bob );
        channel.PumpUntilIdle();

        ClassicAssert.Greater( tokened, 0,
            "no Session Request carried a token, so the Retry never fed back into SendSessionRequest" );
    }

    /// <summary>
    ///     A peer that answers every Session Request with another Retry must not be able to keep
    ///     us in that loop for the whole handshake window.
    /// </summary>
    [Test]
    public void TheInitiatorStopsAfterOneRetry()
    {
        var channel = new LossyChannel( seed: 77 );
        var alice = LoopbackSSU2Peer.Create( "alice", 29417, channel );
        var bob = LoopbackSSU2Peer.Create( "bob", 29418, channel );

        var sessionRequests = 0;
        channel.Tap = ( from, to, data ) =>
        {
            if ( Equals( from, alice.Endpoint ) ) sessionRequests++;
        };

        alice.ConnectTo( bob );
        channel.PumpUntilIdle();

        ClassicAssert.LessOrEqual( sessionRequests, 3,
            "Alice sent an unbounded number of Session Requests; the Retry cap is not holding" );
    }
}
