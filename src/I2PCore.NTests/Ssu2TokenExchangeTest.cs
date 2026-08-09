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
///         <b>These assert on the token exchange, not on a session being established.</b> When
///         they were written, establishment was blocked by batch 4-0b's header defect and a test
///         that waited for it would have been red for a reason that has nothing to do with
///         tokens. **4-0b and 4-0h have since landed and the handshake completes**, but the
///         narrower assertions are kept deliberately: a token test that passes only because the
///         whole handshake works tells you less, not more, and it goes red for every reason under
///         the sun.
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
    ///     <b>The 4-0m defect, and the cause of the intermittent failure recorded against
    ///     4-0l.</b> <c>ARetryTeachesTheInitiatorATokenItThenPresents</c> failed once in twelve
    ///     full-suite runs with <c>ProcessSessionCreated ... AEAD authentication failed</c>: Bob's
    ///     Retry was dispatched to the Session Created handler.
    ///
    ///     <para>
    ///         In state <c>SessionRequestSent</c>, <c>PeekMessageType</c> trial-decrypts with the
    ///         derived <c>SessCreateHeader</c> key first. That key is wrong for a Retry, so the
    ///         type byte it reads is <b>uniformly random</b> — and one value in 256 is
    ///         <c>TYPE_SESSION_CREATED</c>. Ordering the trials, which batch 4-0h did, lowers the
    ///         odds from one in sixty to one in 256; it does not remove them. The token is then
    ///         never learned and the session stalls, which against a token-enforcing peer — i2pd's
    ///         normal configuration — is a handshake that fails outright.
    ///     </para>
    ///     <para>
    ///         <b>The remedy was already written down next door.</b>
    ///         <see cref="TheInitiatorStopsAfterOneRetry" /> identifies a message by type
    ///         <em>and</em> version <em>and</em> netid precisely because one field decoded under
    ///         the wrong key agrees once in 256. The production dispatcher checked one field.
    ///     </para>
    ///     <para>
    ///         <b>Measured by consequence, not by exception.</b> A Retry that reaches
    ///         <c>ProcessRetry</c> makes Alice re-send her Session Request with the new token, so
    ///         one extra datagram leaves her. A mis-dispatched one produces nothing at all —
    ///         <c>ProcessSessionCreated</c> rejects the garbage header quietly rather than
    ///         throwing, which is why counting exceptions measures nothing. A fresh session per
    ///         iteration keeps the one-Retry budget from being spent and gives each sample an
    ///         independent chaining key. The channel is never pumped, so Bob stays out of it.
    ///     </para>
    /// </summary>
    [Test]
    public void ARetryIsNeverMistakenForASessionCreated()
    {
        const int samples = 3000;

        var channel = new LossyChannel( seed: 5150 );
        var alice = LoopbackSSU2Peer.Create( "alice", 29419, channel );
        var bob = LoopbackSSU2Peer.Create( "bob", 29420, channel );

        var consumed = 0;

        for ( var i = 0; i < samples; i++ )
        {
            var session = alice.ConnectTo( bob );

            var request = new SSU2Header
            {
                IsLongHeader = true,
                Type = SSU2Header.TYPE_SESSION_REQUEST,
                Version = 2,
                NetId = (byte)I2PCore.Data.I2PConstants.I2PNetworkId,
                DestinationConnectionId = 0x4242_0000_0000_0000UL | (uint)i,
                SourceConnectionId = 0x8888_0000_0000_0000UL | (uint)i,
                PacketNumber = (uint)i
            };

            var packet = Retry.Build( request, 0x1234_5678UL + (ulong)i, bob.IntroKey, bob.Endpoint );

            var before = channel.SentCount;
            session.ProcessReceivedPacket( packet );
            if ( channel.SentCount > before ) consumed++;
        }

        // One tolerated, and the arithmetic is the reason rather than a shrug. Fixed, a false
        // match needs type *and* version *and* netid to agree at 1 in 16.7 million, so 3000
        // samples miss 1.8e-4 times: demanding a clean sweep would make this test itself fail
        // about one run in 5600. Broken, the rate is 1 in 256 and the expected count is 11.7, so
        // a regression still shows up here 99.99% of the time.
        ClassicAssert.GreaterOrEqual( consumed, samples - 1,
            $"{samples - consumed} of {samples} Retries never reached ProcessRetry. The "
            + "SessCreateHeader key is wrong for a Retry, so the type byte it yields is random "
            + "and matches TYPE_SESSION_CREATED once in 256. Require version and netid to agree "
            + "as well, as TheInitiatorStopsAfterOneRetry already does." );
    }

    /// <summary>
    ///     A peer that answers every Session Request with another Retry must not be able to keep
    ///     us in that loop for the whole handshake window.
    ///
    ///     <para>
    ///         <b>This counted every datagram Alice sent, and batch 4-0h invalidated that
    ///         proxy.</b> While the handshake stalled at the Session Created, "datagrams from
    ///         Alice" and "Session Requests from Alice" were the same number; now that it
    ///         completes, Alice also sends a Session Confirmed across two fragments and the count
    ///         reached 4 against a cap of 3 — with the Retry cap working perfectly. A test whose
    ///         measurement stops meaning what its name says is worse than no test, so it now
    ///         counts what it claims to.
    ///     </para>
    ///     <para>
    ///         Identified by type <em>and</em> version <em>and</em> netid rather than type alone:
    ///         a Session Confirmed is a short header masked with a different key, so decoding it
    ///         this way yields a random type byte that would read as a Session Request once in
    ///         256. Three agreeing fields make that one in sixteen million.
    ///     </para>
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
            if ( !Equals( from, alice.Endpoint ) ) return;

            var probe = (byte[])data.Clone();
            I2PCore.Crypto.SSU2HeaderEncryption.DecryptLongHeaderComplete(
                probe, 0, bob.IntroKey, bob.IntroKey );

            var header = SSU2Header.ParseLongHeader( new I2PCore.Utils.I2PBufferCursor( probe ) );

            if ( header.Type == SSU2Header.TYPE_SESSION_REQUEST
                 && header.Version == 2
                 && header.NetId == (byte)I2PCore.Data.I2PConstants.I2PNetworkId ) sessionRequests++;
        };

        alice.ConnectTo( bob );
        channel.PumpUntilIdle();

        ClassicAssert.LessOrEqual( sessionRequests, 2,
            "Alice sent more than the original Session Request and one re-send; the Retry cap "
            + "is not holding" );
    }
}
