using System;
using System.Linq;
using System.Net;
using I2PCore.Data;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;
using I2PTests.Loopback;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-2a (docs/PRODUCTION-PLAN.md). i2pd's first packet to a peer it holds no token for
///     is a <b>TokenRequest</b> (type 10), and nothing here handled it — it fell through
///     <c>SSU2Host.DispatchPacket</c>'s final <c>else</c>. An inbound SSU2 session from i2pd could
///     not begin at all.
/// </summary>
[TestFixture]
public class Ssu2RetryTokenTest
{
    private static readonly IPEndPoint Remote = new( IPAddress.Parse( "192.0.2.7" ), 29001 );
    private static readonly byte[] IntroKey = Enumerable.Range( 0, 32 ).Select( i => (byte)( i * 5 + 11 ) ).ToArray();

    private int _originalNetworkId;

    [SetUp]
    public void SetUp()
    {
        _originalNetworkId = I2PConstants.I2PNetworkId;
    }

    [TearDown]
    public void TearDown()
    {
        I2PConstants.I2PNetworkId = _originalNetworkId;
    }

    /// <summary>
    ///     <b>The most valuable test in the batch, and the only one measured against bytes we did
    ///     not produce.</b> Drives the real i2pd TokenRequest captured by batch 3-5 through the
    ///     production entry point.
    ///
    ///     <para>
    ///         The Poly1305 tag authenticates with AD = all 32 plaintext header bytes, so a pass
    ///         here proves every header byte was recovered exactly as i2pd wrote it — much
    ///         stronger than the three bytes <c>Ssu2GoldenVectorTest</c> asserts. It confirms, at
    ///         once: the ChaCha20 block-1 keystream (batch 4-0), the two IV-derived 8-byte masks
    ///         plus one 16-byte zero-nonce pass, and <c>ChaCha20Poly1305.CreateNonce</c>.
    ///     </para>
    /// </summary>
    [Test]
    public void WeCanAuthenticateTheTokenRequestI2pdReallySent()
    {
        var vector = GoldenVectors.Read( GoldenVectors.Ssu2TokenRequest );
        I2PConstants.I2PNetworkId = 99; // the capture's network

        var opened = Retry.TryOpen(
            vector["packet"], vector["intro_key"], SSU2Header.TYPE_TOKEN_REQUEST,
            out var header, out var payload );

        ClassicAssert.IsTrue( opened,
            "the TokenRequest i2pd really sent did not authenticate against our implementation" );
        ClassicAssert.AreEqual( SSU2Header.TYPE_TOKEN_REQUEST, header.Type );
        ClassicAssert.AreEqual( 2, header.Version );
        ClassicAssert.AreEqual( 99, header.NetId );
        ClassicAssert.AreEqual( 0UL, header.Token,
            "a TokenRequest asks for a token; it carries none" );

        // DateTime block (type 0, length 4) then Padding (type 254).
        ClassicAssert.AreEqual( 0, payload[0], "first block should be DateTime" );
        ClassicAssert.AreEqual( 4, ( payload[1] << 8 ) | payload[2] );
        ClassicAssert.AreEqual( 0xFE, payload[7], "second block should be Padding" );
    }

    /// <summary>
    ///     The Retry must be readable by the same code path that reads i2pd's TokenRequest — and
    ///     that path is exercised against real bytes by the test above, so this is not merely
    ///     self-agreement.
    /// </summary>
    [Test]
    public void ARetryCarriesTheTokenWeIssuedAndEchoesTheConnectionIds()
    {
        var request = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_TOKEN_REQUEST,
            Version = 2,
            NetId = (byte)I2PConstants.I2PNetworkId,
            DestinationConnectionId = 0x1122334455667788,
            SourceConnectionId = 0x99AABBCCDDEEFF00,
            PacketNumber = 4242
        };

        const ulong token = 0xFEEDFACECAFEBEEF;
        var packet = Retry.Build( request, token, IntroKey, Remote );

        ClassicAssert.IsTrue(
            Retry.TryOpen( packet, IntroKey, SSU2Header.TYPE_RETRY, out var header, out _ ),
            "our own Retry did not authenticate" );

        ClassicAssert.AreEqual( token, header.Token );

        // Echoed, not recomputed: i2pd routes by the destination connection ID it recovers, and a
        // Retry addressed to anything else is dropped silently at both ends.
        ClassicAssert.AreEqual( request.SourceConnectionId, header.DestinationConnectionId,
            "the Retry must be addressed to the connection ID the requester used as its source" );
        ClassicAssert.AreEqual( request.DestinationConnectionId, header.SourceConnectionId );
    }

    /// <summary>
    ///     Batch 4-0d's rule, applied to a message type that did not exist when it ran.
    /// </summary>
    [Test]
    public void ARetryAnnouncesTheConfiguredNetwork()
    {
        I2PConstants.I2PNetworkId = 3; // the netid the plan mandates for local testing

        var packet = Retry.Build( NewRequest(), 1, IntroKey, Remote );

        ClassicAssert.IsTrue( Retry.TryOpen( packet, IntroKey, SSU2Header.TYPE_RETRY, out var h, out _ ) );
        ClassicAssert.AreEqual( 3, h.NetId );
    }

    /// <summary>
    ///     A note to batch 4-0b, which changes how Session Request and Session Created mask bytes
    ///     16..64. The captured TokenRequest pins the <b>16-byte</b> tail form for these two types,
    ///     so 4-0b must add a new method rather than change the one this path uses. If 4-0b
    ///     breaks that, this goes red rather than the interop being discovered later.
    /// </summary>
    [Test]
    public void TheRetryPathIsUnaffectedByTheFortyEightBytePass()
    {
        var packet = Retry.Build( NewRequest(), 7, IntroKey, Remote );

        ClassicAssert.IsTrue(
            Retry.TryOpen( packet, IntroKey, SSU2Header.TYPE_RETRY, out _, out _ ),
            "the Retry no longer round-trips: if batch 4-0b changed the shared masking helper, "
            + "it must introduce a separate 48-byte method instead" );
    }

    [Test]
    public void AGarbledPacketIsRejectedRatherThanParsed()
    {
        var packet = Retry.Build( NewRequest(), 5, IntroKey, Remote );
        packet[^1] ^= 0xFF; // corrupt the tag

        ClassicAssert.IsFalse(
            Retry.TryOpen( packet, IntroKey, SSU2Header.TYPE_RETRY, out _, out _ ),
            "a packet failing AEAD must not be accepted" );
    }

    [Test]
    public void ATokenIsAcceptedOnlyFromTheEndpointItWasIssuedTo()
    {
        var cache = new SSU2TokenCache();
        var other = new IPEndPoint( IPAddress.Parse( "198.51.100.9" ), 29001 );

        var token = cache.Issue( Remote );

        ClassicAssert.IsTrue( cache.IsOurs( Remote, token ) );
        ClassicAssert.IsFalse( cache.IsOurs( other, token ),
            "a token must not be spendable from a different endpoint" );
        ClassicAssert.IsFalse( cache.IsOurs( Remote, token ^ 1 ) );
        ClassicAssert.IsFalse( cache.IsOurs( Remote, 0 ),
            "zero means 'no token' on the wire and is never valid" );
    }

    [Test]
    public void TokensExpire()
    {
        var cache = new SSU2TokenCache( TickSpan.Milliseconds( 40 ), TickSpan.Milliseconds( 40 ) );

        var token = cache.Issue( Remote );
        ClassicAssert.IsTrue( cache.IsOurs( Remote, token ) );

        System.Threading.Thread.Sleep( 120 );

        ClassicAssert.IsFalse( cache.IsOurs( Remote, token ),
            "an expired token must not be accepted" );
    }

    /// <summary>
    ///     Tokens we issue and tokens a peer issues us are separate, so a peer's own token cannot
    ///     be replayed back at it.
    /// </summary>
    [Test]
    public void IssuedAndReceivedTokensDoNotLeakIntoEachOther()
    {
        var cache = new SSU2TokenCache();

        var ours = cache.Issue( Remote );
        cache.StoreReceived( Remote, 0xABCDEF );

        ClassicAssert.AreEqual( 0xABCDEF, cache.GetOutgoing( Remote ),
            "GetOutgoing must return the peer's token, not ours" );
        ClassicAssert.IsTrue( cache.IsOurs( Remote, ours ) );
        ClassicAssert.IsFalse( cache.IsOurs( Remote, 0xABCDEF ),
            "a token the peer gave us must not be accepted as one we issued" );
    }

    /// <summary>
    ///     The batch's actual deliverable, end to end: an inbound TokenRequest must be answered
    ///     with a Retry. Before 4-2a type 10 fell through <c>DispatchPacket</c>'s final
    ///     <c>else</c> to "Received packet type 10 from unknown endpoint", so an inbound SSU2
    ///     session from i2pd could not begin. Confirmed to fail with that branch removed.
    ///
    ///     <para>
    ///         Uses the socket-free loopback fixture from batch 3-3, so this needs no i2pd, no
    ///         ports and no handshake — and note it deliberately asserts on the <b>reply</b>
    ///         rather than on a session being established, because establishment is still blocked
    ///         on 4-0b.
    ///     </para>
    /// </summary>
    [Test]
    public void AnInboundTokenRequestIsAnsweredWithARetry()
    {
        var channel = new LossyChannel( seed: 4242 );
        var alice = LoopbackSSU2Peer.Create( "alice", 29401, channel );
        var bob = LoopbackSSU2Peer.Create( "bob", 29402, channel );

        byte[] reply = null;
        channel.Tap = ( from, to, data ) =>
        {
            if ( Equals( from, bob.Endpoint ) && Equals( to, alice.Endpoint ) ) reply = data;
        };

        // A TokenRequest carries no token and is masked with the *responder's* intro key.
        var request = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_TOKEN_REQUEST,
            Version = 2,
            NetId = (byte)I2PConstants.I2PNetworkId,
            DestinationConnectionId = 0x5150,
            SourceConnectionId = 0x6161,
            Token = 0,
            PacketNumber = 99
        };

        channel.Send( alice.Endpoint, bob.Endpoint, BuildTokenRequest( request, bob.IntroKey ) );
        channel.PumpUntilIdle();

        ClassicAssert.IsNotNull( reply,
            "Bob did not answer the TokenRequest at all; type 10 is being ignored" );

        ClassicAssert.IsTrue(
            Retry.TryOpen( reply, bob.IntroKey, SSU2Header.TYPE_RETRY, out var retry, out _ ),
            "Bob's reply is not a Retry we can authenticate with his intro key" );

        ClassicAssert.AreNotEqual( 0UL, retry.Token, "a Retry must carry a usable token" );
        ClassicAssert.AreEqual( request.SourceConnectionId, retry.DestinationConnectionId,
            "the Retry must be addressed back to the requester's source connection ID" );
    }

    /// <summary>
    ///     A TokenRequest built the way i2pd builds one — same masking and AEAD as a Retry, only
    ///     the type differs. Verified against real i2pd bytes by
    ///     <see cref="WeCanAuthenticateTheTokenRequestI2pdReallySent" />.
    /// </summary>
    private static byte[] BuildTokenRequest( SSU2Header header, byte[] introKey )
    {
        var headerBytes = header.ToByteArray();
        var payload = new DateTimeBlock().Serialize();
        var padded = new byte[payload.Length + 3 + 32];
        Array.Copy( payload, padded, payload.Length );
        Array.Copy( new PaddingBlock( 32 ).Serialize(), 0, padded, payload.Length, 35 );

        var encrypted = I2PCore.Crypto.ChaCha20Poly1305.Encrypt(
            introKey, I2PCore.Crypto.ChaCha20Poly1305.CreateNonce( header.PacketNumber ),
            padded, headerBytes );

        var packet = new byte[headerBytes.Length + encrypted.Length];
        Array.Copy( headerBytes, packet, headerBytes.Length );
        Array.Copy( encrypted, 0, packet, headerBytes.Length, encrypted.Length );

        I2PCore.Crypto.SSU2HeaderEncryption.EncryptLongHeaderComplete( packet, 0, introKey, introKey );

        return packet;
    }

    private static SSU2Header NewRequest()
    {
        return new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_TOKEN_REQUEST,
            Version = 2,
            NetId = (byte)I2PConstants.I2PNetworkId,
            DestinationConnectionId = 0xAAAA,
            SourceConnectionId = 0xBBBB,
            PacketNumber = 1
        };
    }
}
