using System.Net;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;

namespace I2PTests.Loopback;

/// <summary>
///     Two <see cref="SSU2Session" /> objects driven against each other over a
///     <see cref="LossyChannel" /> — no sockets, no NetDb, no router, no i2pd.
///
///     Batch 3-3 (docs/PRODUCTION-PLAN.md).
///
///     <para>
///         <b>This is the first thing in the repository to exercise the SSU2 handshake.</b>
///         <c>SSU2ProtocolTest</c> covers constants, header round-trips, fragmentation and ACK
///         bookkeeping, but never runs a handshake; the integration suite does not either,
///         because SSU2 has been off by default since batch 0-4. The quarantined tests below are
///         therefore the first measurements of SSU2 session establishment, and they are red.
///     </para>
///     <para>
///         <b>Quarantined, not deleted</b> — each names the batch that owns it, per
///         <see cref="TestCategories.Experimental" />. They are the specification for Phase 4.
///     </para>
///     <para>
///         <b>Nothing here ticks the sessions periodically, because there is nothing to tick.</b>
///         <c>SSU2Host.ProcessSessions</c> only reaps terminated sessions, and no other periodic
///         work touches a session — SSU2 has no timer-driven behaviour of any kind. That is a
///         finding for batch 4-1, which has to add the tick before it can hang
///         <c>GenerateAck()</c> or retransmission on one.
///     </para>
/// </summary>
[TestFixture]
public class SSU2LoopbackTest
{
    private const int MessageCount = 100;
    private const int AlicePort = 41000;
    private const int BobPort = 41001;

    /// <summary>
    ///     The SSU2 handshake does not complete even between two of our own sessions on a
    ///     lossless in-memory channel. Still red after batch 4-0b, but it now fails a message
    ///     later and for a different, identified reason.
    ///
    ///     <para>
    ///         <b>Fixed since this was written.</b> The AEAD failure in
    ///         <c>ProcessSessionRequest</c> was the header-encryption divergence: Alice masked
    ///         packet bytes 0-15 while Bob unmasked 0-31, so Bob hashed a header Alice never
    ///         built. Batch 4-0b closed it, and the fixture now reaches
    ///         <c>sent=2</c> — Bob logs <c>SessionRequest received and validated</c> and replies
    ///         with a SessionCreated.
    ///     </para>
    ///     <para>
    ///         <b>Where it stops now: Alice logs <c>Unknown packet type 160</c>.</b>
    ///         <c>ProcessReceivedPacket</c> peeks the message type by trial-decrypting the long
    ///         header with <c>k_header_2 = k_header_1 = </c> the intro key. That is right for a
    ///         Session Request and wrong for a Session Created, whose k_header_2 is
    ///         <c>HKDF(chainKey, "SessCreateHeader")</c> — the very derivation
    ///         <c>ProcessSessionCreated</c> performs correctly two calls later. The type byte
    ///         lives at offset 12, inside the group k_header_2 masks, so Alice can never read the
    ///         type of the reply she is waiting for and drops it in the <c>default</c> arm.
    ///     </para>
    ///
    ///     Owner: the next SSU2 batch. Batch 4-1 wires ACKs on top of a handshake that has to
    ///     work first.
    /// </summary>
    [Test]
    [Category(TestCategories.Experimental)]
    public void HandshakeCompletesOnACleanChannel()
    {
        var (channel, alice, bob) = BuildPair();

        alice.ConnectTo(bob);
        channel.PumpUntilIdle();

        Assert.That(alice.Established, Is.Not.Empty,
            $"SSU2 handshake did not complete on a lossless channel. {channel}");
    }

    /// <summary>
    ///     The plan's stated 3-3 gate: 0% loss delivers 100/100. Blocked by
    ///     <see cref="HandshakeCompletesOnACleanChannel" /> — there is no data phase to measure
    ///     until the handshake completes. Owner: Phase 4.
    /// </summary>
    [Test]
    [Category(TestCategories.Experimental)]
    public void CleanChannelDeliversEveryMessage()
    {
        var (channel, alice, bob) = BuildPair();

        var session = alice.ConnectTo(bob);
        channel.PumpUntilIdle();
        bob.ObserveNewSessions();

        Assume.That(alice.Established, Is.Not.Empty,
            "Handshake did not complete; see HandshakeCompletesOnACleanChannel.");

        for (var i = 0; i < MessageCount; i++)
            session.Send(BuildMessage(i));

        channel.PumpUntilIdle();

        Assert.That(bob.Received.Count, Is.EqualTo(MessageCount),
            $"Expected all {MessageCount} messages through a lossless channel. {channel}");
    }

    /// <summary>
    ///     The 4-1 defect. SSU2 has no ACK or retransmit path in production code:
    ///     <c>SSU2AckManager</c> is a complete, unit-tested class nothing instantiates, and the
    ///     ACK block case in <c>SSU2Session</c> is empty — so a dropped datagram is simply gone.
    ///     Also blocked by the handshake. Owner: batch 4-1.
    /// </summary>
    [Test]
    [Category(TestCategories.Experimental)]
    public void LossAtFivePercentStillDeliversEveryMessage()
    {
        var (channel, alice, bob) = BuildPair();

        // Handshake on a clean channel: this test is about the data phase, and a handshake
        // failing for loss reasons would be a different (also real) defect.
        var session = alice.ConnectTo(bob);
        channel.PumpUntilIdle();
        bob.ObserveNewSessions();

        Assume.That(alice.Established, Is.Not.Empty,
            "Handshake did not complete; see HandshakeCompletesOnACleanChannel.");

        channel.DropProbability = 0.05;

        for (var i = 0; i < MessageCount; i++)
            session.Send(BuildMessage(i));

        channel.PumpUntilIdle();

        Assert.That(bob.Received.Count, Is.EqualTo(MessageCount),
            $"5% loss must still deliver every message once SSU2 retransmits. {channel}");
    }

    /// <summary>
    ///     SSU2 announces network ID 2 — the live network — whatever
    ///     <see cref="I2PConstants.I2PNetworkId" /> is set to. <c>SendSessionRequest</c> and
    ///     <c>SendSessionCreated</c> each build their header with a literal <c>NetId = 2</c>,
    ///     while <c>SSU2SecurityValidator.ValidateVersionAndNetId</c> correctly compares the
    ///     received value against the configured one.
    ///
    ///     <para>
    ///         The two disagree on every network except the default, so <b>SSU2 cannot establish
    ///         a session on any non-default netid at all</b>: the responder rejects the
    ///         initiator's first packet. That includes netid 3, which this repository's safety
    ///         rule mandates for all testing, and netid 99, which the integration suite uses. Any
    ///         Phase 4 work measured on a private network hits this before it reaches anything
    ///         about ACKs or Retry.
    ///     </para>
    ///
    ///     Owner: Phase 4. Related: session 2 recorded that inbound NTCP2 never validates the
    ///     peer's netId either, so netid handling wants an audit across both transports.
    /// </summary>
    [Test]
    [Category(TestCategories.Experimental)]
    public void SessionRequestAnnouncesTheConfiguredNetworkId()
    {
        var originalNetId = I2PConstants.I2PNetworkId;
        I2PConstants.I2PNetworkId = 3;

        try
        {
            var (channel, alice, bob) = BuildPair();

            byte[] firstDatagram = null;
            channel.Tap = (_, _, data) => firstDatagram ??= data;

            alice.ConnectTo(bob);

            Assert.That(firstDatagram, Is.Not.Null, "Alice sent no SessionRequest");

            // For a SessionRequest both header keys are Bob's intro key, so this is exactly what
            // Bob's host does on receipt.
            SSU2HeaderEncryption.DecryptLongHeaderComplete(firstDatagram, 0, bob.IntroKey, bob.IntroKey);
            var header = SSU2Header.ParseLongHeader(new I2PBufferCursor(firstDatagram));

            Assert.That(header.NetId, Is.EqualTo((byte)I2PConstants.I2PNetworkId),
                "SSU2 SessionRequest announced a different network than the router is configured for");
        }
        finally
        {
            I2PConstants.I2PNetworkId = originalNetId;
        }
    }

    /// <summary>
    ///     Guards the channel itself. A fixture whose impairments do not bite would make every
    ///     protocol test above it vacuously green — the failure mode Phase 2 hit three times.
    /// </summary>
    [Test]
    public void ChannelAppliesItsImpairments()
    {
        var from = new IPEndPoint(IPAddress.Loopback, AlicePort);
        var to = new IPEndPoint(IPAddress.Loopback, BobPort);

        var channel = new LossyChannel(7) { DropProbability = 0.5 };
        var delivered = 0;
        channel.Register(to, (_, _) => delivered++);

        for (var i = 0; i < 1000; i++)
            channel.Send(from, to, new byte[16]);

        channel.PumpUntilIdle();

        Assert.Multiple(() =>
        {
            Assert.That(channel.DroppedByLossCount, Is.GreaterThan(0), "no datagram was ever dropped");
            Assert.That(delivered, Is.GreaterThan(0), "every datagram was dropped");
            Assert.That(delivered, Is.EqualTo(channel.DeliveredCount));
            Assert.That(channel.DroppedByLossCount + delivered, Is.EqualTo(1000));
        });

        // MTU is enforced, and separately from loss.
        var mtuChannel = new LossyChannel(7) { Mtu = 100 };
        mtuChannel.Register(to, (_, _) => { });
        mtuChannel.Send(from, to, new byte[101]);
        mtuChannel.Send(from, to, new byte[100]);
        mtuChannel.PumpUntilIdle();

        Assert.Multiple(() =>
        {
            Assert.That(mtuChannel.DroppedByMtuCount, Is.EqualTo(1));
            Assert.That(mtuChannel.DeliveredCount, Is.EqualTo(1));
        });
    }

    /// <summary>Same seed, same outcome — see the determinism note on <see cref="LossyChannel" />.</summary>
    [Test]
    public void ChannelIsDeterministic()
    {
        static int DeliveredWithSeed(int seed)
        {
            var channel = new LossyChannel(seed) { DropProbability = 0.3 };
            var from = new IPEndPoint(IPAddress.Loopback, AlicePort);
            var to = new IPEndPoint(IPAddress.Loopback, BobPort);
            channel.Register(to, (_, _) => { });

            for (var i = 0; i < 500; i++) channel.Send(from, to, new byte[16]);
            channel.PumpUntilIdle();
            return channel.DeliveredCount;
        }

        Assert.That(DeliveredWithSeed(42), Is.EqualTo(DeliveredWithSeed(42)));
    }

    /// <summary>
    ///     The fixture reaches the Noise handshake rather than falling over earlier. Green, and
    ///     deliberately so: it keeps the quarantined tests honest by proving their failure is the
    ///     handshake and not the harness. If this goes red, the loopback wiring broke, not SSU2.
    /// </summary>
    [Test]
    public void FixtureDeliversTheSessionRequestToAnInboundSession()
    {
        var (channel, alice, bob) = BuildPair();

        alice.ConnectTo(bob);
        channel.PumpUntilIdle();

        Assert.Multiple(() =>
        {
            Assert.That(channel.SentCount, Is.GreaterThanOrEqualTo(1), "Alice sent no SessionRequest");
            Assert.That(channel.DeliveredCount, Is.GreaterThanOrEqualTo(1), "Bob received nothing");
            Assert.That(channel.DroppedByLossCount, Is.Zero, $"clean channel dropped a datagram. {channel}");
        });
    }

    private static (LossyChannel, LoopbackSSU2Peer alice, LoopbackSSU2Peer bob) BuildPair()
    {
        var channel = new LossyChannel(20260808);
        var alice = LoopbackSSU2Peer.Create("Alice", AlicePort, channel);
        var bob = LoopbackSSU2Peer.Create("Bob", BobPort, channel);
        return (channel, alice, bob);
    }

    /// <summary>A small, distinguishable I2NP message. Content is irrelevant; arrival is not.</summary>
    private static I2NpMessage BuildMessage(int index)
    {
        var payload = new byte[64];
        payload[0] = (byte)index;
        return new DataMessage(new I2PByteBlock(payload));
    }
}
