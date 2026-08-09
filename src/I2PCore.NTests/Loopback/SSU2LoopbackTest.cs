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
///         because SSU2 has been off by default since batch 0-4.
///     </para>
///     <para>
///         Every test here was red when written. <b>The handshake ones are green as of batch
///         4-0h</b>; what remains quarantined is the data phase, which now fails on its own
///         merits — 99 of 100 messages on a clean channel, and no retransmission at all — rather
///         than being skipped because no session could be established.
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
    ///     <b>Green as of batch 4-0h — the first SSU2 handshake this repository has ever
    ///     completed.</b> Both sides reach <c>Session established</c> in four datagrams: Session
    ///     Request, Session Created, and a Session Confirmed fragmented across two.
    ///
    ///     <para>
    ///         It took four defects, each hiding the next, and each invisible to a test that
    ///         talked only to itself:
    ///     </para>
    ///     <list type="number">
    ///         <item>
    ///             <b>4-0b</b> — Alice masked packet bytes 0-15 while Bob unmasked 0-31, so Bob
    ///             hashed a header Alice never built and Message 1 failed to authenticate.
    ///         </item>
    ///         <item>
    ///             <b>4-0h</b> — the type peek trial-decrypted with the intro key, which cannot
    ///             read a Session Created's type (<c>Unknown packet type 160</c>).
    ///         </item>
    ///         <item>
    ///             <b>4-0h</b> — Alice derived the Session Confirmed header key after message 3
    ///             had already mixed <c>se</c> into the chaining key, so Bob could not derive the
    ///             same key (<c>Unknown packet type 4</c>, then <c>13</c>).
    ///         </item>
    ///         <item>
    ///             <b>4-0h</b> — Bob hashed the header as received where Alice hashed the
    ///             canonical <c>flags[0] = 0x01</c> form, which differs only when the Session
    ///             Confirmed is fragmented. It always is here: the RouterInfo does not fit one
    ///             datagram.
    ///         </item>
    ///     </list>
    ///     <para>
    ///         <b>C#-to-C# only.</b> Nothing here says i2pd would accept this handshake — batch
    ///         4-0i has evidence that it would not, because our handshake payload is not
    ///         block-framed. What this proves is that our two halves finally agree, which they
    ///         did not before.
    ///     </para>
    /// </summary>
    [Test]
    public void HandshakeCompletesOnACleanChannel()
    {
        var (channel, alice, bob) = BuildPair();

        alice.ConnectTo(bob);
        channel.PumpUntilIdle();

        Assert.That(alice.Established, Is.Not.Empty,
            $"SSU2 handshake did not complete on a lossless channel. {channel}");
    }

    /// <summary>
    ///     Batch 4-0h. Alice must recognise Bob's Session Created rather than dropping it as an
    ///     unknown type — the step immediately after the one batch 4-0b unblocked.
    ///
    ///     <para>
    ///         Green or red, this test is about the <em>dispatch</em>, not the whole handshake:
    ///         it asserts only that Alice's session leaves <c>SessionRequestSent</c>, which she
    ///         cannot do while the type peek reads the reply as type 160. Whatever fails after
    ///         that fails in <see cref="HandshakeCompletesOnACleanChannel" /> instead, where it
    ///         belongs.
    ///     </para>
    /// </summary>
    [Test]
    public void AliceRecognisesTheSessionCreatedSentBackToHer()
    {
        var (channel, alice, bob) = BuildPair();

        var session = alice.ConnectTo(bob);
        channel.PumpUntilIdle();

        Assume.That(channel.DeliveredCount, Is.GreaterThanOrEqualTo(2),
            $"Bob never replied, so there is no Session Created to recognise. {channel}");

        Assert.That(session.State, Is.Not.EqualTo(SessionState.SessionRequestSent),
            "Alice is still waiting for a Session Created she has already been sent: the type "
            + "peek decrypts the long header with the intro key, but a Session Created's "
            + "k_header_2 is HKDF(chainKey, \"SessCreateHeader\")");
    }

    /// <summary>
    ///     Batch 4-0h, the responder's half of the same question. Bob must recognise the Session
    ///     Confirmed Alice sends back, which he cannot do while she masks its short header with a
    ///     key he has no way to derive.
    ///
    ///     <para>
    ///         <b>A Session Confirmed's k_header_2 is fixed at the state the handshake was in
    ///         when the Session Created went out</b> — the receiver has to unmask the header
    ///         before it can process the message, so it cannot depend on anything inside that
    ///         message. Alice derived it *after* <c>CreateMessage3Part2</c>, which mixes <c>se</c>
    ///         into the chaining key and splits, so the two sides derived from different chaining
    ///         keys and never agreed. Bob logged <c>Unknown packet type 4</c> and
    ///         <c>Unknown packet type 13</c> — a random type byte per fragment.
    ///     </para>
    /// </summary>
    [Test]
    public void BobRecognisesTheSessionConfirmedSentBackToHim()
    {
        var (channel, alice, bob) = BuildPair();

        alice.ConnectTo(bob);
        channel.PumpUntilIdle();

        Assume.That(channel.SentCount, Is.GreaterThanOrEqualTo(3),
            $"Alice never sent a Session Confirmed, so there is nothing to recognise. {channel}");

        Assert.That(bob.Established, Is.Not.Empty,
            "Bob never accepted the Session Confirmed he was sent: its header key must be "
            + "derived from the chaining key as it stood when the Session Created went out, "
            + "before message 3 mixes se into it");
    }

    /// <summary>
    ///     The plan's stated 3-3 gate: 0% loss delivers 100/100. **No longer blocked** — as of
    ///     4-0h the handshake completes, so this measures the data phase for the first time
    ///     rather than being skipped by its own <c>Assume</c>.
    ///
    ///     <para>
    ///         It delivers <b>99 of 100</b> on a lossless channel, which is a far narrower defect
    ///         than "no data phase". One message in a hundred is lost with nothing dropping it —
    ///         `sent=104 delivered=104 lost=0`. Owner: batch 4-1, which has to explain that one
    ///         before it can claim anything about retransmission.
    ///     </para>
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
    ///     As of 4-0h this reaches the data phase and measures exactly that: 6 datagrams lost,
    ///     6 messages never delivered, nothing retransmitted. Owner: batch 4-1.
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
