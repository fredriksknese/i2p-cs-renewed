using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.SessionLayer.Streaming;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

[TestFixture]
public class StreamingProtocolTest
{
    /// <summary>
    ///     Test that StreamingPacket round-trips through serialization.
    /// </summary>
    [Test]
    public void TestStreamingPacketSerialization()
    {
        var pkt = new StreamingPacket
        {
            SendStreamId = 0x12345678,
            ReceiveStreamId = 0xABCDEF01,
            SequenceNumber = 42,
            AckThrough = 41,
            ResendDelay = 5,
            Flags = StreamingPacket.FLAG_SYNCHRONIZE | StreamingPacket.FLAG_FROM_INCLUDED,
            Payload = BufUtils.RandomBytes(100)
        };

        var bytes = pkt.ToByteArray();
        Assert.IsNotNull(bytes);
        Assert.IsTrue(bytes.Length > 0, "Serialized packet should not be empty");

        var parsed = StreamingPacket.Parse(bytes);

        Assert.AreEqual(pkt.SendStreamId, parsed.SendStreamId, "SendStreamId mismatch");
        Assert.AreEqual(pkt.ReceiveStreamId, parsed.ReceiveStreamId, "ReceiveStreamId mismatch");
        Assert.AreEqual(pkt.SequenceNumber, parsed.SequenceNumber, "SequenceNumber mismatch");
        Assert.AreEqual(pkt.AckThrough, parsed.AckThrough, "AckThrough mismatch");
    }

    /// <summary>
    ///     Test stream creation and basic state transitions.
    /// </summary>
    [Test]
    public void TestStreamStateTransitions()
    {
        var cert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var keys = I2PPrivateKey.GetNewKeyPair();
        var privskey = new I2PSigningPrivateKey(cert);
        var pubskey = new I2PSigningPublicKey(privskey);
        var localDest = new I2PDestination(keys.PublicKey, pubskey);
        var remoteDest = new I2PDestination(keys.PublicKey, pubskey);

        var sentPackets = new List<byte[]>();

        var stream = new I2PStream(
            localDest,
            remoteDest,
            localDest.ToByteArray(),
            data => sentPackets.Add(data),
            privskey);

        Assert.AreEqual(I2PStream.StreamStatus.New, stream.Status);
        Assert.IsTrue(stream.IsOutgoing);

        // Send data should stay in New until SYN/ACK
        stream.Send(new byte[] { 1, 2, 3 });

        Assert.AreEqual(I2PStream.StreamStatus.New, stream.Status,
            "After first send, stream should still be New until SYN/ACK");
        Assert.IsTrue(sentPackets.Count > 0, "Should have sent a SYN packet");

        // Simulate receiving a SYN/ACK from remote
        var ackPkt = new StreamingPacket
        {
            SendStreamId = 12345, // remote ID
            ReceiveStreamId = stream.RecvStreamId, // our ID
            SequenceNumber = 0,
            AckThrough = 0, // ACK through seq 0
            Flags = StreamingPacket.FLAG_SYNCHRONIZE // SYN/ACK
        };
        stream.HandleNextPacket(ackPkt);

        Assert.AreEqual(I2PStream.StreamStatus.Open, stream.Status,
            "After SYN/ACK, stream should be Open");

        // First packet should have SYN flag
        var firstPkt = StreamingPacket.Parse(sentPackets[0]);
        Assert.IsTrue(firstPkt.IsSYN, "First packet should be SYN");
    }

    /// <summary>
    ///     Test that close sends a CLOSE packet after all data is acknowledged.
    /// </summary>
    [Test]
    public void TestStreamClose()
    {
        var cert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var keys = I2PPrivateKey.GetNewKeyPair();
        var privskey = new I2PSigningPrivateKey(cert);
        var pubskey = new I2PSigningPublicKey(privskey);
        var localDest = new I2PDestination(keys.PublicKey, pubskey);
        var remoteDest = new I2PDestination(keys.PublicKey, pubskey);

        var sentPackets = new List<byte[]>();

        var stream = new I2PStream(
            localDest,
            remoteDest,
            localDest.ToByteArray(),
            data => sentPackets.Add(data),
            privskey);

        // Move to Open state by sending SYN and receiving SYN/ACK
        stream.Send(new byte[] { 1, 2, 3 });
        Assert.IsTrue(sentPackets.Count > 0, "Should have sent SYN");

        // Simulate receiving an ACK for the SYN packet (seq 0)
        var ackPkt = new StreamingPacket
        {
            SendStreamId = 12345, // remote ID
            ReceiveStreamId = stream.RecvStreamId, // our ID
            SequenceNumber = 0,
            AckThrough = 0, // ACK through seq 0
            Flags = StreamingPacket.FLAG_SYNCHRONIZE // SYN/ACK
        };
        stream.HandleNextPacket(ackPkt);
        Assert.AreEqual(I2PStream.StreamStatus.Open, stream.Status, "Stream should be Open after SYN/ACK");

        sentPackets.Clear();

        // Now close - should succeed since send queue is clear
        stream.Close();

        // Should have sent a CLOSE packet
        Assert.IsTrue(sentPackets.Count > 0, "Close should send a packet");
        var closePkt = StreamingPacket.Parse(sentPackets[sentPackets.Count - 1]);
        Assert.IsTrue(closePkt.IsClose, "Last sent packet should have CLOSE flag");
    }

    /// <summary>
    ///     Test streaming constants match i2pd reference values.
    /// </summary>
    [Test]
    public void TestStreamingConstants()
    {
        Assert.AreEqual(1730, I2PStream.STREAMING_MTU,
            "MTU should match i2pd STREAMING_MTU");
        Assert.AreEqual(1812, I2PStream.STREAMING_MTU_RATCHETS,
            "Ratchet MTU should match i2pd");
        Assert.AreEqual(10, I2PStream.INITIAL_WINDOW_SIZE,
            "Initial window should match i2pd");
        Assert.AreEqual(3, I2PStream.MIN_WINDOW_SIZE,
            "Min window should match i2pd");
        Assert.AreEqual(512, I2PStream.MAX_WINDOW_SIZE,
            "Max window should match i2pd");
        Assert.AreEqual(1500, I2PStream.INITIAL_RTT,
            "Initial RTT should match i2pd");
        Assert.AreEqual(9000, I2PStream.INITIAL_RTO,
            "Initial RTO should match i2pd");
        Assert.AreEqual(20, I2PStream.MIN_RTO,
            "Min RTO should match i2pd");
        Assert.AreEqual(10, I2PStream.MAX_NUM_RESEND_ATTEMPTS,
            "Max resend attempts should match i2pd");
        Assert.AreEqual(2, I2PStream.MIN_SEND_ACK_TIMEOUT,
            "Min ACK timeout should match i2pd");
    }

    /// <summary>
    ///     Test datagram creation and parsing round-trip.
    /// </summary>
    [Test]
    public void TestRepliableDatagramRoundTrip()
    {
        var cert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var keys = I2PPrivateKey.GetNewKeyPair();
        var privskey = new I2PSigningPrivateKey(cert);
        var pubskey = new I2PSigningPublicKey(privskey);
        var sender = new I2PDestination(keys.PublicKey, pubskey);

        var payload = BufUtils.RandomBytes(256);

        // Create a repliable datagram
        var datagram = I2PDatagramDissector.CreateRepliableDatagram(
            sender, privskey, payload);

        Assert.IsNotNull(datagram);
        Assert.IsTrue(datagram.Length > payload.Length,
            "Datagram should be larger than payload (includes identity + signature)");

        // Parse it back
        var (parsedSender, parsedPayload, verified) =
            I2PDatagramDissector.ParseRepliableDatagram(datagram);

        Assert.IsNotNull(parsedSender, "Parsed sender should not be null");
        Assert.IsNotNull(parsedPayload, "Parsed payload should not be null");
        Assert.IsTrue(BufUtils.Equal(payload, parsedPayload),
            "Parsed payload should match original");
        Assert.IsTrue(verified, "Signature should verify");
    }

    /// <summary>
    ///     Test raw datagram creation.
    /// </summary>
    [Test]
    public void TestRawDatagram()
    {
        var payload = BufUtils.RandomBytes(512);
        var raw = I2PDatagramDissector.CreateRawDatagram(payload);

        Assert.IsNotNull(raw);
        Assert.IsTrue(BufUtils.Equal(payload, raw),
            "Raw datagram should be identical to payload");
    }
}