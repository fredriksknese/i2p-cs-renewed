using System;
using I2PCore.Crypto;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PTests;

/// <summary>
///     Tests over the SSU2 packet captured from a real i2pd. Batch 3-5
///     (docs/PRODUCTION-PLAN.md).
///
///     <para>
///         Ordinary unit tests — the vector is checked in, so nothing here needs i2pd, a network
///         or a port. <c>SSU2GoldenVectorCapture</c> is the Integration-category producer that
///         refreshes it.
///     </para>
///     <para>
///         <b>What the capture settled.</b> Two things, and neither was what the batch expected
///         to find. i2pd's opening move is a <b>TokenRequest</b>, not a SessionRequest; and our
///         header encryption uses the wrong ChaCha20 block, so we cannot read i2pd's headers and
///         it cannot read ours.
///     </para>
/// </summary>
[TestFixture]
public class Ssu2GoldenVectorTest
{
    private const byte TypeTokenRequest = 10;
    private const byte TestNetId = 99;

    [SetUp]
    public void RequireVector()
    {
        if (!GoldenVectors.Exists(GoldenVectors.Ssu2TokenRequest))
            Assert.Ignore(
                $"{GoldenVectors.Ssu2TokenRequest} not present. Run SSU2GoldenVectorCapture "
                + "with i2pd available to regenerate it.");
    }

    /// <summary>
    ///     Ground truth, decoded with i2pd's convention rather than ours: the header key stream
    ///     is ChaCha20 <b>block 1</b> (counter starting at one), with a nonce of the packet's
    ///     last 12 bytes.
    ///
    ///     <para>
    ///         Green, and it is the reference the red test below is measured against. It also
    ///         records the more surprising half of the finding: <b>the first packet i2pd sends
    ///         to a peer it holds no token for is a TokenRequest (type 10), not a
    ///         SessionRequest.</b> Nothing in this repository handles that message — the plan's
    ///         batch 4-2 is written as though we only need to *receive* Retry as an initiator,
    ///         but a C# router must also *answer* a TokenRequest with a Retry before i2pd will
    ///         ever send a SessionRequest. Until it does, an inbound SSU2 session from i2pd
    ///         cannot begin.
    ///     </para>
    /// </summary>
    [Test]
    public void I2pdOpensWithATokenRequest()
    {
        var vector = GoldenVectors.Read(GoldenVectors.Ssu2TokenRequest);

        foreach (var line in GoldenVectors.Provenance(GoldenVectors.Ssu2TokenRequest))
            TestContext.Out.WriteLine(line);

        var packet = vector["packet"];
        var introKey = vector["intro_key"];

        var header = DecodeSecondHeaderGroupTheWayI2pdDoes(packet, introKey);

        TestContext.Out.WriteLine(
            $"type={header.type} version={header.version} netid={header.netId}");

        Assert.Multiple(() =>
        {
            Assert.That(header.version, Is.EqualTo(2), "SSU2 version");
            Assert.That(header.netId, Is.EqualTo(TestNetId), "netid the capture ran on");
            Assert.That(header.type, Is.EqualTo(TypeTokenRequest),
                "i2pd's first packet should be a TokenRequest");
        });
    }

    /// <summary>
    ///     Our production header decryption, run against a header i2pd really sent. It recovers
    ///     nonsense — on the captured vector, version 27 and netid 27 where 2 and 99 are
    ///     correct.
    ///
    ///     <para>
    ///         <b>The divergence is the ChaCha20 block counter.</b> Scanning the key stream for
    ///         the offset that yields the correct version and netid lands on byte 64 — the start
    ///         of the second 64-byte ChaCha20 block. i2pd generates its header mask from block
    ///         1; <c>SSU2HeaderEncryption.GenerateChaCha20Mask</c> uses <c>ChaCha7539Engine</c>
    ///         from its initial state, which is block 0. The nonce agrees (the packet's last 12
    ///         bytes); only the block differs.
    ///     </para>
    ///     <para>
    ///         <b>Self-consistent, and therefore invisible until now.</b> Both ends of a C#-only
    ///         exchange use block 0, so every internal test passes and the batch 3-3 loopback
    ///         fixture reaches the Noise layer before failing. Nothing that talks only to itself
    ///         can detect this. It does mean no SSU2 header we produce can be read by i2pd and
    ///         none of i2pd's can be read by us, which makes it an outright interop blocker for
    ///         all of Phase 4 — and separate from the 3-3 AEAD defect, which is a C#-to-C#
    ///         failure this does not explain.
    ///     </para>
    ///     <para>
    ///         <b>Fixed by batch 4-0</b>, and this test is no longer quarantined — it is now the
    ///         regression guard for the block counter. The convention was re-derived from
    ///         <c>libi2pd/Crypto.cpp ChaCha20()</c> (<c>iv[0] = htole32 (1)</c>) rather than from
    ///         the absent document the old comments cited.
    ///     </para>
    /// </summary>
    [Test]
    public void OurHeaderDecryptionCanReadI2pdsHeader()
    {
        var vector = GoldenVectors.Read(GoldenVectors.Ssu2TokenRequest);

        var packet = (byte[])vector["packet"].Clone();
        var introKey = vector["intro_key"];

        // Both header keys are the responder's intro key before a session exists — the same
        // thing SSU2Host.DispatchPacket does on receipt.
        SSU2HeaderEncryption.DecryptLongHeaderComplete(packet, 0, introKey, introKey);

        var header = SSU2Header.ParseLongHeader(new I2PBufferCursor(packet));

        TestContext.Out.WriteLine(
            $"ours: type={header.Type} version={header.Version} netid={header.NetId}");

        Assert.Multiple(() =>
        {
            Assert.That(header.Version, Is.EqualTo(2), "SSU2 version recovered from i2pd's header");
            Assert.That(header.NetId, Is.EqualTo(TestNetId), "netid recovered from i2pd's header");
            Assert.That(header.Type, Is.EqualTo(TypeTokenRequest), "message type recovered from i2pd's header");
        });
    }

    /// <summary>
    ///     Pins the exact divergence rather than only its symptom, so a fix can be checked
    ///     against a number instead of a vibe. If <c>SSU2HeaderEncryption</c> is corrected to
    ///     use block 1, this test still describes what i2pd does and stays green.
    /// </summary>
    [Test]
    public void I2pdHeaderMaskComesFromChaCha20BlockOne()
    {
        var vector = GoldenVectors.Read(GoldenVectors.Ssu2TokenRequest);
        var packet = vector["packet"];
        var introKey = vector["intro_key"];

        var nonce = LastTwelveBytes(packet);
        var keyStream = KeyStream(introKey, nonce, 128);

        var matches = 0;
        var matchOffset = -1;

        for (var offset = 0; offset + 8 <= keyStream.Length; offset++)
        {
            var version = (byte)(packet[13] ^ keyStream[offset + 5]);
            var netId = (byte)(packet[14] ^ keyStream[offset + 6]);

            if (version != 2 || netId != TestNetId) continue;

            matches++;
            matchOffset = offset;
        }

        Assert.Multiple(() =>
        {
            Assert.That(matches, Is.EqualTo(1), "exactly one key stream offset should decode the header");
            Assert.That(matchOffset, Is.EqualTo(64),
                "i2pd's header mask starts at ChaCha20 block 1 (byte 64), not block 0");
        });
    }

    private static (byte type, byte version, byte netId) DecodeSecondHeaderGroupTheWayI2pdDoes(
        byte[] packet, byte[] introKey)
    {
        var keyStream = KeyStream(introKey, LastTwelveBytes(packet), 128);

        // Header bytes 8-15 are masked with the key stream starting at block 1; type, version
        // and netid sit at header offsets 12, 13 and 14.
        return ((byte)(packet[12] ^ keyStream[64 + 4]),
            (byte)(packet[13] ^ keyStream[64 + 5]),
            (byte)(packet[14] ^ keyStream[64 + 6]));
    }

    private static byte[] LastTwelveBytes(byte[] packet)
    {
        var nonce = new byte[12];
        Array.Copy(packet, packet.Length - 12, nonce, 0, 12);
        return nonce;
    }

    private static byte[] KeyStream(byte[] key, byte[] nonce, int length)
    {
        var engine = new ChaCha7539Engine();
        engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        var output = new byte[length];
        engine.ProcessBytes(new byte[length], 0, length, output, 0);
        return output;
    }
}
