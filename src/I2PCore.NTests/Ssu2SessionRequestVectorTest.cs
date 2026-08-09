using System;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PTests;

/// <summary>
///     Batch 4-0b (docs/PRODUCTION-PLAN.md). The SSU2 Session Request, measured against the one
///     i2pd 2.61.0 really sent — <c>TestData/ssu2_sessionrequest_i2pd.txt</c>, captured by batch
///     4-2c after i2pd accepted our Retry.
///
///     <para>
///         <b>The question this fixture settles.</b> For Session Request and Session Created,
///         i2pd covers packet bytes 16..64 — header bytes 16-31 (source connection ID and token)
///         plus the 32-byte ephemeral key — with a <b>single 48-byte ChaCha20 pass</b>, zero
///         nonce, block counter 1:
///     </para>
///     <code>
///         // libi2pd/SSU2Session.cpp, ProcessSessionRequest
///         m_Server.ChaCha20 (buf + 16, 48, i2p::context.GetSSU2IntroKey (), nonce, headerX);
///     </code>
///     <para>
///         This repository restarted the keystream for the ephemeral key, XORing it with bytes
///         0..32 where i2pd uses 16..48. <b>Header bytes 16-31 cannot tell the two apart</b> —
///         both take keystream bytes 0..16 there — which is why the TokenRequest vector could
///         never decide it and a packet carrying an ephemeral key can.
///     </para>
///     <para>
///         <b>Why the AEAD test below is the whole proof.</b> A verifying Poly1305 tag covers the
///         entire Noise transcript: the 32 plaintext header bytes, the ephemeral key X, and the
///         protocol name, all as i2pd hashed them. If any single byte of the deobfuscated header
///         or key differed from what i2pd sent, the tag would fail. That is a stronger statement
///         than any byte comparison this repository could make against itself, and it is the
///         standard the plan asks for after four self-agreeing convention defects.
///     </para>
/// </summary>
[TestFixture]
public class Ssu2SessionRequestVectorTest
{
    private const byte TypeSessionRequest = 0;
    private const byte TestNetId = 99;

    [SetUp]
    public void RequireVector()
    {
        if (!GoldenVectors.Exists(GoldenVectors.Ssu2SessionRequest))
            Assert.Ignore(
                $"{GoldenVectors.Ssu2SessionRequest} not present. Run SSU2GoldenVectorCapture "
                + "with i2pd available to regenerate it.");
    }

    /// <summary>
    ///     The production receive path, run over i2pd's real Session Request: the same calls
    ///     <c>SSU2Session.ProcessSessionRequest</c> makes, in the same order. Red before 4-0b —
    ///     <c>DeobfuscateEphemeralKey</c> recovers a key i2pd never sent, so the Noise AEAD
    ///     cannot authenticate.
    /// </summary>
    [Test]
    public void I2pdsSessionRequestAuthenticatesThroughTheProductionPath()
    {
        var vector = GoldenVectors.Read(GoldenVectors.Ssu2SessionRequest);

        foreach (var line in GoldenVectors.Provenance(GoldenVectors.Ssu2SessionRequest))
            TestContext.Out.WriteLine(line);

        var packet = (byte[])vector["packet"].Clone();
        var introKey = vector["intro_key"];

        // Both header keys are our intro key for a Session Request, exactly as
        // SSU2Host.DispatchPacket and SSU2Session.ProcessSessionRequest use them.
        SSU2HeaderEncryption.DecryptLongHeaderComplete(packet, 0, introKey, introKey);

        var header = new byte[32];
        Array.Copy(packet, 0, header, 0, 32);

        var obfuscatedX = new byte[32];
        Array.Copy(packet, 32, obfuscatedX, 0, 32);
        var ephemeralKey = SSU2HeaderEncryption.DeobfuscateEphemeralKey(obfuscatedX, introKey);

        var encryptedPayload = new byte[packet.Length - 64];
        Array.Copy(packet, 64, encryptedPayload, 0, encryptedPayload.Length);

        var noise = new NoiseXK(NoiseXK.PROTOCOL_NAME_SSU2);
        noise.InitializeAsBob(vector["static_private"], vector["static_public"]);

        byte[] payload = null;
        Assert.DoesNotThrow(
            () => payload = noise.ProcessMessage1WithHeader(header, ephemeralKey, encryptedPayload),
            "i2pd's Session Request must authenticate: a failing tag means the header or the "
            + "ephemeral key we recovered is not the one i2pd hashed");

        Assert.That(payload, Is.Not.Null.And.Not.Empty, "authenticated payload");

        // i2pd frames the handshake payload as SSU2 blocks — type, 2-byte length, data — opening
        // with a DateTime block. Recorded here because our own SessionRequest payload is *not*
        // block-framed on either side: BuildRequestPayload writes a bare timestamp and
        // ProcessSessionRequest reads one back. That is a separate defect from this batch's
        // header encryption, and it is the next SSU2 batch.
        TestContext.Out.WriteLine($"payload: {Convert.ToHexString(payload)}");
        Assert.Multiple(() =>
        {
            Assert.That(payload[0], Is.EqualTo(0), "first payload block is DateTime (type 0)");
            Assert.That((payload[1] << 8) | payload[2], Is.EqualTo(4), "DateTime block is 4 bytes");
        });
    }

    /// <summary>
    ///     Batch 4-0i. i2pd's handshake payload is SSU2 <b>blocks</b>, and ours must be read as
    ///     such. This decrypts the captured Session Request exactly as the production receive
    ///     path does, then hands the authenticated plaintext to the production payload parser.
    ///
    ///     <para>
    ///         <b>The timestamp asserted here is i2pd's, not ours.</b> Its payload is
    ///         <c>00 0004 6a77a32d | fe 001a 00…</c> — a DateTime block then a Padding block —
    ///         while <c>BuildRequestPayload</c> wrote a bare timestamp and both handlers read one
    ///         back, agreeing with each other and with nothing on the network. Read the old way,
    ///         i2pd's DateTime block decodes as a timestamp of <c>0x00000406</c>: a router forty
    ///         years in the past, which the clock-skew check would reject even if nothing else
    ///         did.
    ///     </para>
    /// </summary>
    [Test]
    public void I2pdsHandshakePayloadParsesAsBlocks()
    {
        var vector = GoldenVectors.Read(GoldenVectors.Ssu2SessionRequest);
        var packet = (byte[])vector["packet"].Clone();
        var introKey = vector["intro_key"];

        SSU2HeaderEncryption.DecryptLongHeaderComplete(packet, 0, introKey, introKey);

        var header = new byte[32];
        Array.Copy(packet, 0, header, 0, 32);

        var obfuscatedX = new byte[32];
        Array.Copy(packet, 32, obfuscatedX, 0, 32);

        var encryptedPayload = new byte[packet.Length - 64];
        Array.Copy(packet, 64, encryptedPayload, 0, encryptedPayload.Length);

        var noise = new NoiseXK(NoiseXK.PROTOCOL_NAME_SSU2);
        noise.InitializeAsBob(vector["static_private"], vector["static_public"]);

        var payload = noise.ProcessMessage1WithHeader(
            header, SSU2HeaderEncryption.DeobfuscateEphemeralKey(obfuscatedX, introKey), encryptedPayload);

        var parsed = SSU2HandshakePayload.Parse(payload);

        Assert.Multiple(() =>
        {
            Assert.That(parsed.Timestamp, Is.EqualTo(0x6a77a32du),
                "the DateTime block i2pd sent must be read as a DateTime block");
            Assert.That(parsed.PaddingLength, Is.EqualTo(26), "the Padding block that follows it");
        });
    }

    /// <summary>
    ///     The send side of the same convention: what we build must parse as the blocks a peer
    ///     expects, with the timestamp we put in it.
    /// </summary>
    [Test]
    public void OurHandshakePayloadIsBlockFramed()
    {
        var built = SSU2HandshakePayload.Build(0x12345678, 16);

        Assert.That(built[0], Is.EqualTo((byte)SSU2BlockType.DateTime), "first block is DateTime");

        var parsed = SSU2HandshakePayload.Parse(built);

        Assert.Multiple(() =>
        {
            Assert.That(parsed.Timestamp, Is.EqualTo(0x12345678u));
            Assert.That(parsed.PaddingLength, Is.EqualTo(16));
        });
    }

    /// <summary>
    ///     The same recovery stated as bytes rather than as a tag, so a failure says which
    ///     convention was used rather than only that something is wrong. The expected value comes
    ///     from a keystream generated here, not from <c>SSU2HeaderEncryption</c> — a reference
    ///     shared with the code under test would hide exactly this class of defect.
    /// </summary>
    [Test]
    public void TheEphemeralKeyIsMaskedWithTheContinuationOfTheHeaderKeystream()
    {
        var vector = GoldenVectors.Read(GoldenVectors.Ssu2SessionRequest);
        var packet = vector["packet"];
        var introKey = vector["intro_key"];

        var obfuscatedX = new byte[32];
        Array.Copy(packet, 32, obfuscatedX, 0, 32);

        // i2pd's one 48-byte pass over bytes 16..64: the ephemeral key is its second half.
        var expected = Xor(obfuscatedX, Slice(I2pdKeyStream(introKey, new byte[12], 48), 16, 32));

        var actual = SSU2HeaderEncryption.DeobfuscateEphemeralKey(obfuscatedX, introKey);

        Assert.That(actual, Is.EqualTo(expected),
            "the ephemeral key i2pd sent is XORed with keystream bytes 16..48 of the pass that "
            + "starts at packet byte 16, not with a keystream restarted at 0");
    }

    /// <summary>
    ///     Header bytes 16-31 decode identically under both conventions, so this one is green
    ///     before and after 4-0b. It is here to bound the change: whatever the fix does to the
    ///     ephemeral key, it must leave this region — and therefore the TokenRequest, Retry and
    ///     PeerTest paths that share it — reading exactly as it does today.
    /// </summary>
    [Test]
    public void TheHeaderRegionIsUnaffectedByTheChange()
    {
        var vector = GoldenVectors.Read(GoldenVectors.Ssu2SessionRequest);
        var packet = (byte[])vector["packet"].Clone();
        var introKey = vector["intro_key"];

        SSU2HeaderEncryption.DecryptLongHeaderComplete(packet, 0, introKey, introKey);
        var header = SSU2Header.ParseLongHeader(new I2PBufferCursor(packet));

        Assert.Multiple(() =>
        {
            Assert.That(header.Type, Is.EqualTo(TypeSessionRequest), "message type");
            Assert.That(header.Version, Is.EqualTo(2), "SSU2 version");
            Assert.That(header.NetId, Is.EqualTo(TestNetId), "netid the capture ran on");

            // Bytes 24-31. i2pd echoes the token our Retry issued, which is what proves it read
            // that Retry — see batch 4-2c and the provenance comments in the vector file.
            Assert.That(header.Token, Is.Not.Zero, "token echoed from our Retry");
        });
    }

    /// <summary>
    ///     The send side of the same convention. Red before 4-0b twice over:
    ///     <c>SessionRequest.ToByteArray</c> calls <c>EncryptLongHeaderInPacket</c>, which stops
    ///     at byte 16 and leaves the source connection ID and token in the clear, and it obfuscates
    ///     the ephemeral key with a restarted keystream.
    /// </summary>
    [Test]
    public void OurSessionRequestMasksBytesSixteenToSixtyFourAsOnePass()
    {
        var introKey = Enumerable32(0x11);
        var ephemeralKey = Enumerable32(0x40);
        var encryptedPayload = Enumerable32(0x70);

        var request = new SessionRequest();
        request.Header.DestinationConnectionId = 0x0123456789ABCDEF;
        request.Header.SourceConnectionId = 0xFEDCBA9876543210;
        request.Header.Token = 0x1122334455667788;
        request.Header.PacketNumber = 0x2A2B2C2D;

        var plaintextHeader = request.Header.ToByteArray();

        var packet = request.ToByteArray(introKey, ephemeralKey, encryptedPayload);

        // Undo i2pd's single pass over bytes 16..64 and expect the plaintext back.
        var unmasked = Xor(Slice(packet, 16, 48), I2pdKeyStream(introKey, new byte[12], 48));

        Assert.Multiple(() =>
        {
            Assert.That(Slice(unmasked, 0, 16), Is.EqualTo(Slice(plaintextHeader, 16, 16)),
                "header bytes 16-31 (source connection ID and token) must be masked, and with "
                + "the first 16 bytes of the same keystream");
            Assert.That(Slice(unmasked, 16, 32), Is.EqualTo(ephemeralKey),
                "the ephemeral key must be masked with keystream bytes 16..48 of that pass");
        });
    }

    /// <summary>
    ///     i2pd's ChaCha20 keystream: block counter 1, per <c>libi2pd/Crypto.cpp</c>
    ///     (<c>iv[0] = htole32 (1)</c>). Deliberately duplicated from the other SSU2 fixtures —
    ///     see the note on <c>Ssu2HeaderLayoutTest.I2pdKeyStream</c>.
    /// </summary>
    private static byte[] I2pdKeyStream(byte[] key, byte[] nonce, int length)
    {
        var engine = new ChaCha7539Engine();
        engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        var all = new byte[64 + length];
        engine.ProcessBytes(new byte[64 + length], 0, 64 + length, all, 0);

        return Slice(all, 64, length);
    }

    private static byte[] Slice(byte[] source, int offset, int length)
    {
        var result = new byte[length];
        Array.Copy(source, offset, result, 0, length);
        return result;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        var result = new byte[a.Length];
        for (var i = 0; i < a.Length; i++) result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }

    private static byte[] Enumerable32(byte seed)
    {
        var result = new byte[32];
        for (var i = 0; i < 32; i++) result[i] = (byte)(seed + i);
        return result;
    }
}
