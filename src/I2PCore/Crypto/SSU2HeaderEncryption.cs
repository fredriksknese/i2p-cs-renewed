using System;
using System.Text;
using I2PCore.Crypto.Noise;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.Crypto;

/// <summary>
///     SSU2 header encryption — two-stage ChaCha20 obfuscation for DPI resistance.
///
///     <para>
///         <b>Citations.</b> This file used to cite "SSU2 spec lines 761-798" and similar, of a
///         document that is not in this repository and that nobody has been able to produce.
///         Batch 4-0 re-derived the convention from i2pd, the peer we must interoperate with,
///         and cites it by symbol so the references can be checked:
///         <c>libi2pd/Crypto.cpp ChaCha20()</c>, <c>libi2pd/SSU2Session.h CreateHeaderMask()</c>,
///         and the send/process pairs in <c>libi2pd/SSU2Session.cpp</c>. Verified against
///         i2pd 2.61.0. <b>Do not reintroduce line-number citations to an absent document</b> —
///         batch 9-1 has the same problem with "ntcp2-hybrid.md line 363".
///     </para>
///
///     <para><b>Key selection by message type</b> (unchanged, and confirmed correct):</para>
///     <list type="bullet">
///         <item>Session Request: k_header_1 = k_header_2 = Bob's intro key, no derivation</item>
///         <item>Session Created: k_header_1 = bik, k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)</item>
///         <item>Session Confirmed: k_header_1 = bik, k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)</item>
///         <item>Data: k_header_2 from the data-phase KDF</item>
///     </list>
///
///     <para>
///         <b>Bytes 16..64 of a Session Request or Session Created are one 48-byte ChaCha20
///         pass</b> — header bytes 16-31 (source connection ID and token) plus the 32-byte
///         ephemeral key, one keystream, zero nonce. From i2pd:
///     </para>
///     <code>
///         // SSU2Session.cpp SendSessionRequest / ProcessSessionRequest
///         m_Server.ChaCha20 (headerX, 48, m_Address->i, nonce, headerX);
///         m_Server.ChaCha20 (buf + 16, 48, i2p::context.GetSSU2IntroKey (), nonce, headerX);
///     </code>
///     <para>
///         Batch 4-0b, against a Session Request i2pd 2.61.0 really sent. This is expressed here
///         as <see cref="EncryptLongHeaderComplete" /> (bytes 0..16 of that pass, over header
///         bytes 16-31) followed by <see cref="ObfuscateEphemeralKey" /> (bytes 16..48, over the
///         key). The composition is byte-identical to i2pd's single call — 48 bytes fit in one
///         ChaCha20 block and both halves use the zero nonce — and it keeps the 16-byte form
///         intact for TokenRequest, Retry and PeerTest, which carry no ephemeral key and share
///         <see cref="EncryptLongHeaderComplete" />.
///     </para>
///     <para>
///         <b>It was one defect, not two.</b> Batch 3-3's unexplained C#-to-C# AEAD failure was
///         the same divergence seen from inside: <c>SendSessionRequest</c> masked bytes 0-15 with
///         <see cref="EncryptLongHeaderInPacket" /> while <c>SSU2Host.DispatchPacket</c> unmasked
///         0-31, so the receiver XORed 16 bytes the sender never masked and the header Bob hashed
///         was not the one Alice hashed. Both send paths now use
///         <see cref="EncryptLongHeaderComplete" />, which is also what makes the source
///         connection ID and token stop going out in the clear.
///     </para>
///     <para>
///         <b>Do not verify a change here against this repository alone.</b> Every SSU2
///         convention defect found so far — the block counter, this pass, the data-phase header —
///         round-tripped perfectly against itself. The tests that matter are
///         <c>Ssu2SessionRequestVectorTest</c> and <c>Ssu2GoldenVectorTest</c>, which measure
///         against captured i2pd bytes.
///     </para>
/// </summary>
public static class SSU2HeaderEncryption
{
    /// <summary>ChaCha20 operates on 64-byte blocks; block 0 is discarded to start at block 1.</summary>
    private const int ChaCha20BlockSize = 64;

    /// <summary>
    ///     Where the ephemeral key sits in the 48-byte pass over packet bytes 16..64: after the
    ///     16 bytes that cover header bytes 16-31. Batch 4-0b.
    /// </summary>
    private const int EphemeralKeyOffsetInPass = 16;

    /// <summary>
    ///     Derive k_header_2 for Session Created
    ///     SSU2 spec lines 1255-1270
    ///     k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
    /// </summary>
    public static byte[] DeriveSessionCreatedHeaderKey(byte[] chainingKey)
    {
        if (chainingKey == null || chainingKey.Length != 32)
            throw new ArgumentException("Chaining key must be 32 bytes", nameof(chainingKey));

        var info = Encoding.ASCII.GetBytes("SessCreateHeader");
        return NoiseKDF.HKDF(chainingKey, Array.Empty<byte>(), info, 32);
    }

    /// <summary>
    ///     Derive k_header_2 for Session Confirmed
    ///     SSU2 spec lines 1474-1492
    ///     k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)
    /// </summary>
    public static byte[] DeriveSessionConfirmedHeaderKey(byte[] chainingKey)
    {
        if (chainingKey == null || chainingKey.Length != 32)
            throw new ArgumentException("Chaining key must be 32 bytes", nameof(chainingKey));

        var info = Encoding.ASCII.GetBytes("SessionConfirmed");
        return NoiseKDF.HKDF(chainingKey, Array.Empty<byte>(), info, 32);
    }

    /// <summary>
    ///     Encrypt SSU2 long header (32 bytes for Session Request/Created/Confirmed)
    ///     Per spec lines 767-797:
    ///     The IV is taken from the END of the PACKET (including payload), not the header!
    ///     - IV1: packet[len-24:len-13] (next-to-last 12 bytes)
    ///     - IV2: packet[len-12:len-1] (last 12 bytes)
    ///     - Bytes 0-7: XOR with first 8 bytes of ChaCha20(k_header_1, IV1)
    ///     - Bytes 8-15: XOR with first 8 bytes of ChaCha20(k_header_2, IV2)
    ///     Note: This method encrypts the header bytes in place.
    ///     The full packet (header + ephemeral key + payload) must be constructed first.
    /// </summary>
    public static void EncryptLongHeaderInPacket(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
    {
        if (packet == null || packet.Length < 64)
            throw new ArgumentException("Packet must be at least 64 bytes (32 header + 32 ephemeral + payload)",
                nameof(packet));

        var packetLen = packet.Length;

        // IV1: next-to-last 12 bytes of packet (packet[len-24:len-13])
        var iv1 = new byte[12];
        Array.Copy(packet, packetLen - 24, iv1, 0, 12);

        // Generate mask and encrypt bytes 0-7
        var mask1 = GenerateChaCha20Mask(kHeader1, iv1, 8);
        for (var i = 0; i < 8; i++) packet[headerOffset + i] ^= mask1[i];

        // IV2: last 12 bytes of packet (packet[len-12:len-1])
        var iv2 = new byte[12];
        Array.Copy(packet, packetLen - 12, iv2, 0, 12);

        // Generate mask and encrypt bytes 8-15
        var mask2 = GenerateChaCha20Mask(kHeader2, iv2, 8);
        for (var i = 8; i < 16; i++) packet[headerOffset + i] ^= mask2[i - 8];
    }

    /// <summary>
    ///     Encrypt SSU2 long header AND the third part (bytes 16-31)
    ///     Per spec lines 788-790: bytes 16-31 are encrypted with ChaCha20(k_header_2, zero IV)
    /// </summary>
    public static void EncryptLongHeaderComplete(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
    {
        // First encrypt bytes 0-15 using IVs from packet end
        EncryptLongHeaderInPacket(packet, headerOffset, kHeader1, kHeader2);

        // Then encrypt bytes 16-31 with zero IV
        var zeroIV = new byte[12];
        var mask = GenerateChaCha20Mask(kHeader2, zeroIV, 16);
        for (var i = 16; i < 32; i++) packet[headerOffset + i] ^= mask[i - 16];
    }

    /// <summary>
    ///     Decrypt SSU2 long header (32 bytes) - first 16 bytes only
    ///     ChaCha20 is symmetric, so decryption is identical to encryption
    /// </summary>
    public static void DecryptLongHeaderInPacket(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
    {
        // ChaCha20 XOR is symmetric
        EncryptLongHeaderInPacket(packet, headerOffset, kHeader1, kHeader2);
    }

    /// <summary>
    ///     Decrypt SSU2 long header - all 32 bytes
    /// </summary>
    public static void DecryptLongHeaderComplete(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
    {
        // ChaCha20 XOR is symmetric
        EncryptLongHeaderComplete(packet, headerOffset, kHeader1, kHeader2);
    }

    /// <summary>
    ///     Encrypt SSU2 short header (16 bytes for Data packets)
    ///     Per spec:
    ///     - Bytes 0-15: XOR with ChaCha20(k_header_2, zero IV)
    /// </summary>
    public static void EncryptShortHeader(byte[] header, byte[] kHeader2)
    {
        if (header == null || header.Length != 16)
            throw new ArgumentException("Header must be 16 bytes for short header", nameof(header));

        var zeroIV = new byte[12];
        var mask = GenerateChaCha20Mask(kHeader2, zeroIV, 16);

        for (var i = 0; i < 16; i++) header[i] ^= mask[i];
    }

    /// <summary>
    ///     Decrypt SSU2 short header (16 bytes)
    ///     ChaCha20 is symmetric, so decryption is identical to encryption
    /// </summary>
    public static void DecryptShortHeader(byte[] header, byte[] kHeader2)
    {
        EncryptShortHeader(header, kHeader2);
    }

    /// <summary>
    ///     Encrypt SSU2 short header (16 bytes) in a complete packet
    ///     For Session Confirmed only - uses only k_header_2
    /// </summary>
    public static void EncryptShortHeaderInPacket(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
    {
        if (packet == null || packet.Length < headerOffset + 16)
            throw new ArgumentException("Packet too short for short header", nameof(packet));

        // Short header only uses k_header_2 (not k_header_1)
        // Bytes 0-15: XOR with ChaCha20(k_header_2, zero IV)
        var header = new byte[16];
        Array.Copy(packet, headerOffset, header, 0, 16);

        EncryptShortHeader(header, kHeader2);

        Array.Copy(header, 0, packet, headerOffset, 16);
    }

    /// <summary>
    ///     Decrypt SSU2 short header (16 bytes) in a complete packet
    ///     ChaCha20 is symmetric, so decryption is identical to encryption
    /// </summary>
    public static void DecryptShortHeaderInPacket(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
    {
        EncryptShortHeaderInPacket(packet, headerOffset, kHeader1, kHeader2);
    }

    /// <summary>
    ///     Obfuscate the ephemeral key of a Session Request or Session Created — packet bytes
    ///     32-63, the <b>second half</b> of the 48-byte pass that starts at packet byte 16.
    ///
    ///     <para>
    ///         Batch 4-0b. This used to restart the keystream, XORing the key with bytes 0..32
    ///         where i2pd uses 16..48 of the same stream, so the key we sent was unreadable to
    ///         i2pd and the key we read from i2pd was noise. It is a 48-byte pass and not two,
    ///         per <c>libi2pd/SSU2Session.cpp</c>:
    ///     </para>
    ///     <code>
    ///         m_Server.ChaCha20 (buf + 16, 48, i2p::context.GetSSU2IntroKey (), nonce, headerX);
    ///     </code>
    ///     <para>
    ///         Header bytes 16-31 keep taking bytes 0..16 of that same stream, which is what
    ///         <see cref="EncryptLongHeaderComplete" /> already does — so that method is unchanged
    ///         and the TokenRequest, Retry and PeerTest paths sharing it are untouched. Composing
    ///         the two therefore produces i2pd's single pass byte for byte, because 48 bytes fit
    ///         inside one ChaCha20 block and the nonce is zero in both halves.
    ///     </para>
    ///     <para>
    ///         Verified against a Session Request i2pd 2.61.0 really sent (batch 4-2c's vector):
    ///         the recovered key makes the Noise AEAD tag verify, which no other value can —
    ///         <c>Ssu2SessionRequestVectorTest</c>.
    ///     </para>
    /// </summary>
    public static byte[] ObfuscateEphemeralKey(byte[] ephemeralKey, byte[] kHeader2)
    {
        if (ephemeralKey == null || ephemeralKey.Length != 32)
            throw new ArgumentException("Ephemeral key must be 32 bytes", nameof(ephemeralKey));
        if (kHeader2 == null || kHeader2.Length != 32)
            throw new ArgumentException("k_header_2 must be 32 bytes", nameof(kHeader2));

        // Zero nonce, and 48 bytes of it: the first 16 cover header bytes 16-31 and are consumed
        // by EncryptLongHeaderComplete, leaving 16..48 for the key.
        var zeroIV = new byte[12];
        var mask = GenerateChaCha20Mask(kHeader2, zeroIV, EphemeralKeyOffsetInPass + 32);

        var obfuscated = new byte[32];
        for (var i = 0; i < 32; i++)
            obfuscated[i] = (byte)(ephemeralKey[i] ^ mask[EphemeralKeyOffsetInPass + i]);

        return obfuscated;
    }

    /// <summary>
    ///     Deobfuscate ephemeral key (ChaCha20 is symmetric)
    /// </summary>
    public static byte[] DeobfuscateEphemeralKey(byte[] obfuscatedKey, byte[] kHeader2)
    {
        return ObfuscateEphemeralKey(obfuscatedKey, kHeader2);
    }

    /// <summary>
    ///     ChaCha20 keystream, starting at <b>block 1</b>.
    ///
    ///     <para>
    ///         Batch 4-0 (docs/PRODUCTION-PLAN.md). This used to return the keystream from block
    ///         0, which is <see cref="ChaCha7539Engine" />'s initial state. i2pd starts at block
    ///         1 — <c>libi2pd/Crypto.cpp</c>, <c>ChaCha20()</c>:
    ///     </para>
    ///     <code>
    ///         uint32_t iv[4];
    ///         iv[0] = htole32 (1); memcpy (iv + 1, nonce, 12); // counter | nonce
    ///     </code>
    ///     <para>
    ///         RFC 8439 §2.4 permits either ("this can be set to any number, but will usually be
    ///         zero or one"), so neither library is wrong on its own — but the two disagree, and
    ///         SSU2 is defined by what the network does. Every masked byte was therefore offset
    ///         by 64 bytes of keystream: no header we produced could be read by i2pd and none of
    ///         i2pd's could be read by us.
    ///     </para>
    ///     <para>
    ///         Batch 3-5 measured this against a captured i2pd TokenRequest before it was fixed —
    ///         scanning 128 bytes of keystream for an offset that decoded the header found
    ///         exactly one, at byte 64. <c>Ssu2GoldenVectorTest</c> holds both ends of that:
    ///         one test asserts i2pd's convention, the other decodes the real packet with ours.
    ///     </para>
    ///     <para>
    ///         It stayed invisible because it is self-consistent — both ends of a C#-only
    ///         exchange used block 0, so every internal test passed. Nothing that talks only to
    ///         itself can detect a convention error.
    ///     </para>
    /// </summary>
    private static byte[] GenerateChaCha20Mask(byte[] key, byte[] nonce, int length)
    {
        if (key == null || key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce == null || nonce.Length != 12)
            throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));

        var engine = new ChaCha7539Engine();
        engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        // Discard block 0 rather than calling SkipTo: the engine exposes the skip as a counter
        // manipulation on its parent Salsa20Engine, and generating the block explicitly is both
        // obviously correct and immune to that API changing under us. These buffers are at most
        // 32 bytes of payload on top of the 64 discarded, so this is not worth optimising until
        // batch 10 pools the packet allocations around it.
        var discarded = new byte[ChaCha20BlockSize];
        engine.ProcessBytes(new byte[ChaCha20BlockSize], 0, ChaCha20BlockSize, discarded, 0);

        var input = new byte[length];
        var output = new byte[length];
        engine.ProcessBytes(input, 0, length, output, 0);

        return output;
    }
}