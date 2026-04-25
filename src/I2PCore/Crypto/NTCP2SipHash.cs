using System;

namespace I2PCore.Crypto;

/// <summary>
///     NTCP2 SipHash-2-4 implementation for length field obfuscation
///     Per NTCP2 spec lines 1216-1251
///     Used to obfuscate the two-byte length field in data phase messages
/// </summary>
public class NTCP2SipHash
{
    private readonly ulong k0;
    private readonly ulong k1;
    private ulong iv;

    /// <summary>
    ///     Initialize SipHash with keys
    /// </summary>
    public NTCP2SipHash(ulong k0, ulong k1, byte[] iv8)
    {
        this.k0 = k0;
        this.k1 = k1;
        iv = ReadLittleEndianUInt64(iv8, 0);
    }

    /// <summary>
    ///     Initialize SipHash with keys from KDF
    /// </summary>
    /// <param name="sipKeys">32 bytes from KDF (k0=bytes[0:7], k1=bytes[8:15], iv=bytes[16:23])</param>
    public NTCP2SipHash(byte[] sipKeys)
    {
        if (sipKeys == null || sipKeys.Length != 32)
            throw new ArgumentException("SipHash keys must be 32 bytes", nameof(sipKeys));

        // Extract k0, k1 (little-endian)
        k0 = ReadLittleEndianUInt64(sipKeys, 0);
        k1 = ReadLittleEndianUInt64(sipKeys, 8);

        // Extract initial IV (bytes 16-23)
        iv = ReadLittleEndianUInt64(sipKeys, 16);
    }

    /// <summary>
    ///     Obfuscate/Deobfuscate a 2-byte length field
    ///     Per spec: obfuscatedLength = length ^ Mask[n]
    ///     Where Mask[n] = First 2 bytes of IV[n]
    ///     And IV[n] = SipHash-2-4(k0, k1, IV[n-1])
    /// </summary>
    public ushort ObfuscateLength(ushort length)
    {
        // Compute IV[n] = SipHash-2-4(k0, k1, IV[n-1])
        iv = SipHash24(k0, k1, iv);

        // Mask is the first 2 bytes of the new IV (little-endian, so just the lowest 16 bits)
        var mask = (ushort)(iv & 0xFFFF);

        // XOR length with mask
        return (ushort)(length ^ mask);
    }

    /// <summary>
    ///     Deobfuscate a 2-byte length field
    ///     XOR is symmetric, so this is identical to ObfuscateLength
    /// </summary>
    public ushort DeobfuscateLength(ushort obfuscatedLength)
    {
        return ObfuscateLength(obfuscatedLength);
    }

    /// <summary>
    ///     SipHash-2-4 implementation
    ///     Returns 64-bit hash of 64-bit input
    /// </summary>
    private static ulong SipHash24(ulong k0, ulong k1, ulong input)
    {
        // Initialize state
        var v0 = 0x736f6d6570736575UL ^ k0;
        var v1 = 0x646f72616e646f6dUL ^ k1;
        var v2 = 0x6c7967656e657261UL ^ k0;
        var v3 = 0x7465646279746573UL ^ k1;

        // Process input (8 bytes)
        v3 ^= input;
        for (var i = 0; i < 2; i++) SipRound(ref v0, ref v1, ref v2, ref v3);
        v0 ^= input;

        // b = bufsz << 56
        var b = 8UL << 56;
        v3 ^= b;
        for (var i = 0; i < 2; i++) SipRound(ref v0, ref v1, ref v2, ref v3);
        v0 ^= b;

        // Finalization
        v2 ^= 0xff;

        // SipRound x 4 (finalization)
        for (var i = 0; i < 4; i++) SipRound(ref v0, ref v1, ref v2, ref v3);

        // Return hash
        return v0 ^ v1 ^ v2 ^ v3;
    }

    /// <summary>
    ///     SipHash round function
    /// </summary>
    private static void SipRound(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
    {
        v0 += v1;
        v2 += v3;
        v1 = RotateLeft(v1, 13);
        v3 = RotateLeft(v3, 16);
        v1 ^= v0;
        v3 ^= v2;

        v0 = RotateLeft(v0, 32);

        v2 += v1;
        v0 += v3;
        v1 = RotateLeft(v1, 17);
        v3 = RotateLeft(v3, 21);
        v1 ^= v2;
        v3 ^= v0;

        v2 = RotateLeft(v2, 32);
    }

    /// <summary>
    ///     Rotate left (circular shift)
    /// </summary>
    private static ulong RotateLeft(ulong value, int bits)
    {
        return (value << bits) | (value >> (64 - bits));
    }

    /// <summary>
    ///     Read 64-bit unsigned integer in little-endian format
    /// </summary>
    private static ulong ReadLittleEndianUInt64(byte[] buffer, int offset)
    {
        return buffer[offset + 0]
               | ((ulong)buffer[offset + 1] << 8)
               | ((ulong)buffer[offset + 2] << 16)
               | ((ulong)buffer[offset + 3] << 24)
               | ((ulong)buffer[offset + 4] << 32)
               | ((ulong)buffer[offset + 5] << 40)
               | ((ulong)buffer[offset + 6] << 48)
               | ((ulong)buffer[offset + 7] << 56);
    }
}