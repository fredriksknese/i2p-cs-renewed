using System;

namespace I2PCore.TransportLayer.Crypto
{
    /// <summary>
    /// SipHash-2-4 implementation
    /// Used in NTCP2 for obfuscating frame length fields
    /// 
    /// Reference: https://www.131002.net/siphash/
    /// Paper: "SipHash: a fast short-input PRF" by Aumasson and Bernstein
    /// </summary>
    public static class SipHash
    {
        /// <summary>
        /// Compute SipHash-2-4
        /// </summary>
        /// <param name="key0">First 8 bytes of key (little-endian)</param>
        /// <param name="key1">Second 8 bytes of key (little-endian)</param>
        /// <param name="data">Input data to hash</param>
        /// <returns>64-bit hash value</returns>
        public static ulong Hash24(ulong key0, ulong key1, byte[] data)
        {
            // Initialize state
            ulong v0 = 0x736f6d6570736575UL ^ key0;
            ulong v1 = 0x646f72616e646f6dUL ^ key1;
            ulong v2 = 0x6c7967656e657261UL ^ key0;
            ulong v3 = 0x7465646279746573UL ^ key1;

            int length = data.Length;
            int blocks = length / 8;

            // Process 8-byte blocks
            for (int i = 0; i < blocks; i++)
            {
                ulong m = ReadLittleEndianUInt64(data, i * 8);
                v3 ^= m;
                
                // SipRound x 2 (the "2" in SipHash-2-4)
                SipRound(ref v0, ref v1, ref v2, ref v3);
                SipRound(ref v0, ref v1, ref v2, ref v3);
                
                v0 ^= m;
            }

            // Process remaining bytes and append length
            ulong lastBlock = (ulong)length << 56;
            int remaining = length % 8;
            int offset = blocks * 8;

            for (int i = 0; i < remaining; i++)
            {
                lastBlock |= ((ulong)data[offset + i]) << (i * 8);
            }

            v3 ^= lastBlock;
            
            // SipRound x 2
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);
            
            v0 ^= lastBlock;

            // Finalization
            v2 ^= 0xff;
            
            // SipRound x 4 (the "4" in SipHash-2-4)
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);

            return v0 ^ v1 ^ v2 ^ v3;
        }

        /// <summary>
        /// One SipRound
        /// </summary>
        private static void SipRound(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
        {
            v0 += v1;
            v1 = RotateLeft(v1, 13);
            v1 ^= v0;
            v0 = RotateLeft(v0, 32);

            v2 += v3;
            v3 = RotateLeft(v3, 16);
            v3 ^= v2;

            v0 += v3;
            v3 = RotateLeft(v3, 21);
            v3 ^= v0;

            v2 += v1;
            v1 = RotateLeft(v1, 17);
            v1 ^= v2;
            v2 = RotateLeft(v2, 32);
        }

        /// <summary>
        /// Rotate left (circular shift)
        /// </summary>
        private static ulong RotateLeft(ulong value, int bits)
        {
            return (value << bits) | (value >> (64 - bits));
        }

        /// <summary>
        /// Read 64-bit little-endian integer
        /// </summary>
        private static ulong ReadLittleEndianUInt64(byte[] buffer, int offset)
        {
            return ((ulong)buffer[offset + 0])
                 | ((ulong)buffer[offset + 1] << 8)
                 | ((ulong)buffer[offset + 2] << 16)
                 | ((ulong)buffer[offset + 3] << 24)
                 | ((ulong)buffer[offset + 4] << 32)
                 | ((ulong)buffer[offset + 5] << 40)
                 | ((ulong)buffer[offset + 6] << 48)
                 | ((ulong)buffer[offset + 7] << 56);
        }

        /// <summary>
        /// Write 64-bit little-endian integer
        /// </summary>
        public static void WriteLittleEndianUInt64(byte[] buffer, int offset, ulong value)
        {
            buffer[offset + 0] = (byte)(value);
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)(value >> 16);
            buffer[offset + 3] = (byte)(value >> 24);
            buffer[offset + 4] = (byte)(value >> 32);
            buffer[offset + 5] = (byte)(value >> 40);
            buffer[offset + 6] = (byte)(value >> 48);
            buffer[offset + 7] = (byte)(value >> 56);
        }

        /// <summary>
        /// Obfuscate a 16-bit frame length using SipHash
        /// Used in NTCP2 data phase
        /// </summary>
        /// <param name="length">Frame length to obfuscate</param>
        /// <param name="key0">SipHash key 0</param>
        /// <param name="key1">SipHash key 1</param>
        /// <param name="iv">Current IV (8 bytes, will be updated)</param>
        /// <returns>Obfuscated length</returns>
        public static ushort ObfuscateLength(ushort length, ulong key0, ulong key1, ref byte[] iv)
        {
            // Compute next IV = SipHash-2-4(key, current IV)
            var nextIV = Hash24(key0, key1, iv);
            
            // Update IV with next value
            WriteLittleEndianUInt64(iv, 0, nextIV);
            
            // XOR length with first 2 bytes of new IV
            var mask = (ushort)(nextIV & 0xFFFF);
            return (ushort)(length ^ mask);
        }

        /// <summary>
        /// Deobfuscate a 16-bit frame length using SipHash
        /// </summary>
        public static ushort DeobfuscateLength(ushort obfuscatedLength, ulong key0, ulong key1, ref byte[] iv)
        {
            // Same operation as obfuscate (XOR is its own inverse)
            return ObfuscateLength(obfuscatedLength, key0, key1, ref iv);
        }
    }
}
