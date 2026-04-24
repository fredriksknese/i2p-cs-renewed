using System;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.TransportLayer.Crypto
{
    /// <summary>
    /// SSU2 Header Encryption
    /// Per SSU2 spec lines 761-798: Header Encryption
    ///
    /// Uses two-stage ChaCha20 encryption for obfuscation and DPI resistance
    ///
    /// CRITICAL: Key derivation differs by message type:
    /// - Session Request: k_header_1 = bik, k_header_2 = bik (Bob's intro key DIRECTLY, no derivation)
    /// - Session Created: k_header_1 = bik, k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
    /// - Session Confirmed: k_header_1 = bik, k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)
    /// - Data: k_header_2 from data phase KDF
    /// </summary>
    public static class SSU2HeaderEncryption
    {
        /// <summary>
        /// Derive k_header_2 for Session Created
        /// SSU2 spec lines 1255-1270
        /// k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
        /// </summary>
        public static byte[] DeriveSessionCreatedHeaderKey(byte[] chainingKey)
        {
            if (chainingKey == null || chainingKey.Length != 32)
                throw new ArgumentException("Chaining key must be 32 bytes", nameof(chainingKey));

            var info = System.Text.Encoding.ASCII.GetBytes("SessCreateHeader");
            return NoiseKDF.HKDF(chainingKey, Array.Empty<byte>(), info, 32);
        }

        /// <summary>
        /// Derive k_header_2 for Session Confirmed
        /// SSU2 spec lines 1474-1492
        /// k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)
        /// </summary>
        public static byte[] DeriveSessionConfirmedHeaderKey(byte[] chainingKey)
        {
            if (chainingKey == null || chainingKey.Length != 32)
                throw new ArgumentException("Chaining key must be 32 bytes", nameof(chainingKey));

            var info = System.Text.Encoding.ASCII.GetBytes("SessionConfirmed");
            return NoiseKDF.HKDF(chainingKey, Array.Empty<byte>(), info, 32);
        }

        /// <summary>
        /// Encrypt SSU2 long header (32 bytes for Session Request/Created/Confirmed)
        /// Per spec lines 767-797:
        ///   The IV is taken from the END of the PACKET (including payload), not the header!
        ///   - IV1: packet[len-24:len-13] (next-to-last 12 bytes)
        ///   - IV2: packet[len-12:len-1] (last 12 bytes)
        ///   - Bytes 0-7: XOR with first 8 bytes of ChaCha20(k_header_1, IV1)
        ///   - Bytes 8-15: XOR with first 8 bytes of ChaCha20(k_header_2, IV2)
        ///   
        /// Note: This method encrypts the header bytes in place.
        /// The full packet (header + ephemeral key + payload) must be constructed first.
        /// </summary>
        public static void EncryptLongHeaderInPacket(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
        {
            if (packet == null || packet.Length < 64)
                throw new ArgumentException("Packet must be at least 64 bytes (32 header + 32 ephemeral + payload)", nameof(packet));

            int packetLen = packet.Length;

            // IV1: next-to-last 12 bytes of packet (packet[len-24:len-13])
            var iv1 = new byte[12];
            Array.Copy(packet, packetLen - 24, iv1, 0, 12);

            // Generate mask and encrypt bytes 0-7
            var mask1 = GenerateChaCha20Mask(kHeader1, iv1, 8);
            for (int i = 0; i < 8; i++)
            {
                packet[headerOffset + i] ^= mask1[i];
            }

            // IV2: last 12 bytes of packet (packet[len-12:len-1])
            var iv2 = new byte[12];
            Array.Copy(packet, packetLen - 12, iv2, 0, 12);

            // Generate mask and encrypt bytes 8-15
            var mask2 = GenerateChaCha20Mask(kHeader2, iv2, 8);
            for (int i = 8; i < 16; i++)
            {
                packet[headerOffset + i] ^= mask2[i - 8];
            }
        }

        /// <summary>
        /// Encrypt SSU2 long header AND the third part (bytes 16-31)
        /// Per spec lines 788-790: bytes 16-31 are encrypted with ChaCha20(k_header_2, zero IV)
        /// </summary>
        public static void EncryptLongHeaderComplete(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
        {
            // First encrypt bytes 0-15 using IVs from packet end
            EncryptLongHeaderInPacket(packet, headerOffset, kHeader1, kHeader2);

            // Then encrypt bytes 16-31 with zero IV
            var zeroIV = new byte[12];
            var mask = GenerateChaCha20Mask(kHeader2, zeroIV, 16);
            for (int i = 16; i < 32; i++)
            {
                packet[headerOffset + i] ^= mask[i - 16];
            }
        }

        /// <summary>
        /// Decrypt SSU2 long header (32 bytes) - first 16 bytes only
        /// ChaCha20 is symmetric, so decryption is identical to encryption
        /// </summary>
        public static void DecryptLongHeaderInPacket(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
        {
            // ChaCha20 XOR is symmetric
            EncryptLongHeaderInPacket(packet, headerOffset, kHeader1, kHeader2);
        }

        /// <summary>
        /// Decrypt SSU2 long header - all 32 bytes
        /// </summary>
        public static void DecryptLongHeaderComplete(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
        {
            // ChaCha20 XOR is symmetric
            EncryptLongHeaderComplete(packet, headerOffset, kHeader1, kHeader2);
        }

        /// <summary>
        /// Encrypt SSU2 short header (16 bytes for Data packets)
        /// Per spec:
        ///   - Bytes 0-15: XOR with ChaCha20(k_header_2, zero IV)
        /// </summary>
        public static void EncryptShortHeader(byte[] header, byte[] kHeader2)
        {
            if (header == null || header.Length != 16)
                throw new ArgumentException("Header must be 16 bytes for short header", nameof(header));

            var zeroIV = new byte[12];
            var mask = GenerateChaCha20Mask(kHeader2, zeroIV, 16);

            for (int i = 0; i < 16; i++)
            {
                header[i] ^= mask[i];
            }
        }

        /// <summary>
        /// Decrypt SSU2 short header (16 bytes)
        /// ChaCha20 is symmetric, so decryption is identical to encryption
        /// </summary>
        public static void DecryptShortHeader(byte[] header, byte[] kHeader2)
        {
            EncryptShortHeader(header, kHeader2);
        }

        /// <summary>
        /// Encrypt SSU2 short header (16 bytes) in a complete packet
        /// For Session Confirmed only - uses only k_header_2
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
        /// Decrypt SSU2 short header (16 bytes) in a complete packet
        /// ChaCha20 is symmetric, so decryption is identical to encryption
        /// </summary>
        public static void DecryptShortHeaderInPacket(byte[] packet, int headerOffset, byte[] kHeader1, byte[] kHeader2)
        {
            EncryptShortHeaderInPacket(packet, headerOffset, kHeader1, kHeader2);
        }

        /// <summary>
        /// Obfuscate ephemeral key with ChaCha20 (for Session Request/Created)
        /// Per spec lines 788-790: Uses k_header_2 with ZERO IV (all zeros nonce)
        /// This is part of the header bytes 16-63 encryption
        /// </summary>
        public static byte[] ObfuscateEphemeralKey(byte[] ephemeralKey, byte[] kHeader2)
        {
            if (ephemeralKey == null || ephemeralKey.Length != 32)
                throw new ArgumentException("Ephemeral key must be 32 bytes", nameof(ephemeralKey));
            if (kHeader2 == null || kHeader2.Length != 32)
                throw new ArgumentException("k_header_2 must be 32 bytes", nameof(kHeader2));

            // Per spec: IV is zero for ephemeral key obfuscation
            var zeroIV = new byte[12];

            // Generate ChaCha20 keystream and XOR with ephemeral key
            var mask = GenerateChaCha20Mask(kHeader2, zeroIV, 32);
            var obfuscated = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                obfuscated[i] = (byte)(ephemeralKey[i] ^ mask[i]);
            }

            return obfuscated;
        }

        /// <summary>
        /// Deobfuscate ephemeral key (ChaCha20 is symmetric)
        /// </summary>
        public static byte[] DeobfuscateEphemeralKey(byte[] obfuscatedKey, byte[] kHeader2)
        {
            return ObfuscateEphemeralKey(obfuscatedKey, kHeader2);
        }

        /// <summary>
        /// Generate ChaCha20 keystream mask
        /// </summary>
        private static byte[] GenerateChaCha20Mask(byte[] key, byte[] nonce, int length)
        {
            if (key == null || key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes", nameof(key));
            if (nonce == null || nonce.Length != 12)
                throw new ArgumentException("Nonce must be 12 bytes", nameof(nonce));

            var engine = new ChaCha7539Engine();
            engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

            var input = new byte[length];
            var output = new byte[length];
            engine.ProcessBytes(input, 0, length, output, 0);

            return output;
        }

    }
}
