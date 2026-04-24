using System;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TransportLayer.Crypto;

namespace I2PCore.TransportLayer.NTCP2.Messages
{
    /// <summary>
    /// NTCP2 Session Request (Handshake Message 1)
    /// 
    /// Noise XK pattern: -> e, es
    /// 
    /// Structure:
    /// - X: 32 bytes, AES-256-CBC encrypted ephemeral key (obfuscated)
    /// - Encrypted payload: 32 bytes (16 byte options + 16 byte MAC)
    /// - Padding: 0+ bytes (optional, authenticated in next message)
    /// 
    /// Total: 64+ bytes
    /// </summary>
    public class SessionRequest
    {
        public byte[] EphemeralKey { get; set; }  // X, 32 bytes (before encryption)
        public byte NetworkId { get; set; } = 2;  // I2P mainnet
        public byte Version { get; set; } = 2;
        public ushort PaddingLength { get; set; }
        public ushort Message3Part2Length { get; set; }  // m3p2len
        public uint TimestampA { get; set; }
        public byte[] Padding { get; set; }

        public const int ENCRYPTED_KEY_SIZE = 32;
        public const int ENCRYPTED_PAYLOAD_SIZE = 32;  // 16 options + 16 MAC
        public const int MIN_SIZE = 64;  // X + payload
        public const int MAX_SIZE_NTCP_COMPAT = 287;  // For dual NTCP/NTCP2 ports

        public static SessionRequest Parse(BufRef data, byte[] bobRouterHash, byte[] bobIV, NoiseXK noise)
        {
            var request = new SessionRequest();

            // Read AES-encrypted X
            var encryptedX = data.ReadBufLen(ENCRYPTED_KEY_SIZE);
            request.EphemeralKey = DecryptEphemeralKey(encryptedX, bobRouterHash, bobIV);

            // Read ChaCha20-Poly1305 encrypted payload
            var encryptedPayload = data.ReadBufLen(ENCRYPTED_PAYLOAD_SIZE);
            
            // Decrypt using Noise protocol (Message 1: e, es)
            var payload = noise.ProcessMessage1(request.EphemeralKey, encryptedPayload.ToByteArray());
            
            // Parse options block from decrypted payload
            var options = ParseOptionsBlock(payload);
            request.NetworkId = options.NetworkId;
            request.Version = options.Version;
            request.PaddingLength = options.PaddingLength;
            request.Message3Part2Length = options.Message3Part2Length;
            request.TimestampA = options.TimestampA;
            
            // Read padding if present
            var remaining = data.BaseArray.Length - data.BaseArrayOffset;
            if (remaining > 0)
            {
                request.Padding = data.ReadBufLen(remaining).ToByteArray();
                
                // CRITICAL: MixHash padding for authentication in message 2
                // Per NTCP2 spec line 420
                noise.MixHashPadding(request.Padding);
            }

            return request;
        }

        private static (byte NetworkId, byte Version, ushort PaddingLength, ushort Message3Part2Length, uint TimestampA) ParseOptionsBlock(byte[] options)
        {
            if (options.Length < 16)
                throw new Exception("Invalid options block size");

            var reader = new BufRef(options);
            var networkId = reader.Read8();
            var version = reader.Read8();
            var paddingLength = reader.ReadFlip16();
            var message3Part2Length = reader.ReadFlip16();
            reader.ReadFlip16(); // Reserved
            var timestampA = reader.ReadFlip32();

            return (networkId, version, paddingLength, message3Part2Length, timestampA);
        }

        public byte[] ToByteArray(byte[] bobRouterHash, byte[] bobIV)
        {
            var result = new BufLen(new byte[4096]);
            var writer = new BufRefLen(result);

            // Encrypt ephemeral key with AES-256-CBC
            var encryptedX = EncryptEphemeralKey(EphemeralKey, bobRouterHash, bobIV);
            writer.Write(encryptedX);

            // Build options block
            var options = BuildOptionsBlock();
            
            // Encrypt options with ChaCha20-Poly1305 (Noise)
            var encryptedOptions = EncryptOptions(options);
            writer.Write(encryptedOptions);

            // Add padding
            if (Padding != null && Padding.Length > 0)
            {
                writer.Write(Padding);
            }

            return result.ToByteArray();
        }

        private byte[] BuildOptionsBlock()
        {
            var options = new byte[16];
            var writer = new BufRefLen(options);

            writer.Write8(NetworkId);
            writer.Write8(Version);
            writer.WriteFlip16(PaddingLength);
            writer.WriteFlip16(Message3Part2Length);
            writer.WriteFlip16(0);  // Reserved
            writer.WriteFlip32(TimestampA);
            writer.WriteFlip32(0);  // Reserved

            return options;
        }

        private static byte[] EncryptEphemeralKey(byte[] key, byte[] routerHash, byte[] iv)
        {
            // AES-256-CBC encryption for obfuscation
            // key = router hash (32 bytes)
            // IV = Bob's published IV (16 bytes)
            return Crypto.AESObfuscation.Encrypt(key, routerHash, iv);
        }

        private static byte[] DecryptEphemeralKey(BufLen encryptedKey, byte[] routerHash, byte[] iv)
        {
            // AES-256-CBC decryption
            return Crypto.AESObfuscation.Decrypt(encryptedKey.ToByteArray(), routerHash, iv);
        }

        private byte[] EncryptOptions(byte[] options)
        {
            // ChaCha20-Poly1305 AEAD encryption (Noise protocol)
            // This should be done by the Noise protocol handler, not here
            // Return plaintext options - encryption happens in session layer
            return options;
        }
    }
}
