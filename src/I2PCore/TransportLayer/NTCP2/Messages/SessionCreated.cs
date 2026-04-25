using System;
using I2PCore.Crypto;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.NTCP2.Messages
{
    /// <summary>
    /// NTCP2 Session Created (Handshake Message 2)
    /// 
    /// Noise XK pattern: <- e, ee
    /// 
    /// Structure:
    /// - Y: 32 bytes, AES-256-CBC encrypted ephemeral key (obfuscated)
    /// - Encrypted payload: 32 bytes (16 byte options + 16 byte MAC)
    /// - Padding: 0+ bytes (optional, authenticated in next message)
    /// 
    /// Total: 64+ bytes
    /// </summary>
    public class SessionCreated
    {
        public byte[] EphemeralKey { get; set; }  // Y, 32 bytes (before encryption)
        public ushort PaddingLength { get; set; }
        public uint TimestampB { get; set; }
        public byte[] Padding { get; set; }

        public const int ENCRYPTED_KEY_SIZE = 32;
        public const int ENCRYPTED_PAYLOAD_SIZE = 32;
        public const int MIN_SIZE = 64;

        public static SessionCreated Parse(I2PBufferCursor data, byte[] bobRouterHash, byte[] aesState)
        {
            var created = new SessionCreated();

            // Read AES-encrypted Y (using AES state from message 1)
            var encryptedY = data.ReadBlock(ENCRYPTED_KEY_SIZE);
            created.EphemeralKey = DecryptEphemeralKey(encryptedY, bobRouterHash, aesState);

            // Read ChaCha20-Poly1305 encrypted payload
            var encryptedPayload = data.ReadBlock(ENCRYPTED_PAYLOAD_SIZE);
            
            // TODO: Decrypt using Noise protocol
            
            // Read padding if present
            var remaining = data.Remaining;
            if (remaining > 0)
            {
                created.Padding = data.ReadBlock(remaining).ToByteArray();
            }

            return created;
        }

        public byte[] ToByteArray(byte[] bobRouterHash, byte[] aesState)
        {
            var result = new I2PByteBlock(new byte[4096]);
            var writer = new I2PBufferCursor(result);

            // Encrypt ephemeral key Y with AES-256-CBC
            var encryptedY = EncryptEphemeralKey(EphemeralKey, bobRouterHash, aesState);
            writer.WriteBytes(encryptedY);

            // Build options block
            var options = BuildOptionsBlock();
            
            // Encrypt options with ChaCha20-Poly1305 (Noise)
            var encryptedOptions = EncryptOptions(options);
            writer.WriteBytes(encryptedOptions);

            // Add padding
            if (Padding != null && Padding.Length > 0)
            {
                writer.WriteBytes(Padding);
            }

            return result.ToByteArray();
        }

        private byte[] BuildOptionsBlock()
        {
            var options = new byte[16];
            var writer = new I2PBufferCursor(options);

            writer.WriteUInt16BigEndian(0);  // Reserved
            writer.WriteUInt16BigEndian(PaddingLength);
            writer.WriteUInt32BigEndian(0);  // Reserved
            writer.WriteUInt32BigEndian(TimestampB);
            writer.WriteUInt32BigEndian(0);  // Reserved

            return options;
        }

        private static byte[] EncryptEphemeralKey(byte[] key, byte[] routerHash, byte[] aesState)
        {
            // AES-256-CBC encryption continuing from message 1 state
            // aesState is the IV after encrypting message 1
            return AESObfuscation.Encrypt(key, routerHash, aesState);
        }

        private static byte[] DecryptEphemeralKey(I2PByteBlock encryptedKey, byte[] routerHash, byte[] aesState)
        {
            // AES-256-CBC decryption
            return AESObfuscation.Decrypt(encryptedKey.ToByteArray(), routerHash, aesState);
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
