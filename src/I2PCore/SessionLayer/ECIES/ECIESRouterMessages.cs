using System;
using System.Collections.Generic;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES
{
    /// <summary>
    /// ECIES Router New Session Message
    /// Sent when no existing session exists
    /// Uses Noise N pattern (one-way, ephemeral)
    /// </summary>
    public class ECIESRouterNewSessionMessage
    {
        /// <summary>
        /// Ephemeral X25519 public key (32 bytes)
        /// </summary>
        public byte[] EphemeralPublicKey { get; set; }

        /// <summary>
        /// Encrypted payload (includes tags + actual message)
        /// </summary>
        public byte[] EncryptedPayload { get; set; }

        /// <summary>
        /// Poly1305 MAC (16 bytes)
        /// </summary>
        public byte[] MAC { get; set; }

        /// <summary>
        /// Total message size: 32 (ephemeral) + payload + 16 (MAC)
        /// </summary>
        public const int MinimumSize = 48;

        /// <summary>
        /// Create a new session message
        /// </summary>
        public static ECIESRouterNewSessionMessage Create(
            byte[] remoteStaticPublicKey,
            List<SessionTag> tags,
            byte[] payload)
        {
            if (remoteStaticPublicKey == null || remoteStaticPublicKey.Length != 32)
                throw new ArgumentException("Remote static public key must be 32 bytes", nameof(remoteStaticPublicKey));

            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            // Build message data with tags
            var messageData = BuildMessageData(tags, payload);

            // Create Noise N initiator
            var noiseN = NoiseN.CreateInitiator(remoteStaticPublicKey);

            // Encrypt: -> e, es, payload
            var fullMessage = noiseN.CreateMessage(messageData);

            // Parse result: ephemeral key (32) + encrypted payload + MAC (16)
            return Parse(fullMessage);
        }

        /// <summary>
        /// Parse from wire format
        /// </summary>
        public static ECIESRouterNewSessionMessage Parse(byte[] data)
        {
            if (data == null || data.Length < MinimumSize)
                throw new ArgumentException($"Data must be at least {MinimumSize} bytes", nameof(data));

            var msg = new ECIESRouterNewSessionMessage();

            // Extract ephemeral key (first 32 bytes)
            msg.EphemeralPublicKey = new byte[32];
            Array.Copy(data, 0, msg.EphemeralPublicKey, 0, 32);

            // Extract MAC (last 16 bytes)
            msg.MAC = new byte[16];
            Array.Copy(data, data.Length - 16, msg.MAC, 0, 16);

            // Extract encrypted payload (between ephemeral and MAC)
            var payloadLength = data.Length - 32 - 16;
            msg.EncryptedPayload = new byte[payloadLength];
            Array.Copy(data, 32, msg.EncryptedPayload, 0, payloadLength);

            return msg;
        }

        /// <summary>
        /// Decrypt the message using local static key
        /// </summary>
        public (List<SessionTag> tags, byte[] payload) Decrypt(
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey)
        {
            if (localStaticPrivateKey == null || localStaticPrivateKey.Length != 32)
                throw new ArgumentException("Local static private key must be 32 bytes", nameof(localStaticPrivateKey));

            if (localStaticPublicKey == null || localStaticPublicKey.Length != 32)
                throw new ArgumentException("Local static public key must be 32 bytes", nameof(localStaticPublicKey));

            // Create Noise N responder
            var noiseN = NoiseN.CreateResponder(localStaticPrivateKey, localStaticPublicKey);

            // Reconstruct full message for decryption
            var fullMessage = ToByteArray();

            // Decrypt
            var decryptedData = noiseN.ProcessMessage(fullMessage);

            // Extract tags and payload
            return ExtractTagsAndPayload(decryptedData);
        }

        /// <summary>
        /// Convert to wire format
        /// </summary>
        public byte[] ToByteArray()
        {
            var stream = new BufRefStream();
            stream.Write(EphemeralPublicKey);
            stream.Write(EncryptedPayload);
            stream.Write(MAC);
            return stream.ToByteArray();
        }

        /// <summary>
        /// Build message data with tags and payload
        /// </summary>
        private static byte[] BuildMessageData(List<SessionTag> tags, byte[] payload)
        {
            var stream = new BufRefStream();

            // Write tag count (1 byte)
            stream.Write((byte)(tags?.Count ?? 0));

            // Write tags (16 bytes each)
            if (tags != null)
            {
                foreach (var tag in tags)
                {
                    stream.Write(tag.ToByteArray());
                }
            }

            // Write payload
            stream.Write(payload);

            return stream.ToByteArray();
        }

        /// <summary>
        /// Extract tags and payload from decrypted data
        /// </summary>
        private static (List<SessionTag> tags, byte[] payload) ExtractTagsAndPayload(byte[] data)
        {
            var reader = new BufRef(data);

            // Read tag count
            var tagCount = reader.Read8();

            // Read tags
            var tags = new List<SessionTag>();
            for (int i = 0; i < tagCount; i++)
            {
                var tagBytes = reader.Read(8);
                tags.Add(new SessionTag(tagBytes));
            }

            // Read remaining payload
            var payloadLength = data.Length - (1 + tagCount * 8);
            var payload = reader.Read(payloadLength);

            return (tags, payload);
        }
    }

    /// <summary>
    /// ECIES Router Existing Session Message
    /// Sent when a session already exists
    /// Uses session tag + symmetric encryption (ChaCha20-Poly1305)
    /// </summary>
    public class ECIESRouterExistingSessionMessage
    {
        /// <summary>
        /// Session tag (8 bytes)
        /// </summary>
        public SessionTag Tag { get; set; }

        /// <summary>
        /// Encrypted payload
        /// </summary>
        public byte[] EncryptedPayload { get; set; }

        /// <summary>
        /// Poly1305 MAC (16 bytes)
        /// </summary>
        public byte[] MAC { get; set; }

        /// <summary>
        /// Minimum message size: 16 (tag) + 0 (min payload) + 16 (MAC) = 32 bytes
        /// </summary>
        public const int MinimumSize = 24; // 8 (tag) + 0 (payload) + 16 (MAC)

        /// <summary>
        /// Create an existing session message
        /// </summary>
        public static ECIESRouterExistingSessionMessage Create(
            SessionTag tag,
            byte[] sessionKey,
            byte[] payload,
            int tagIndex = 0)
        {
            if (tag == null)
                throw new ArgumentNullException(nameof(tag));

            if (sessionKey == null || sessionKey.Length != 32)
                throw new ArgumentException("Session key must be 32 bytes", nameof(sessionKey));

            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            var nonce = ECIESExistingSessionMessage.CreateNonce(tagIndex);
            var (encryptedPayload, mac) = EncryptPayload(sessionKey, payload, nonce);

            return new ECIESRouterExistingSessionMessage
            {
                Tag = tag,
                EncryptedPayload = encryptedPayload,
                MAC = mac
            };
        }

        /// <summary>
        /// Parse from wire format
        /// </summary>
        public static ECIESRouterExistingSessionMessage Parse(byte[] data)
        {
            if (data == null || data.Length < MinimumSize)
                throw new ArgumentException($"Data must be at least {MinimumSize} bytes", nameof(data));

            var msg = new ECIESRouterExistingSessionMessage();

            // Extract tag (first 8 bytes)
            var tagBytes = new byte[8];
            Array.Copy(data, 0, tagBytes, 0, 8);
            msg.Tag = new SessionTag(tagBytes);

            // Extract MAC (last 16 bytes)
            msg.MAC = new byte[16];
            Array.Copy(data, data.Length - 16, msg.MAC, 0, 16);

            // Extract payload
            msg.EncryptedPayload = new byte[data.Length - 24];
            Array.Copy(data, 8, msg.EncryptedPayload, 0, msg.EncryptedPayload.Length);

            return msg;
        }

        /// <summary>
        /// Decrypt the payload using session key
        /// </summary>
        public byte[] Decrypt(byte[] sessionKey, int tagIndex = 0)
        {
            if (sessionKey == null || sessionKey.Length != 32)
                throw new ArgumentException("Session key must be 32 bytes", nameof(sessionKey));

            var nonce = ECIESExistingSessionMessage.CreateNonce(tagIndex);
            return DecryptPayload(sessionKey, EncryptedPayload, MAC, nonce);
        }

        /// <summary>
        /// Convert to wire format
        /// </summary>
        public byte[] ToByteArray()
        {
            var stream = new BufRefStream();
            stream.Write(Tag.ToByteArray());
            stream.Write(EncryptedPayload);
            stream.Write(MAC);
            return stream.ToByteArray();
        }

        /// <summary>
        /// Encrypt payload using ChaCha20-Poly1305
        /// </summary>
        private static (byte[] ciphertext, byte[] mac) EncryptPayload(byte[] key, byte[] plaintext, byte[] nonce)
        {
            if (key == null || key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var parameters = new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key), nonce);
            cipher.Init(true, parameters);

            var ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            cipher.DoFinal(ciphertext, len);

            // Extract MAC (last 16 bytes)
            var mac = new byte[16];
            Array.Copy(ciphertext, ciphertext.Length - 16, mac, 0, 16);

            // Ciphertext without MAC
            var ciphertextOnly = new byte[ciphertext.Length - 16];
            Array.Copy(ciphertext, 0, ciphertextOnly, 0, ciphertextOnly.Length);

            return (ciphertextOnly, mac);
        }

        /// <summary>
        /// Decrypt payload using ChaCha20-Poly1305
        /// </summary>
        private static byte[] DecryptPayload(byte[] key, byte[] ciphertext, byte[] mac, byte[] nonce)
        {
            if (key == null || key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            if (mac == null || mac.Length != 16)
                throw new ArgumentException("MAC must be 16 bytes", nameof(mac));

            // Reconstruct full ciphertext with MAC
            var fullCiphertext = new byte[ciphertext.Length + mac.Length];
            Array.Copy(ciphertext, 0, fullCiphertext, 0, ciphertext.Length);
            Array.Copy(mac, 0, fullCiphertext, ciphertext.Length, mac.Length);

            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var parameters = new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key), nonce);
            cipher.Init(false, parameters);

            var plaintext = new byte[cipher.GetOutputSize(fullCiphertext.Length)];
            var len = cipher.ProcessBytes(fullCiphertext, 0, fullCiphertext.Length, plaintext, 0);
            cipher.DoFinal(plaintext, len);

            return plaintext;
        }
    }
}
