using System;
using System.Collections.Generic;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.SessionLayer.ECIES
{
    /// <summary>
    /// ECIES New Session Message
    /// Noise IK pattern: -> e, es, s, ss, payload
    /// Initiator sends ephemeral key, encrypted static key, and payload
    /// Uses Elligator2 encoding for ephemeral key
    /// </summary>
    public class ECIESNewSessionMessage
    {
        /// <summary>
        /// Ephemeral public key (32 bytes, Elligator2 encoded)
        /// </summary>
        public byte[] EphemeralPublicKey { get; set; }

        /// <summary>
        /// Encrypted static public key + payload
        /// </summary>
        public byte[] EncryptedData { get; set; }

        /// <summary>
        /// Poly1305 MAC (16 bytes)
        /// </summary>
        public byte[] MAC { get; set; }

        /// <summary>
        /// Raw message bytes for passing to Noise state
        /// </summary>
        public byte[] RawMessage { get; set; }

        public const int MinimumSize = 48; // 32 (ephemeral) + 0 (payload) + 16 (MAC)

        public static ECIESNewSessionMessage Parse(byte[] data)
        {
            if (data == null || data.Length < MinimumSize)
                throw new ArgumentException($"Data must be at least {MinimumSize} bytes", nameof(data));

            return new ECIESNewSessionMessage
            {
                EphemeralPublicKey = data[..32],
                EncryptedData = data[32..^16],
                MAC = data[^16..],
                RawMessage = (byte[])data.Clone()
            };
        }

        public (byte[] payload, byte[] remoteStaticKey) Decrypt(
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey)
        {
            // Decode Elligator2 ephemeral key
            var ephemeralKey = Elligator2.Decode(EphemeralPublicKey);

            // Create Noise IK responder for decryption
            var noiseIK = NoiseIK.CreateResponder(
                localStaticPrivateKey,
                localStaticPublicKey);

            // Decrypt: extracts remote static key and payload
            var fullMessage = ToByteArray();
            var (payload, remoteStaticKey) = noiseIK.ProcessNewSessionMessage(fullMessage);

            return (payload, remoteStaticKey);
        }

        public byte[] ToByteArray()
        {
            var result = new byte[32 + EncryptedData.Length + 16];
            Array.Copy(EphemeralPublicKey, 0, result, 0, 32);
            Array.Copy(EncryptedData, 0, result, 32, EncryptedData.Length);
            Array.Copy(MAC, 0, result, 32 + EncryptedData.Length, 16);
            return result;
        }
    }

    /// <summary>
    /// ECIES New Session Reply Message
    /// Noise IK pattern: <- tag, e, ee, se, payload
    /// Responder sends ephemeral key and encrypted payload with session tags
    /// </summary>
    public class ECIESNewSessionReplyMessage
    {
        /// <summary>
        /// Reply tag (16 bytes)
        /// </summary>
        public byte[] ReplyTag { get; set; }

        /// <summary>
        /// Ephemeral public key (32 bytes)
        /// </summary>
        public byte[] EphemeralPublicKey { get; set; }

        /// <summary>
        /// Encrypted payload (includes session tags)
        /// </summary>
        public byte[] EncryptedPayload { get; set; }

        /// <summary>
        /// Poly1305 MAC (16 bytes)
        /// </summary>
        public byte[] MAC { get; set; }

        /// <summary>
        /// Session tags for future messages
        /// </summary>
        public List<SessionTag> SessionTags { get; set; }

        /// <summary>
        /// Alias for SessionTags for cleaner API
        /// </summary>
        public List<SessionTag> Tags => SessionTags;

        /// <summary>
        /// Raw message bytes for passing to Noise state
        /// </summary>
        public byte[] RawMessage { get; set; }

        public const int MinimumSize = 56; // 8 (tag) + 32 (ephemeral) + 0 (payload) + 16 (MAC)

        public static ECIESNewSessionReplyMessage Parse(byte[] data, List<SessionTag> tags)
        {
            if (data == null || data.Length < MinimumSize)
                throw new ArgumentException($"Data must be at least {MinimumSize} bytes", nameof(data));

            return new ECIESNewSessionReplyMessage
            {
                ReplyTag = data[..8],
                EphemeralPublicKey = data[8..40],
                EncryptedPayload = data[40..^16],
                MAC = data[^16..],
                SessionTags = tags ?? new List<SessionTag>(),
                RawMessage = (byte[])data.Clone()
            };
        }

        /// <summary>
        /// Decrypt using a retained Noise IK state from the initiator.
        /// Note: The proper way to decrypt is via ECIESOutboundSession.ProcessNewSessionReply()
        /// which maintains the Noise IK state from CreateNewSessionMessage.
        /// This standalone decrypt is for backwards compatibility.
        /// </summary>
        public (byte[] payload, List<SessionTag> tags) Decrypt(
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey)
        {
            // Standalone decryption is not possible without the original Noise IK state
            // The initiator must maintain state from CreateNewSessionMessage through ProcessNewSessionReply
            Logging.LogWarning("ECIESNewSessionReplyMessage.Decrypt called without Noise state - use ECIESOutboundSession instead");
            return (Array.Empty<byte>(), SessionTags);
        }

        public byte[] ToByteArray()
        {
            var result = new byte[8 + 32 + EncryptedPayload.Length + 16];
            Array.Copy(ReplyTag, 0, result, 0, 8);
            Array.Copy(EphemeralPublicKey, 0, result, 8, 32);
            Array.Copy(EncryptedPayload, 0, result, 40, EncryptedPayload.Length);
            Array.Copy(MAC, 0, result, 40 + EncryptedPayload.Length, 16);
            return result;
        }
    }

    /// <summary>
    /// ECIES Existing Session Message
    /// Uses session tag + ChaCha20-Poly1305 encryption
    /// Smaller than new session messages
    /// </summary>
    public class ECIESExistingSessionMessage
    {
        /// <summary>
        /// Session tag (16 bytes)
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

        public const int MinimumSize = 24; // 8 (tag) + 0 (payload) + 16 (MAC)

        /// <summary>
        /// Create an existing session message with a tag index for nonce derivation.
        /// Per I2P ECIES-X25519-AEAD-Ratchet spec, the nonce is derived from
        /// the tag's index in the tag set (4 bytes zero + 8 bytes LE index).
        /// </summary>
        public static ECIESExistingSessionMessage Create(
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

            var nonce = CreateNonce(tagIndex);
            var (encryptedPayload, mac) = EncryptPayload(sessionKey, payload, nonce);

            return new ECIESExistingSessionMessage
            {
                Tag = tag,
                EncryptedPayload = encryptedPayload,
                MAC = mac
            };
        }

        public static ECIESExistingSessionMessage Parse(byte[] data)
        {
            if (data == null || data.Length < MinimumSize)
                throw new ArgumentException($"Data must be at least {MinimumSize} bytes", nameof(data));

            var tagBytes = new byte[8];
            Array.Copy(data, 0, tagBytes, 0, 8);

            var mac = new byte[16];
            Array.Copy(data, data.Length - 16, mac, 0, 16);

            var encryptedPayload = new byte[data.Length - 24];
            Array.Copy(data, 8, encryptedPayload, 0, encryptedPayload.Length);

            return new ECIESExistingSessionMessage
            {
                Tag = new SessionTag(tagBytes),
                EncryptedPayload = encryptedPayload,
                MAC = mac
            };
        }

        /// <summary>
        /// Decrypt the payload using the session key and tag index for nonce derivation.
        /// </summary>
        public byte[] Decrypt(byte[] sessionKey, int tagIndex = 0)
        {
            if (sessionKey == null || sessionKey.Length != 32)
                throw new ArgumentException("Session key must be 32 bytes", nameof(sessionKey));

            var nonce = CreateNonce(tagIndex);
            return DecryptPayload(sessionKey, EncryptedPayload, MAC, nonce);
        }

        public byte[] ToByteArray()
        {
            var result = new byte[8 + EncryptedPayload.Length + 16];
            Array.Copy(Tag.ToByteArray(), 0, result, 0, 8);
            Array.Copy(EncryptedPayload, 0, result, 8, EncryptedPayload.Length);
            Array.Copy(MAC, 0, result, 8 + EncryptedPayload.Length, 16);
            return result;
        }

        /// <summary>
        /// Create a 12-byte AEAD nonce from a sequence number.
        /// Format: 4 bytes zero + 8 bytes little-endian sequence number.
        /// Matches i2pd's CreateNonce(uint64_t seqn, uint8_t* nonce).
        /// </summary>
        internal static byte[] CreateNonce(long sequenceNumber)
        {
            var nonce = new byte[12];
            // First 4 bytes are zero
            // Last 8 bytes are the sequence number in little-endian
            nonce[4] = (byte)(sequenceNumber & 0xFF);
            nonce[5] = (byte)((sequenceNumber >> 8) & 0xFF);
            nonce[6] = (byte)((sequenceNumber >> 16) & 0xFF);
            nonce[7] = (byte)((sequenceNumber >> 24) & 0xFF);
            nonce[8] = (byte)((sequenceNumber >> 32) & 0xFF);
            nonce[9] = (byte)((sequenceNumber >> 40) & 0xFF);
            nonce[10] = (byte)((sequenceNumber >> 48) & 0xFF);
            nonce[11] = (byte)((sequenceNumber >> 56) & 0xFF);
            return nonce;
        }

        private static (byte[] ciphertext, byte[] mac) EncryptPayload(byte[] key, byte[] plaintext, byte[] nonce)
        {
            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
            cipher.Init(true, parameters);

            var ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            len += cipher.DoFinal(ciphertext, len);

            var mac = new byte[16];
            Array.Copy(ciphertext, ciphertext.Length - 16, mac, 0, 16);

            var ciphertextOnly = new byte[ciphertext.Length - 16];
            Array.Copy(ciphertext, 0, ciphertextOnly, 0, ciphertextOnly.Length);

            return (ciphertextOnly, mac);
        }

        private static byte[] DecryptPayload(byte[] key, byte[] ciphertext, byte[] mac, byte[] nonce)
        {
            var fullCiphertext = new byte[ciphertext.Length + mac.Length];
            Array.Copy(ciphertext, 0, fullCiphertext, 0, ciphertext.Length);
            Array.Copy(mac, 0, fullCiphertext, ciphertext.Length, mac.Length);

            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
            cipher.Init(false, parameters);

            var plaintext = new byte[cipher.GetOutputSize(fullCiphertext.Length)];
            var len = cipher.ProcessBytes(fullCiphertext, 0, fullCiphertext.Length, plaintext, 0);
            len += cipher.DoFinal(plaintext, len);

            return plaintext;
        }
    }

    /// <summary>
    /// ECIES One-Time Message (for connectionless messages)
    /// Uses Noise N pattern: -> e, es, payload
    /// No session state required
    /// </summary>
    public class ECIESOneTimeMessage
    {
        public byte[] EphemeralPublicKey { get; set; }
        public byte[] EncryptedPayload { get; set; }
        public byte[] MAC { get; set; }

        public const int MinimumSize = 48;

        public static ECIESOneTimeMessage Create(
            byte[] remoteStaticPublicKey,
            byte[] payload)
        {
            if (remoteStaticPublicKey == null || remoteStaticPublicKey.Length != 32)
                throw new ArgumentException("Remote static public key must be 32 bytes", nameof(remoteStaticPublicKey));

            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            var noiseN = NoiseN.CreateInitiator(remoteStaticPublicKey);
            var message = noiseN.CreateMessage(payload);

            return Parse(message);
        }

        public static ECIESOneTimeMessage Parse(byte[] data)
        {
            if (data == null || data.Length < MinimumSize)
                throw new ArgumentException($"Data must be at least {MinimumSize} bytes", nameof(data));

            return new ECIESOneTimeMessage
            {
                EphemeralPublicKey = data[..32],
                EncryptedPayload = data[32..^16],
                MAC = data[^16..]
            };
        }

        public byte[] Decrypt(byte[] localStaticPrivateKey, byte[] localStaticPublicKey)
        {
            var noiseN = NoiseN.CreateResponder(localStaticPrivateKey, localStaticPublicKey);
            return noiseN.ProcessMessage(ToByteArray());
        }

        public byte[] ToByteArray()
        {
            var result = new byte[32 + EncryptedPayload.Length + 16];
            Array.Copy(EphemeralPublicKey, 0, result, 0, 32);
            Array.Copy(EncryptedPayload, 0, result, 32, EncryptedPayload.Length);
            Array.Copy(MAC, 0, result, 32 + EncryptedPayload.Length, 16);
            return result;
        }
    }
}
