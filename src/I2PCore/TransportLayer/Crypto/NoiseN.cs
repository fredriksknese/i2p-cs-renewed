using System;
using System.Linq;

namespace I2PCore.TransportLayer.Crypto
{
    /// <summary>
    /// Noise N (one-way) pattern implementation
    /// Used for ECIES tunnel building and router messages
    /// 
    /// Pattern: -> e, es, payload
    /// 
    /// Alice (initiator) does not reveal her static key
    /// Bob's (responder) static key is known in advance
    /// Provides forward secrecy and authentication of Bob
    /// </summary>
    public class NoiseN
    {
        private const string ProtocolName = "Noise_N_25519_ChaChaPoly_SHA256";
        
        private readonly NoiseHandshakeState state;
        private readonly bool isInitiator;

        /// <summary>
        /// Create a Noise N initiator (Alice - sends message)
        /// </summary>
        public static NoiseN CreateInitiator(byte[] remoteStaticPublicKey)
        {
            return new NoiseN(true, remoteStaticPublicKey);
        }

        /// <summary>
        /// Create a Noise N responder (Bob - receives message)
        /// </summary>
        public static NoiseN CreateResponder(byte[] localStaticPrivateKey, byte[] localStaticPublicKey)
        {
            return new NoiseN(false, null, localStaticPrivateKey, localStaticPublicKey);
        }

        private NoiseN(
            bool isInitiator,
            byte[] remoteStaticPublicKey = null,
            byte[] localStaticPrivateKey = null,
            byte[] localStaticPublicKey = null)
        {
            this.isInitiator = isInitiator;
            state = new NoiseHandshakeState();
            state.Initialize(ProtocolName);

            if (isInitiator)
            {
                if (remoteStaticPublicKey == null)
                    throw new ArgumentNullException(nameof(remoteStaticPublicKey));

                // Extract X25519 part from Hybrid keys if needed
                if (remoteStaticPublicKey.Length != 32)
                {
                    remoteStaticPublicKey = remoteStaticPublicKey.Skip(remoteStaticPublicKey.Length - 32).Take(32).ToArray();
                }

                state.RemoteStaticPublicKey = remoteStaticPublicKey;
                // Java I2P's Noise N initiator DOES MixHash(rs) as a pre-message step in start().
                // Pattern N has FLAG_REMOTE_REQUIRED which sets REMOTE_PREMSG.
                state.MixHash(remoteStaticPublicKey);
            }
            else
            {
                if (localStaticPrivateKey == null)
                    throw new ArgumentNullException(nameof(localStaticPrivateKey));

                if (localStaticPublicKey == null)
                    throw new ArgumentNullException(nameof(localStaticPublicKey));

                // Extract X25519 part from Hybrid keys if needed
                if (localStaticPrivateKey.Length != 32)
                {
                    localStaticPrivateKey = localStaticPrivateKey.Skip(localStaticPrivateKey.Length - 32).Take(32).ToArray();
                }

                if (localStaticPublicKey.Length != 32)
                {
                    localStaticPublicKey = localStaticPublicKey.Skip(localStaticPublicKey.Length - 32).Take(32).ToArray();
                }

                // Clone keys so Dispose() doesn't wipe the caller's arrays
                state.LocalStaticPrivateKey = (byte[])localStaticPrivateKey.Clone();
                state.LocalStaticPublicKey = (byte[])localStaticPublicKey.Clone();

                // Java I2P's Noise N responder DOES MixHash(rs) as a pre-message step.
                state.MixHash(localStaticPublicKey);
            }
        }

        /// <summary>
        /// Create and encrypt a message (initiator only)
        /// Returns: ephemeralKey (32) || encryptedPayload (len + 16)
        /// </summary>
        public byte[] CreateMessage(byte[] payload)
        {
            if (!isInitiator)
                throw new InvalidOperationException("Only initiator can create messages");

            if (payload == null)
                payload = Array.Empty<byte>();

            // -> e
            state.GenerateEphemeralKey();
            var ephemeralKey = state.LocalEphemeralPublicKey;

            // -> es (ephemeral-static DH)
            state.PerformES(isInitiator: true);

            // -> payload
            var encryptedPayload = state.EncryptPayload(payload);

            // Combine: ephemeralKey || encryptedPayload
            var message = new byte[ephemeralKey.Length + encryptedPayload.Length];
            Array.Copy(ephemeralKey, 0, message, 0, ephemeralKey.Length);
            Array.Copy(encryptedPayload, 0, message, ephemeralKey.Length, encryptedPayload.Length);

            return message;
        }

        /// <summary>
        /// Decrypt and process a message (responder only)
        /// Input: ephemeralKey (32) || encryptedPayload (len + 16)
        /// Returns: decrypted payload
        /// </summary>
        public byte[] ProcessMessage(byte[] message)
        {
            if (isInitiator)
                throw new InvalidOperationException("Only responder can process messages");

            if (message == null || message.Length < 32 + 16)
                throw new ArgumentException("Message too short");

            // Extract ephemeral key
            var ephemeralKey = new byte[32];
            Array.Copy(message, 0, ephemeralKey, 0, 32);

            // Extract encrypted payload
            var encryptedPayload = new byte[message.Length - 32];
            Array.Copy(message, 32, encryptedPayload, 0, encryptedPayload.Length);

            // -> e
            state.ReceiveEphemeralKey(ephemeralKey);

            // -> es (ephemeral-static DH)
            state.PerformES(isInitiator: false);

            // -> payload
            var payload = state.DecryptPayload(encryptedPayload);

            return payload;
        }

        /// <summary>
        /// Get the current handshake hash (for additional processing)
        /// </summary>
        public byte[] GetHandshakeHash()
        {
            return (byte[])state.Hash?.Clone();
        }

        /// <summary>
        /// Get the chaining key (for key derivation)
        /// </summary>
        public byte[] GetChainingKey()
        {
            return (byte[])state.ChainingKey?.Clone();
        }

        /// <summary>
        /// Get the handshake hash (for AEAD associated data in reply decryption)
        /// </summary>
        public byte[] GetHash()
        {
            return (byte[])state.Hash?.Clone();
        }

        /// <summary>
        /// Clear sensitive key material
        /// </summary>
        public void Dispose()
        {
            if (state.LocalStaticPrivateKey != null)
                Array.Clear(state.LocalStaticPrivateKey, 0, state.LocalStaticPrivateKey.Length);
            if (state.LocalEphemeralPrivateKey != null)
                Array.Clear(state.LocalEphemeralPrivateKey, 0, state.LocalEphemeralPrivateKey.Length);
        }
    }

    /// <summary>
    /// Helper class for creating ECIES tunnel build records using Noise N
    /// Provides convenience methods specific to I2P tunnel building
    /// </summary>
    public static class NoiseNTunnelBuilder
    {
        /// <summary>
        /// Encrypt a tunnel build request record
        /// Returns: ephemeralKey (32) || encryptedRecord (464 + 16)
        /// Total: 512 bytes (before adding router hash truncation)
        /// </summary>
        public static byte[] EncryptBuildRecord(
            byte[] hopPublicKey,
            byte[] buildRequestRecord)
        {
            if (buildRequestRecord == null || buildRequestRecord.Length != 464)
                throw new ArgumentException("Build request record must be 464 bytes");

            var noise = NoiseN.CreateInitiator(hopPublicKey);
            var encrypted = noise.CreateMessage(buildRequestRecord);
            noise.Dispose();

            return encrypted;
        }

        /// <summary>
        /// Decrypt a tunnel build request record
        /// Input: ephemeralKey (32) || encryptedRecord (464 + 16)
        /// Returns: decrypted build request record (464 bytes)
        /// </summary>
        public static byte[] DecryptBuildRecord(
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey,
            byte[] encryptedMessage)
        {
            if (encryptedMessage == null || encryptedMessage.Length != 512)
                throw new ArgumentException("Encrypted message must be 512 bytes");

            var noise = NoiseN.CreateResponder(localStaticPrivateKey, localStaticPublicKey);
            var decrypted = noise.ProcessMessage(encryptedMessage);
            noise.Dispose();

            return decrypted;
        }

        /// <summary>
        /// Derive ChaCha20 reply keys from the Noise N handshake
        /// Used for encrypting tunnel build reply records
        /// </summary>
        public static (byte[] replyKey, byte[] replyIV) DeriveReplyKeys(
            byte[] ephemeralPrivateKey,
            byte[] hopPublicKey)
        {
            // Extract X25519 part from Hybrid keys if needed
            if (hopPublicKey != null && hopPublicKey.Length != 32)
            {
                hopPublicKey = hopPublicKey.Skip(hopPublicKey.Length - 32).Take(32).ToArray();
            }

            // Recreate the DH shared secret
            var sharedSecret = X25519.ComputeSharedSecret(ephemeralPrivateKey, hopPublicKey);

            // Use HKDF to derive reply keys
            // This matches the key derivation done during the Noise handshake
            var keyMaterial = HKDF.DeriveKey(
                salt: null,
                inputKeyMaterial: sharedSecret,
                info: System.Text.Encoding.ASCII.GetBytes("tunnel-reply"),
                outputLength: 64);

            var replyKey = new byte[32];
            var replyIV = new byte[32];
            Array.Copy(keyMaterial, 0, replyKey, 0, 32);
            Array.Copy(keyMaterial, 32, replyIV, 0, 32);

            // Clear sensitive data
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            return (replyKey, replyIV);
        }
    }
}
