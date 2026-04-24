using System;

namespace I2PCore.TransportLayer.Crypto
{
    /// <summary>
    /// Noise IK (interactive handshake) pattern implementation
    /// Used for ECIES-X25519-AEAD-Ratchet (destination-to-destination encryption)
    /// 
    /// Pattern:
    ///   <- s (Bob's static key known in advance)
    ///   -> e, es, s, ss, payload (New Session)
    ///   <- tag, e, ee, se, payload (New Session Reply)
    /// 
    /// Alice (initiator) reveals her static key immediately
    /// Bob's (responder) static key is known in advance
    /// Provides mutual authentication and forward secrecy after message 2
    /// </summary>
    public class NoiseIK
    {
        // Note: Modified protocol name with "elg2" suffix to indicate I2P extensions
        private const string ProtocolName = "Noise_IKelg2_25519_ChaChaPoly_SHA256";
        
        private readonly NoiseHandshakeState state;
        private readonly bool isInitiator;
        private byte[] replyTag; // 8-byte tag for New Session Reply

        /// <summary>
        /// Create a Noise IK initiator (Alice - sends New Session)
        /// </summary>
        public static NoiseIK CreateInitiator(
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey,
            byte[] remoteStaticPublicKey)
        {
            return new NoiseIK(
                isInitiator: true,
                localStaticPrivateKey: localStaticPrivateKey,
                localStaticPublicKey: localStaticPublicKey,
                remoteStaticPublicKey: remoteStaticPublicKey);
        }

        /// <summary>
        /// Create a Noise IK responder (Bob - receives New Session)
        /// </summary>
        public static NoiseIK CreateResponder(
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey)
        {
            return new NoiseIK(
                isInitiator: false,
                localStaticPrivateKey: localStaticPrivateKey,
                localStaticPublicKey: localStaticPublicKey);
        }

        private NoiseIK(
            bool isInitiator,
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey,
            byte[] remoteStaticPublicKey = null)
        {
            this.isInitiator = isInitiator;
            state = new NoiseHandshakeState();
            state.Initialize(ProtocolName);
            // Java I2P's Noise implementation (Southern Storm) specifically skips 
            // the initial MixHash if the prologue is null/empty.
            // Our previous MixHashNullPrologue() was causing a divergence for ECIES.
            // state.MixHashNullPrologue(); 

            if (localStaticPrivateKey == null || localStaticPrivateKey.Length != 32)
                throw new ArgumentException("Local static private key required and must be 32 bytes");
            
            if (localStaticPublicKey == null || localStaticPublicKey.Length != 32)
                throw new ArgumentException("Local static public key required and must be 32 bytes");

            state.LocalStaticPrivateKey = localStaticPrivateKey;
            state.LocalStaticPublicKey = localStaticPublicKey;

            if (isInitiator)
            {
                if (remoteStaticPublicKey == null || remoteStaticPublicKey.Length != 32)
                    throw new ArgumentException("Remote static public key required for initiator");
                
                state.RemoteStaticPublicKey = remoteStaticPublicKey;
                
                // <- s (MixHash of Bob's static key)
                state.MixHash(remoteStaticPublicKey);
            }
            else
            {
                // <- s (MixHash of own static key)
                state.MixHash(localStaticPublicKey);
            }
        }

        /// <summary>
        /// Create New Session message (initiator only)
        /// -> e, es, s, ss, payload
        /// 
        /// Returns: encodedEphemeralKey (32) || encryptedStaticKey (32+16) || encryptedPayload (len+16)
        /// Note: Ephemeral key is Elligator2 encoded for stealth
        /// </summary>
        public byte[] CreateNewSessionMessage(byte[] payload)
        {
            if (!isInitiator)
                throw new InvalidOperationException("Only initiator can create New Session message");

            if (payload == null)
                payload = Array.Empty<byte>();

            // -> e (with Elligator2 encoding)
            var encodedEphemeralKey = state.GenerateEphemeralKeyElligator2();

            // -> es (ephemeral-static DH with Bob's key)
            state.PerformES(isInitiator: true);

            // -> s (Alice's static key, encrypted)
            var encryptedStaticKey = state.SendStaticKey();

            // -> ss (static-static DH)
            state.PerformSS();

            // -> payload
            var encryptedPayload = state.EncryptPayload(payload);

            // Combine all parts
            var totalLength = encodedEphemeralKey.Length + encryptedStaticKey.Length + encryptedPayload.Length;
            var message = new byte[totalLength];
            var offset = 0;

            Array.Copy(encodedEphemeralKey, 0, message, offset, encodedEphemeralKey.Length);
            offset += encodedEphemeralKey.Length;

            Array.Copy(encryptedStaticKey, 0, message, offset, encryptedStaticKey.Length);
            offset += encryptedStaticKey.Length;

            Array.Copy(encryptedPayload, 0, message, offset, encryptedPayload.Length);

            return message;
        }

        /// <summary>
        /// Process New Session message (responder only)
        /// -> e, es, s, ss, payload
        /// 
        /// Input: encodedEphemeralKey (32) || encryptedStaticKey (48) || encryptedPayload
        /// Returns: (decrypted payload, Alice's static public key)
        /// </summary>
        public (byte[] payload, byte[] remoteStaticPublicKey) ProcessNewSessionMessage(byte[] message)
        {
            if (isInitiator)
                throw new InvalidOperationException("Only responder can process New Session message");

            if (message == null || message.Length < 32 + 48 + 16)
                throw new ArgumentException("Message too short");

            var offset = 0;

            // -> e (Elligator2 encoded)
            var encodedEphemeralKey = new byte[32];
            Array.Copy(message, offset, encodedEphemeralKey, 0, 32);
            offset += 32;
            state.ReceiveEphemeralKeyElligator2(encodedEphemeralKey);

            // -> es
            state.PerformES(isInitiator: false);

            // -> s (Alice's static key, encrypted)
            var encryptedStaticKeyLength = 48; // 32 + 16 (MAC)
            var encryptedStaticKey = new byte[encryptedStaticKeyLength];
            Array.Copy(message, offset, encryptedStaticKey, 0, encryptedStaticKeyLength);
            offset += encryptedStaticKeyLength;
            state.ReceiveStaticKey(encryptedStaticKey);

            // -> ss
            state.PerformSS();

            // -> payload
            var encryptedPayloadLength = message.Length - offset;
            var encryptedPayload = new byte[encryptedPayloadLength];
            Array.Copy(message, offset, encryptedPayload, 0, encryptedPayloadLength);
            var payload = state.DecryptPayload(encryptedPayload);

            return (payload, state.RemoteStaticPublicKey);
        }

        /// <summary>
        /// Create New Session Reply message (responder only)
        /// <- tag, e, ee, se, payload
        /// 
        /// Returns: replyTag (8) || ephemeralKey (32) || encryptedPayload (len+16)
        /// Note: Reply tag is for the ratchet session lookup
        /// </summary>
        public byte[] CreateNewSessionReplyMessage(byte[] replyTag, byte[] payload)
        {
            if (isInitiator)
                throw new InvalidOperationException("Only responder can create New Session Reply");

            if (replyTag == null || replyTag.Length != 8)
                throw new ArgumentException("Reply tag must be 8 bytes");

            if (payload == null)
                payload = Array.Empty<byte>();

            this.replyTag = replyTag;

            // <- e (no Elligator2 encoding for reply)
            state.GenerateEphemeralKey();
            var ephemeralKey = state.LocalEphemeralPublicKey;

            // <- ee (ephemeral-ephemeral DH)
            state.PerformEE();

            // <- se (static-ephemeral DH)
            state.PerformSE(isInitiator: false);

            // <- payload
            var encryptedPayload = state.EncryptPayload(payload);

            // Combine: replyTag || ephemeralKey || encryptedPayload
            var message = new byte[8 + 32 + encryptedPayload.Length];
            Array.Copy(replyTag, 0, message, 0, 8);
            Array.Copy(ephemeralKey, 0, message, 8, 32);
            Array.Copy(encryptedPayload, 0, message, 40, encryptedPayload.Length);

            return message;
        }

        /// <summary>
        /// Process New Session Reply message (initiator only)
        /// <- tag, e, ee, se, payload
        /// 
        /// Input: replyTag (8) || ephemeralKey (32) || encryptedPayload
        /// Returns: (decrypted payload, reply tag)
        /// </summary>
        public (byte[] payload, byte[] replyTag) ProcessNewSessionReplyMessage(byte[] message)
        {
            if (!isInitiator)
                throw new InvalidOperationException("Only initiator can process New Session Reply");

            if (message == null || message.Length < 8 + 32 + 16)
                throw new ArgumentException("Message too short");

            // Extract reply tag
            var replyTag = new byte[8];
            Array.Copy(message, 0, replyTag, 0, 8);

            // Extract ephemeral key
            var ephemeralKey = new byte[32];
            Array.Copy(message, 8, ephemeralKey, 0, 32);

            // Extract encrypted payload
            var encryptedPayload = new byte[message.Length - 40];
            Array.Copy(message, 40, encryptedPayload, 0, encryptedPayload.Length);

            // <- e
            state.ReceiveEphemeralKey(ephemeralKey);

            // <- ee
            state.PerformEE();

            // <- se
            state.PerformSE(isInitiator: true);

            // <- payload
            var payload = state.DecryptPayload(encryptedPayload);

            return (payload, replyTag);
        }

        /// <summary>
        /// Finalize handshake and derive transport keys for data phase
        /// Call after completing the handshake
        /// </summary>
        public (byte[] sendKey, byte[] receiveKey, byte[] ck) FinalizeHandshake()
        {
            var (key1, key2, ck, h) = state.FinalizeHandshake();
            
            // Initiator sends with key1, receives with key2
            // Responder sends with key2, receives with key1
            return isInitiator ? (key1, key2, ck) : (key2, key1, ck);
        }

        /// <summary>
        /// Get the handshake hash for additional operations
        /// </summary>
        public byte[] GetHandshakeHash()
        {
            return (byte[])state.Hash?.Clone();
        }

        /// <summary>
        /// Get the chaining key for ratcheting
        /// </summary>
        public byte[] GetChainingKey()
        {
            return (byte[])state.ChainingKey?.Clone();
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
            if (replyTag != null)
                Array.Clear(replyTag, 0, replyTag.Length);
        }
    }
}
