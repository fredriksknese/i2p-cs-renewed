using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES
{
    /// <summary>
    /// ECIES Router Session Key Manager
    /// Manages encryption sessions with other ECIES routers
    ///
    /// Used for:
    /// - DatabaseLookup reply encryption
    /// - Router-to-router message encryption
    /// - NetDB operations
    ///
    /// Uses Noise N pattern (one-way, no authentication)
    /// Simpler than destination-to-destination ECIES which uses Noise IK
    /// </summary>
    public class ECIESRouterSKM
    {
        /// <summary>
        /// Session information for a router
        /// </summary>
        private class RouterSession
        {
            public I2PIdentHash RouterHash { get; set; }
            public byte[] RouterPublicKey { get; set; }

            // Outbound session tags (we send with these tags)
            public Queue<SessionTag> OutboundTags { get; set; }

            // Inbound session tags (we receive with these tags)
            public ConcurrentDictionary<SessionTag, TagInfo> InboundTags { get; set; }

            // Session keys
            public byte[] SendKey { get; set; }
            public byte[] ReceiveKey { get; set; }

            // Timestamps
            public DateTime Created { get; set; }
            public DateTime LastUsed { get; set; }

            public RouterSession()
            {
                OutboundTags = new Queue<SessionTag>();
                InboundTags = new ConcurrentDictionary<SessionTag, TagInfo>();
                Created = DateTime.UtcNow;
                LastUsed = DateTime.UtcNow;
            }
        }

        /// <summary>
        /// Information about a session tag
        /// </summary>
        private class TagInfo
        {
            public byte[] Key { get; set; }
            public DateTime Created { get; set; }
            public int UseCount { get; set; }
        }


        private readonly ConcurrentDictionary<I2PIdentHash, RouterSession> _sessions;
        private readonly ConcurrentDictionary<SessionTag, I2PIdentHash> _tagToRouter;
        private readonly ConcurrentDictionary<SessionTag, TagInfo> _oneTimeSessions = new ConcurrentDictionary<SessionTag, TagInfo>();
        private readonly byte[] _localStaticPrivateKey;
        private readonly byte[] _localStaticPublicKey;

        // Configuration - matching i2pd ECIESX25519AEADRatchetSession.h constants
        private const int MaxTagsPerSession = 8192;        // ECIESX25519_TAGSET_MAX_NUM_TAGS
        private const int MinTagsToSend = 24;              // ECIESX25519_MIN_NUM_GENERATED_TAGS
        private const int MaxTagsToGenerate = 800;         // ECIESX25519_MAX_NUM_GENERATED_TAGS
        private const int NsrNumGeneratedTags = 12;        // ECIESX25519_NSR_NUM_GENERATED_TAGS
        private const int SessionExpirationMinutes = 30;
        private const int TagExpirationMinutes = 15;
        private const int PreviousTagsetExpirationSeconds = 180; // ECIESX25519_PREVIOUS_TAGSET_EXPIRATION_TIMEOUT

        public ECIESRouterSKM(byte[] localStaticPrivateKey, byte[] localStaticPublicKey)
        {
            if (localStaticPrivateKey == null || localStaticPrivateKey.Length != 32)
                throw new ArgumentException("Static private key must be 32 bytes", nameof(localStaticPrivateKey));

            if (localStaticPublicKey == null || localStaticPublicKey.Length != 32)
                throw new ArgumentException("Static public key must be 32 bytes", nameof(localStaticPublicKey));

            _localStaticPrivateKey = localStaticPrivateKey;
            _localStaticPublicKey = localStaticPublicKey;
            _sessions = new ConcurrentDictionary<I2PIdentHash, RouterSession>();
            _tagToRouter = new ConcurrentDictionary<SessionTag, I2PIdentHash>();
        }

        public void RegisterOneTimeSession(SessionTag tag, byte[] key)
        {
            _oneTimeSessions[tag] = new TagInfo
            {
                Key = key,
                Created = DateTime.UtcNow,
                UseCount = 0
            };
            Logging.LogDebug($"ECIESRouterSKM: Registered one-time session for tag {tag}");
        }

        /// <summary>
        /// Create a new session message to a router
        /// Uses Noise N pattern
        /// </summary>
        public byte[] CreateNewSessionMessage(I2PIdentHash routerHash, byte[] routerPublicKey, byte[] payload)
        {
            if (routerHash == null)
                throw new ArgumentNullException(nameof(routerHash));

            if (routerPublicKey == null || routerPublicKey.Length != 32)
                throw new ArgumentException("Router public key must be 32 bytes", nameof(routerPublicKey));

            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            // Java-like: No session management for router-to-router ECIES (Noise N).
            // Every message is a New Session message. This avoids complex ratchet implementation for now
            // and ensures compatibility with Java routers which expect either a New Session (Noise N)
            // or a properly ratcheted Existing Session (which C# hasn't fully implemented yet).

            // Create Noise N initiator
            var noiseN = NoiseN.CreateInitiator(routerPublicKey);

            // Build payload using ECIES block format (Proposal 144)
            var blocks = new List<Block>
            {
                new DateTimeBlock { Timestamp = (uint)((DateTime.UtcNow - I2PDate.RefDate).TotalSeconds) },
                new GarlicCloveBlock { Data = payload }
            };

            // Calculate padding to make the total size a multiple of 16, with at least 16 bytes.
            // Current size: DateTimeBlock (7) + GarlicCloveBlock (3 + payload.Length) = 10 + payload.Length
            int currentSize = 10 + payload.Length;
            int padLen = 16 + ( 16 - ( ( currentSize + 3 ) % 16 ) ) % 16;
            blocks.Add( new PaddingBlock { Data = BufUtils.RandomBytes( padLen ) } );

            var messageData = ECIESBlockFormat.BuildBlocks(blocks);

            // Encrypt using Noise N
            var encryptedMessage = noiseN.CreateMessage(messageData);
            
            // Clean up
            noiseN.Dispose();

            return encryptedMessage;
        }

        /// <summary>
        /// Create an existing session message using a tag
        /// </summary>
        public byte[] CreateExistingSessionMessage(I2PIdentHash routerHash, byte[] payload)
        {
            // For now, always fall back to new session as we don't have ratchets
            throw new InvalidOperationException("Use CreateNewSessionMessage instead (ratchets not implemented)");
        }

        /// <summary>
        /// Process an incoming message (either new session or existing session)
        /// </summary>
        public (byte[] payload, I2PIdentHash routerHash) ProcessMessage(byte[] message)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            // Try to extract tag from message
            var tag = ExtractTag(message);

            if (tag != null)
            {
                if (_tagToRouter.TryGetValue(tag, out var routerHash))
                {
                    // Existing session
                    return ProcessExistingSessionMessage(routerHash, message);
                }

                if (_oneTimeSessions.TryRemove(tag, out var tagInfo))
                {
                    // Decrypt with one-time session key
                    // message is: Tag (16 bytes) || EncryptedPayload
                    var encryptedPayload = new byte[message.Length - SessionTag.Length];
                    Array.Copy(message, SessionTag.Length, encryptedPayload, 0, encryptedPayload.Length);

                    var decryptedPayload = DecryptWithSessionKey(tagInfo.Key, tag, encryptedPayload);
                    if (decryptedPayload == null)
                        throw new InvalidOperationException("Decryption failed for one-time session message");

                    Logging.LogDebug($"ECIESRouterSKM: One-time session matched and decrypted for tag {tag}");
                    return (decryptedPayload, null);
                }
            }

            // New session (Noise N)
            return ProcessNewSessionMessage(message);
        }

        /// <summary>
        /// Process a new session message (Noise N)
        /// </summary>
        private (byte[] payload, I2PIdentHash routerHash) ProcessNewSessionMessage(byte[] message)
        {
            // Create Noise N responder
            var noiseN = NoiseN.CreateResponder(_localStaticPrivateKey, _localStaticPublicKey);

            // Decrypt message
            var decryptedData = noiseN.ProcessMessage(message);

            // Extract tags and payload
            var (tags, payload, routerHash) = ExtractTagsAndPayload(decryptedData);

            // Clean up
            noiseN.Dispose();

            return (payload, routerHash);
        }

        /// <summary>
        /// Process an existing session message using a tag
        /// </summary>
        private (byte[] payload, I2PIdentHash routerHash) ProcessExistingSessionMessage(
            I2PIdentHash routerHash, byte[] message)
        {
            if (!_sessions.TryGetValue(routerHash, out var session))
                throw new InvalidOperationException($"No session found for router {routerHash.Id32Short}");

            // Extract tag
            var tag = ExtractTag(message);
            if (tag == null || !session.InboundTags.TryRemove(tag, out var tagInfo))
                throw new InvalidOperationException("Invalid or expired tag");

            // Remove from global tag lookup
            _tagToRouter.TryRemove(tag, out _);

            // message is: Tag (16 bytes) || EncryptedPayload
            var encryptedPayload = new byte[message.Length - SessionTag.Length];
            Array.Copy(message, SessionTag.Length, encryptedPayload, 0, encryptedPayload.Length);

            // Decrypt using session key (AD = tag)
            var payload = DecryptWithSessionKey(tagInfo.Key, tag, encryptedPayload);
            if (payload == null)
                throw new InvalidOperationException("Decryption failed for existing session message");

            session.LastUsed = DateTime.UtcNow;

            return (payload, routerHash);
        }

        /// <summary>
        /// Build message with tags and payload
        /// </summary>
        private byte[] BuildMessageWithTags(List<SessionTag> tags, byte[] payload)
        {
            var stream = new BufRefStream();

            // Write tag count
            stream.Write((byte)tags.Count);

            // Write tags
            foreach (var tag in tags)
            {
                stream.Write(tag.ToByteArray());
            }

            // Write payload
            stream.Write(payload);

            return stream.ToByteArray();
        }

        /// <summary>
        /// Extract tag from message (first 16 bytes)
        /// </summary>
        private SessionTag ExtractTag(byte[] message)
        {
            if (message == null || message.Length < SessionTag.Length)
                return null;

            var tagBytes = new byte[SessionTag.Length];
            Array.Copy(message, 0, tagBytes, 0, SessionTag.Length);
            return new SessionTag(tagBytes);
        }

        /// <summary>
        /// Extract tags and payload from decrypted new session message
        /// </summary>
        private (List<SessionTag> tags, byte[] payload, I2PIdentHash routerHash) ExtractTagsAndPayload(byte[] data)
        {
            var tags = new List<SessionTag>();
            byte[] payload = null;
            I2PIdentHash routerHash = null;

            try
            {
                // Decrypted data is in ECIES block format (Proposal 144)
                var blocks = ECIESBlockFormat.ParseBlocks(data);
                
                foreach (var block in blocks)
                {
                    if (block is GarlicCloveBlock cloveBlock)
                    {
                        // Payload is the data from the first GarlicCloveBlock
                        if (payload == null) payload = cloveBlock.Data;

                        // Try to extract router hash from garlic clove delivery instructions
                        if (cloveBlock.Data != null && cloveBlock.Data.Length > 0)
                        {
                            var flag = cloveBlock.Data[0];
                            var deliveryType = (flag >> 5) & 0x03;

                            if (deliveryType == 2 && cloveBlock.Data.Length >= 33)
                            {
                                var hashBytes = new byte[32];
                                Array.Copy(cloveBlock.Data, 1, hashBytes, 0, 32);
                                routerHash = new I2PIdentHash(new BufRef(hashBytes));
                            }
                            else if (deliveryType == 3 && cloveBlock.Data.Length >= 37)
                            {
                                var hashBytes = new byte[32];
                                Array.Copy(cloveBlock.Data, 1, hashBytes, 0, 32);
                                routerHash = new I2PIdentHash(new BufRef(hashBytes));
                            }
                        }
                    }
                    else if (block is NextKeyBlock nextKey)
                    {
                        // Handle next key for ratcheting (if implemented)
                        Logging.LogDebug($"ECIESRouterSKM: Received NextKey block (ignored for now)");
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"ECIESRouterSKM: Failed to parse blocks: {ex.Message}");
                // Fallback: use raw data as payload if parsing failed
                payload = data;
            }

            return (tags, payload, routerHash);
        }

        /// <summary>
        /// Encrypt using session key (ChaCha20-Poly1305)
        /// Per ECIES spec: nonce is 0 for tag-based existing session messages,
        /// AD is the session tag (first 16 bytes of the message)
        /// </summary>
        private byte[] EncryptWithSessionKey(byte[] key, SessionTag tag, byte[] plaintext)
        {
            // For existing session messages, nonce is always 0
            // The session tag serves as implicit nonce differentiation
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            return ChaCha20Poly1305.Encrypt(key, nonce, plaintext, tag.ToByteArray());
        }

        /// <summary>
        /// Decrypt using session key (ChaCha20-Poly1305)
        /// </summary>
        private byte[] DecryptWithSessionKey(byte[] key, SessionTag tag, byte[] ciphertext)
        {
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            return ChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tag.ToByteArray());
        }

        /// <summary>
        /// Clean up expired sessions and tags
        /// </summary>
        public void CleanupExpired()
        {
            var now = DateTime.UtcNow;
            var expiredSessions = new List<I2PIdentHash>();

            foreach (var kvp in _sessions)
            {
                var session = kvp.Value;

                // Remove expired sessions
                if ((now - session.LastUsed).TotalMinutes > SessionExpirationMinutes)
                {
                    expiredSessions.Add(kvp.Key);
                    continue;
                }

                // Remove expired inbound tags
                var expiredTags = session.InboundTags
                    .Where(t => (now - t.Value.Created).TotalMinutes > TagExpirationMinutes)
                    .Select(t => t.Key)
                    .ToList();

                foreach (var tag in expiredTags)
                {
                    session.InboundTags.TryRemove(tag, out _);
                    _tagToRouter.TryRemove(tag, out _);
                }
            }

            // Remove expired sessions
            foreach (var hash in expiredSessions)
            {
                if (_sessions.TryRemove(hash, out var session))
                {
                    // Remove all tags for this session
                    foreach (var tag in session.InboundTags.Keys)
                    {
                        _tagToRouter.TryRemove(tag, out _);
                    }
                }
            }
        }

        /// <summary>
        /// Get session count
        /// </summary>
        public int SessionCount => _sessions.Count;

        /// <summary>
        /// Check if session exists for router
        /// </summary>
        public bool HasSession(I2PIdentHash routerHash)
        {
            return _sessions.ContainsKey(routerHash);
        }

        /// <summary>
        /// Handle a NextKey block for ratchet key rotation.
        /// Router-level sessions use Noise N (one-way) so NextKey processing
        /// is limited. Full NextKey rotation applies to destination-level
        /// sessions using Noise IK with bidirectional ratcheting.
        /// </summary>
        public void HandleNextKey(NextKeyBlock nextKey)
        {
            if (nextKey == null) return;

            // Router-level sessions use Noise N (one-way) which doesn't support
            // bidirectional NextKey ratcheting. NextKey blocks are only meaningful
            // for destination-level sessions using Noise IK. Log and ignore.
            Logging.LogDebug($"ECIESRouterSKM: NextKey block received (ignored for Noise N): " +
                $"keyID={nextKey.KeyID}, reverse={nextKey.IsReverseKey}, " +
                $"keyPresent={nextKey.IsKeyPresent}, requestReverse={nextKey.IsRequestReverseKey}");
        }
    }
}
