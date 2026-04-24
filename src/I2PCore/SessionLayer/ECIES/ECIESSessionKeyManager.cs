using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;

namespace I2PCore.SessionLayer.ECIES
{
    /// <summary>
    /// ECIES Session Key Manager
    /// Manages encryption sessions for destination-to-destination communication
    ///
    /// Uses Noise IK pattern with Elligator2 encoding
    /// Implements forward secrecy with ratcheting
    ///
    /// This is the main SKM for ECIES-X25519-AEAD-Ratchet protocol
    /// Different from ECIESRouterSKM which is for router-to-router messages
    /// </summary>
    public class ECIESSessionKeyManager
    {
        private readonly I2PDestination _localDestination;
        private readonly byte[] _localStaticPrivateKey;
        private readonly byte[] _localStaticPublicKey;

        // Session storage
        private readonly ConcurrentDictionary<I2PIdentHash, ECIESInboundSession> _inboundSessions;
        private readonly ConcurrentDictionary<I2PIdentHash, ECIESOutboundSession> _outboundSessions;

        // Tag lookup (16 bytes tag -> session)
        private readonly ConcurrentDictionary<SessionTag, I2PIdentHash> _tagToDestination;

        // Handshake reply lookup (8 bytes tag -> remote destination hash)
        private readonly ConcurrentDictionary<SessionTag, I2PIdentHash> _handshakeTagToDestination;

        // Configuration
        private const int MaxInboundSessions = 1000;
        private const int MaxOutboundSessions = 500;
        private const int SessionExpirationMinutes = 60;
        private const int TagExpirationMinutes = 30;

        public ECIESSessionKeyManager(
            I2PDestination localDestination,
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey)
        {
            _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));

            if (localStaticPrivateKey == null || localStaticPrivateKey.Length != 32)
                throw new ArgumentException("Static private key must be 32 bytes", nameof(localStaticPrivateKey));

            if (localStaticPublicKey == null || localStaticPublicKey.Length != 32)
                throw new ArgumentException("Static public key must be 32 bytes", nameof(localStaticPublicKey));

            _localStaticPrivateKey = localStaticPrivateKey;
            _localStaticPublicKey = localStaticPublicKey;

            _inboundSessions = new ConcurrentDictionary<I2PIdentHash, ECIESInboundSession>();
            _outboundSessions = new ConcurrentDictionary<I2PIdentHash, ECIESOutboundSession>();
            _tagToDestination = new ConcurrentDictionary<SessionTag, I2PIdentHash>();
            _handshakeTagToDestination = new ConcurrentDictionary<SessionTag, I2PIdentHash>();
        }

        /// <summary>
        /// Create a new outbound session and generate New Session message
        /// </summary>
        public byte[] CreateNewSession(
            I2PIdentHash remoteHash,
            I2PPublicKey remotePublicKey,
            byte[] payload,
            NoiseIKhfs.KEMVariant? variant = null)
        {
            if (remoteHash == null)
                throw new ArgumentNullException(nameof(remoteHash));

            if (remotePublicKey == null)
                throw new ArgumentNullException(nameof(remotePublicKey));

            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            // Create or get outbound session
            var session = _outboundSessions.GetOrAdd(remoteHash, _ =>
            {
                return new ECIESOutboundSession(
                    _localDestination,
                    remoteHash,
                    remotePublicKey,
                    _localStaticPrivateKey,
                    _localStaticPublicKey,
                    variant);
            });

            // Create new session message
            var (message, expectedReplyTag) = session.CreateNewSessionMessage(payload);

            // Register expected handshake reply tag (8 bytes)
            var tagKey = new SessionTag(expectedReplyTag);
            _handshakeTagToDestination[tagKey] = remoteHash;

            return message;
        }

        /// <summary>
        /// Process incoming New Session message and create reply
        /// </summary>
        public (byte[] payload, byte[] reply) ProcessNewSession(
            byte[] messageData,
            byte[] replyPayload)
        {
            if (messageData == null)
                throw new ArgumentNullException(nameof(messageData));

            // Detect hybrid message by length
            NoiseIKhfs.KEMVariant? variant = null;
            if ( messageData.Length >= 1680 ) variant = NoiseIKhfs.KEMVariant.MLKEM1024;
            else if ( messageData.Length >= 1296 ) variant = NoiseIKhfs.KEMVariant.MLKEM768;
            else if ( messageData.Length >= 912 ) variant = NoiseIKhfs.KEMVariant.MLKEM512;

            if ( variant.HasValue )
            {
                var hybridMsg = ECIESHybridNewSessionMessage.Parse( messageData, variant.Value );
                var (payload, remoteStaticKey, remoteKemPublicKey) = hybridMsg.Decrypt(
                    _localStaticPrivateKey, _localStaticPublicKey, variant.Value );

                using var sha = SHA256.Create();
                var hashBytes = sha.ComputeHash( remoteStaticKey );
                var remoteHash = new I2PIdentHash( new BufRef( hashBytes ) );

                var session = _inboundSessions.GetOrAdd( remoteHash, _ =>
                {
                    return new ECIESInboundSession(
                        _localDestination,
                        remoteStaticKey,
                        _localStaticPrivateKey,
                        _localStaticPublicKey,
                        variant.Value );
                } );

                var reply = session.CreateNewSessionReply( messageData, replyPayload, out _ );
                foreach ( var tag in session.InboundTags ) _tagToDestination.TryAdd( tag, remoteHash );

                return (payload, reply);
            }
            else
            {
                var newSessionMsg = ECIESNewSessionMessage.Parse( messageData );
                var (payload, remoteStaticKey) = newSessionMsg.Decrypt( _localStaticPrivateKey, _localStaticPublicKey );

                using var sha = SHA256.Create();
                var hashBytes = sha.ComputeHash( remoteStaticKey );
                var remoteHash = new I2PIdentHash( new BufRef( hashBytes ) );

                var session = _inboundSessions.GetOrAdd( remoteHash, _ =>
                {
                    return new ECIESInboundSession(
                        _localDestination,
                        remoteStaticKey,
                        _localStaticPrivateKey,
                        _localStaticPublicKey );
                } );

                var reply = session.CreateNewSessionReply( messageData, replyPayload, out _ );
                foreach ( var tag in session.InboundTags ) _tagToDestination.TryAdd( tag, remoteHash );

                return (payload, reply);
            }
        }

        /// <summary>
        /// Process incoming New Session Reply
        /// </summary>
        public byte[] ProcessNewSessionReply(
            I2PIdentHash remoteDestination,
            byte[] replyData,
            List<SessionTag> tags = null)
        {
            if (remoteDestination == null)
                throw new ArgumentNullException(nameof(remoteDestination));

            if (replyData == null)
                throw new ArgumentNullException(nameof(replyData));

            if (!_outboundSessions.TryGetValue(remoteDestination, out var session))
                throw new InvalidOperationException($"No outbound session for {remoteDestination.Id32Short}");

            return session.ProcessNewSessionReply(replyData, tags);
        }

        /// <summary>
        /// Create existing session message using a tag
        /// </summary>
        public ECIESExistingSessionMessage CreateExistingSession(
            I2PIdentHash remoteDestination,
            byte[] payload)
        {
            if (remoteDestination == null)
                throw new ArgumentNullException(nameof(remoteDestination));

            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            if (!_outboundSessions.TryGetValue(remoteDestination, out var session))
                throw new InvalidOperationException($"No outbound session for {remoteDestination.Id32Short}");

            return session.CreateExistingSessionMessage(payload);
        }

        /// <summary>
        /// Process incoming message (either new session or existing session)
        /// </summary>
        public ProcessedDestinationMessage ProcessMessage(byte[] message)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            // 1. Try Existing Session (using 8-byte tag)
            if (message.Length >= 8)
            {
                var tagBytes = new byte[8];
                Array.Copy(message, 0, tagBytes, 0, 8);
                var tag = new SessionTag(tagBytes);

                if (_tagToDestination.TryGetValue(tag, out var remoteHash))
                {
                    // Existing session message
                    return ProcessExistingSessionMessage(remoteHash, message);
                }
            }

            // 2. Try Handshake Reply (using 8-byte tag)
            // Alice receiving Message B from Bob
            if (message.Length >= 8)
            {
                var tagKey = new SessionTag(message.AsSpan(0, 8).ToArray());
                if (_handshakeTagToDestination.TryGetValue(tagKey, out var remoteHash))
                {
                    _handshakeTagToDestination.TryRemove(tagKey, out _);
                    return ProcessHandshakeReply(remoteHash, message);
                }
            }

            // 3. Try as new session message
            return ProcessNewSessionMessage(message);
        }

        /// <summary>
        /// Process handshake reply (Message B)
        /// </summary>
        private ProcessedDestinationMessage ProcessHandshakeReply(
            I2PIdentHash remoteHash,
            byte[] message)
        {
            if (!_outboundSessions.TryGetValue(remoteHash, out var session))
            {
                return new ProcessedDestinationMessage { Success = false, Error = "Outbound session not found" };
            }

            try
            {
                var payload = session.ProcessNewSessionReply(message, null);

                // Register deterministic handshake tags for this session
                foreach (var tag in session.HandshakeTags)
                {
                    _tagToDestination[tag] = remoteHash;
                }

                return new ProcessedDestinationMessage
                {
                    Success = true,
                    Payload = payload,
                    RemoteDestination = remoteHash,
                    IsNewSession = false,
                    IsHandshakeReply = true
                };
            }
            catch (Exception ex)
            {
                return new ProcessedDestinationMessage { Success = false, Error = ex.Message };
            }
        }

        /// <summary>
        /// Process existing session message
        /// </summary>
        private ProcessedDestinationMessage ProcessExistingSessionMessage(
            I2PIdentHash remoteHash,
            byte[] message)
        {
            if (!_inboundSessions.TryGetValue(remoteHash, out var session))
            {
                return new ProcessedDestinationMessage
                {
                    Success = false,
                    Error = "Session not found"
                };
            }

            try
            {
                var existingMsg = ECIESExistingSessionMessage.Parse(message);
                var payload = session.ProcessExistingSessionMessage(existingMsg);

                return new ProcessedDestinationMessage
                {
                    Success = true,
                    Payload = payload,
                    RemoteDestination = remoteHash,
                    IsNewSession = false
                };
            }
            catch (Exception ex)
            {
                return new ProcessedDestinationMessage
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Process new session message
        /// </summary>
        private ProcessedDestinationMessage ProcessNewSessionMessage(byte[] message)
        {
            try
            {
                var newSessionMsg = ECIESNewSessionMessage.Parse(message);
                var (payload, remoteStaticKey) = newSessionMsg.Decrypt(_localStaticPrivateKey, _localStaticPublicKey);

                // Create hash from remote static key
                using var sha = SHA256.Create();
                var hashBytes = sha.ComputeHash(remoteStaticKey);
                var remoteHash = new I2PIdentHash(new BufRef(hashBytes));

                return new ProcessedDestinationMessage
                {
                    Success = true,
                    Payload = payload,
                    RemoteDestination = remoteHash,
                    IsNewSession = true,
                    RequiresReply = true
                };
            }
            catch (Exception ex)
            {
                return new ProcessedDestinationMessage
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Register a session tag for inbound messages
        /// </summary>
        public void RegisterTag(SessionTag tag, I2PIdentHash destination)
        {
            _tagToDestination.TryAdd(tag, destination);
        }

        /// <summary>
        /// Unregister a used session tag
        /// </summary>
        public void UnregisterTag(SessionTag tag)
        {
            _tagToDestination.TryRemove(tag, out _);
        }

        /// <summary>
        /// Clean up expired sessions and tags
        /// </summary>
        public void CleanupExpired()
        {
            var now = DateTime.UtcNow;

            // Clean up inbound sessions
            var expiredInbound = _inboundSessions
                .Where(kvp => (now - kvp.Value.LastUsed).TotalMinutes > SessionExpirationMinutes)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var hash in expiredInbound)
            {
                if (_inboundSessions.TryRemove(hash, out var session))
                {
                    session.Cleanup();
                }
            }

            // Clean up outbound sessions
            var expiredOutbound = _outboundSessions
                .Where(kvp => (now - kvp.Value.LastUsed).TotalMinutes > SessionExpirationMinutes)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var hash in expiredOutbound)
            {
                if (_outboundSessions.TryRemove(hash, out var session))
                {
                    session.Cleanup();
                }
            }
        }

        /// <summary>
        /// Get session counts
        /// </summary>
        public (int inbound, int outbound) SessionCounts =>
            (_inboundSessions.Count, _outboundSessions.Count);

        /// <summary>
        /// Check if outbound session exists
        /// </summary>
        public bool HasOutboundSession(I2PIdentHash destination) =>
            _outboundSessions.ContainsKey(destination);

        /// <summary>
        /// Check if outbound session has available tags
        /// </summary>
        public bool HasAvailableOutboundTags(I2PIdentHash destination)
        {
            if (_outboundSessions.TryGetValue(destination, out var session))
            {
                return session.HasAvailableTags;
            }
            return false;
        }

        /// <summary>
        /// Check if inbound session exists
        /// </summary>
        public bool HasInboundSession(I2PIdentHash destination) =>
            _inboundSessions.ContainsKey(destination);
    }

    /// <summary>
    /// Result of processing a destination message
    /// </summary>
    public class ProcessedDestinationMessage
    {
        public bool Success { get; set; }
        public byte[] Payload { get; set; }
        public I2PIdentHash RemoteDestination { get; set; }
        public bool IsNewSession { get; set; }
        public bool IsHandshakeReply { get; set; }
        public bool RequiresReply { get; set; }
        public bool IsHybrid { get; set; }
        public NoiseIKhfs.KEMVariant KEMVariant { get; set; }
        public string Error { get; set; }
    }

}
