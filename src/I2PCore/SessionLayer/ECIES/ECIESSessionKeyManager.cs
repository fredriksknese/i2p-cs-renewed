using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES;

/// <summary>
///     ECIES Session Key Manager
///     Manages encryption sessions for destination-to-destination communication
///     Uses Noise IK pattern with Elligator2 encoding
///     Implements forward secrecy with ratcheting
///     This is the main SKM for ECIES-X25519-AEAD-Ratchet protocol
///     Different from ECIESRouterSKM which is for router-to-router messages
/// </summary>
public class ECIESSessionKeyManager
{
    // Configuration
    private const int MaxInboundSessions = 1000;
    private const int MaxOutboundSessions = 500;
    private const int SessionExpirationMinutes = 60;
    private const int TagExpirationMinutes = 30;

    // Handshake reply lookup (8 bytes tag -> remote destination hash)
    private readonly ConcurrentDictionary<SessionTag, I2PIdentHash> _handshakeTagToDestination;

    // Session storage
    private readonly ConcurrentDictionary<I2PIdentHash, ECIESInboundSession> _inboundSessions;
    private readonly I2PDestination _localDestination;
    private readonly byte[] _localStaticPrivateKey;
    private readonly byte[] _localStaticPublicKey;
    private readonly ConcurrentDictionary<I2PIdentHash, ECIESOutboundSession> _outboundSessions;

    // Tag lookup (16 bytes tag -> session)
    private readonly ConcurrentDictionary<SessionTag, I2PIdentHash> _tagToDestination;

    // Mapping from remote static key to confirmed IdentHash
    private readonly ConcurrentDictionary<I2PIdentHash, I2PIdentHash> _staticKeyToIdentHash = new();

    private I2PIdentHash GetRemoteHash(byte[] remoteStaticKey)
    {
        var tempHash = new I2PIdentHash(new I2PBufferCursor(remoteStaticKey));
        if (_staticKeyToIdentHash.TryGetValue(tempHash, out var confirmedHash))
        {
            return confirmedHash;
        }

        var localDest = Router.FindLocalDestinationByStaticKey(remoteStaticKey);
        if (localDest != null)
        {
            return localDest.Destination.IdentHash;
        }

        using var sha = SHA256.Create();
        var hashBytes = sha.ComputeHash(remoteStaticKey);
        return new I2PIdentHash(new I2PBufferCursor(hashBytes));
    }

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
    ///     Get session counts
    /// </summary>
    public (int inbound, int outbound) SessionCounts =>
        (_inboundSessions.Count, _outboundSessions.Count);

    /// <summary>
    ///     Create a new outbound session and generate New Session message
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
    ///     Process incoming New Session message and create reply
    /// </summary>
    public (byte[] payload, byte[] reply) ProcessNewSession(
        byte[] messageData,
        byte[] replyPayload)
    {
        if (messageData == null)
            throw new ArgumentNullException(nameof(messageData));

        // Try hybrid variants first if length matches
        var variants = new List<NoiseIKhfs.KEMVariant>();
        if (messageData.Length >= 1680) variants.Add(NoiseIKhfs.KEMVariant.MLKEM1024);
        if (messageData.Length >= 1296) variants.Add(NoiseIKhfs.KEMVariant.MLKEM768);
        if (messageData.Length >= 912) variants.Add(NoiseIKhfs.KEMVariant.MLKEM512);

        foreach (var variant in variants)
        {
            try
            {
                var hybridMsg = ECIESHybridNewSessionMessage.Parse(messageData, variant);
                var (payload, remoteStaticKey, remoteKemPublicKey) = hybridMsg.Decrypt(
                    _localStaticPrivateKey, _localStaticPublicKey, variant);

                var remoteHash = GetRemoteHash(remoteStaticKey);

                var session = _inboundSessions.GetOrAdd(remoteHash, _ =>
                {
                    return new ECIESInboundSession(
                        _localDestination,
                        remoteStaticKey,
                        _localStaticPrivateKey,
                        _localStaticPublicKey,
                        variant);
                });

                var reply = session.CreateNewSessionReply(messageData, replyPayload, out _, out var sendK, out var ck);
                foreach (var tag in session.InboundTags) _tagToDestination.TryAdd(tag, remoteHash);
                EstablishOutboundSession(remoteHash, sendK, ck);

                return (payload, reply);
            }
            catch { /* Try next variant or fallback */ }
        }

        // Fallback to standard X25519
        try
        {
            var newSessionMsg = ECIESNewSessionMessage.Parse(messageData);
            var (payload, remoteStaticKey) = newSessionMsg.Decrypt(_localStaticPrivateKey, _localStaticPublicKey);

            var remoteHash = GetRemoteHash(remoteStaticKey);

            var session = _inboundSessions.GetOrAdd(remoteHash, _ =>
            {
                return new ECIESInboundSession(
                    _localDestination,
                    remoteStaticKey,
                    _localStaticPrivateKey,
                    _localStaticPublicKey);
            });

            var reply = session.CreateNewSessionReply(messageData, replyPayload, out _, out var sendK, out var ck);
            foreach (var tag in session.InboundTags) _tagToDestination.TryAdd(tag, remoteHash);
            EstablishOutboundSession(remoteHash, sendK, ck);

            return (payload, reply);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"ProcessNewSession failed: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    ///     Process incoming New Session Reply
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
    ///     Create existing session message using a tag
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
    ///     Process incoming message (either new session or existing session)
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
                // Existing session message
                return ProcessExistingSessionMessage(remoteHash, message);
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

        // 3. Try as hybrid handshake reply (no tag)
        foreach (var sess in _outboundSessions.Values)
        {
            if (sess.IsHybridWaitingForReply)
            {
                try
                {
                    var payload = sess.ProcessNewSessionReply(message);
                    
                    // Register deterministic handshake tags for this session
                    foreach (var tag in sess.HandshakeTags) _tagToDestination[tag] = sess.RemoteHash;

                    return new ProcessedDestinationMessage
                    {
                        Success = true,
                        Payload = payload,
                        RemoteDestination = sess.RemoteHash,
                        IsNewSession = false,
                        IsHandshakeReply = true
                    };
                }
                catch { /* Not the right session or invalid reply */ }
            }
        }

        // 4. Try as new session message
        var newSessionResult = ProcessNewSessionMessage(message);
        if (newSessionResult.Success)
        {
            // Establish the session
            EstablishInboundSession(newSessionResult, message);
        }
        return newSessionResult;
    }

    private void EstablishInboundSession(ProcessedDestinationMessage result, byte[] messageData)
    {
        _inboundSessions.GetOrAdd(result.RemoteDestination, _ =>
        {
            return new ECIESInboundSession(
                _localDestination,
                result.RemoteStaticKey,
                _localStaticPrivateKey,
                _localStaticPublicKey,
                result.IsHybrid ? result.KEMVariant : (NoiseIKhfs.KEMVariant?)null);
        });
    }

    /// <summary>
    ///     Process handshake reply (Message B)
    /// </summary>
    private ProcessedDestinationMessage ProcessHandshakeReply(
        I2PIdentHash remoteHash,
        byte[] message)
    {
        if (!_outboundSessions.TryGetValue(remoteHash, out var session))
            return new ProcessedDestinationMessage { Success = false, Error = "Outbound session not found" };

        try
        {
            var payload = session.ProcessNewSessionReply(message, null);

            // Register deterministic handshake tags for this session
            foreach (var tag in session.HandshakeTags) _tagToDestination[tag] = remoteHash;

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
    ///     Process existing session message
    /// </summary>
    private ProcessedDestinationMessage ProcessExistingSessionMessage(
        I2PIdentHash remoteHash,
        byte[] message)
    {
        if (!_inboundSessions.TryGetValue(remoteHash, out var session))
            return new ProcessedDestinationMessage
            {
                Success = false,
                Error = "Session not found"
            };

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
    ///     Process new session message
    /// </summary>
    private ProcessedDestinationMessage ProcessNewSessionMessage(byte[] message)
    {
        // Try hybrid variants first if length matches
        var variants = new List<NoiseIKhfs.KEMVariant>();
        if (message.Length >= 1680) variants.Add(NoiseIKhfs.KEMVariant.MLKEM1024);
        if (message.Length >= 1296) variants.Add(NoiseIKhfs.KEMVariant.MLKEM768);
        if (message.Length >= 912) variants.Add(NoiseIKhfs.KEMVariant.MLKEM512);

        foreach (var variant in variants)
        {
            try
            {
                var hybridMsg = ECIESHybridNewSessionMessage.Parse(message, variant);
                var (payload, remoteStaticKey, remoteKemPublicKey) = hybridMsg.Decrypt(
                    _localStaticPrivateKey, _localStaticPublicKey, variant);

                var remoteHash = GetRemoteHash(remoteStaticKey);

                return new ProcessedDestinationMessage
                {
                    Success = true,
                    Payload = payload,
                    RemoteDestination = remoteHash,
                    RemoteStaticKey = remoteStaticKey,
                    IsNewSession = true,
                    RequiresReply = true,
                    IsHybrid = true,
                    KEMVariant = variant
                };
            }
            catch { /* Try next variant or fallback */ }
        }

        // Fallback to standard X25519
        try
        {
            var newSessionMsg = ECIESNewSessionMessage.Parse(message);
            var (payload, remoteStaticKey) = newSessionMsg.Decrypt(_localStaticPrivateKey, _localStaticPublicKey);

            var remoteHash = GetRemoteHash(remoteStaticKey);

            return new ProcessedDestinationMessage
            {
                Success = true,
                Payload = payload,
                RemoteDestination = remoteHash,
                RemoteStaticKey = remoteStaticKey,
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
    ///     Confirm the real remote IdentHash for a session that was initially
    ///     identified by a placeholder hash (SHA256 of the static key).
    /// </summary>
    public void ConfirmRemoteHash(I2PIdentHash temporaryHash, I2PIdentHash realHash)
    {
        if (temporaryHash == null || realHash == null || temporaryHash == realHash) return;

        if (_inboundSessions.TryRemove(temporaryHash, out var session))
        {
            _inboundSessions[realHash] = session;

            // Move tags
            foreach (var kvp in _tagToDestination.ToArray())
                if (kvp.Value == temporaryHash)
                    _tagToDestination[kvp.Key] = realHash;

            // Record static key mapping
            if (session.RemoteStaticKey != null)
                _staticKeyToIdentHash[new I2PIdentHash(new I2PBufferCursor(session.RemoteStaticKey))] = realHash;

            Logging.LogDebug(
                $"ECIESSessionKeyManager: Confirmed remote hash: {temporaryHash.Id32Short} -> {realHash.Id32Short}");
        }

        if (_outboundSessions.TryRemove(temporaryHash, out var outSession))
        {
            _outboundSessions.TryAdd(realHash, outSession);
        }
    }

    /// <summary>
    ///     Register a session tag for inbound messages
    /// </summary>
    public void RegisterTag(SessionTag tag, I2PIdentHash destination)
    {
        _tagToDestination.TryAdd(tag, destination);
    }

    /// <summary>
    ///     Unregister a used session tag
    /// </summary>
    public void UnregisterTag(SessionTag tag)
    {
        _tagToDestination.TryRemove(tag, out _);
    }

    /// <summary>
    ///     Clean up expired sessions and tags
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
            if (_inboundSessions.TryRemove(hash, out var session))
                session.Cleanup();

        // Clean up outbound sessions
        var expiredOutbound = _outboundSessions
            .Where(kvp => (now - kvp.Value.LastUsed).TotalMinutes > SessionExpirationMinutes)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var hash in expiredOutbound)
            if (_outboundSessions.TryRemove(hash, out var session))
                session.Cleanup();
    }

    /// <summary>
    ///     Check if outbound session exists
    /// </summary>
    public bool HasOutboundSession(I2PIdentHash destination)
    {
        return _outboundSessions.ContainsKey(destination);
    }

    /// <summary>
    ///     Check if outbound session has available tags
    /// </summary>
    public bool HasAvailableOutboundTags(I2PIdentHash destination)
    {
        if (_outboundSessions.TryGetValue(destination, out var session)) return session.HasAvailableTags;
        return false;
    }

    /// <summary>
    ///     Create a handshake reply for a pending session
    /// </summary>
    public byte[] CreateHandshakeReply(I2PIdentHash remoteHash, byte[] newSessionData, byte[] replyPayload = null)
    {
        if (!_inboundSessions.TryGetValue(remoteHash, out var session))
            throw new InvalidOperationException($"No inbound session for {remoteHash.Id32Short}");

        var reply = session.CreateNewSessionReply(newSessionData, replyPayload, out _, out var sendK, out var ck);
        
        // Register tags derived during reply generation
        foreach (var tag in session.InboundTags) _tagToDestination.TryAdd(tag, remoteHash);
        
        // Bob (responder) also establishes an outbound session to send back to Alice
        EstablishOutboundSession(remoteHash, sendK, ck);

        return reply;
    }

    private void EstablishOutboundSession(I2PIdentHash remoteHash, byte[] sendK, byte[] ck)
    {
        var session = new ECIESOutboundSession(_localDestination, remoteHash, sendK, ck);
        _outboundSessions[remoteHash] = session;
    }

    /// <summary>
    ///     Check if we have an inbound session for this destination
    /// </summary>
    public bool HasInboundSession(I2PIdentHash destination)
    {
        return _inboundSessions.ContainsKey(destination);
    }

    public bool IsOutboundHandshakeInProgress(I2PIdentHash destination)
    {
        if (destination == null) return false;
        return _outboundSessions.TryGetValue(destination, out var session) && !session.IsEstablished;
    }
}

/// <summary>
///     Result of processing a destination message
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
    public byte[] RemoteStaticKey { get; set; }
    public byte[] ReplyData { get; set; }
    public string Error { get; set; }
}