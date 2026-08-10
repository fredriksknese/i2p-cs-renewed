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
    private readonly ConcurrentDictionary<I2PIdentHash, ECIESSession> _sessions;
    private readonly I2PDestination _localDestination;
    private readonly byte[] _localStaticPrivateKey;
    private readonly byte[] _localStaticPublicKey;

    /// <summary>Exposed for diagnostics only.</summary>
    internal byte[] LocalStaticPublicKey => _localStaticPublicKey;

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

        _sessions = new ConcurrentDictionary<I2PIdentHash, ECIESSession>();
        _tagToDestination = new ConcurrentDictionary<SessionTag, I2PIdentHash>();
        _handshakeTagToDestination = new ConcurrentDictionary<SessionTag, I2PIdentHash>();
    }

    /// <summary>
    ///     Get session counts
    /// </summary>
    public (int inbound, int outbound) SessionCounts =>
        (_sessions.Count(s => s.Value.IsEstablished), _sessions.Count(s => !s.Value.IsEstablished));

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

        // Create or get session
        var session = _sessions.GetOrAdd(remoteHash, _ =>
        {
            return new ECIESSession(
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

                var session = _sessions.GetOrAdd(remoteHash, _ =>
                {
                    return new ECIESSession(
                        _localDestination,
                        remoteStaticKey,
                        _localStaticPrivateKey,
                        _localStaticPublicKey,
                        variant);
                });

                Logging.LogDebug($"ECIESSessionKeyManager.ProcessNewSession: Handled hybrid variant {variant} for {remoteHash.Id32Short}");

                var reply = session.CreateNewSessionReply(messageData, replyPayload, out _, out _);
                TrackInboundTags(session, remoteHash);

                return (payload, reply);
            }
            catch (Exception ex)
            {
                // Expected: this loop trials every ML-KEM variant against one message, so all but
                // at most one must fail. Debug for that reason, but with the full exception —
                // "variant 3 failed" without a cause is what makes a PQ handshake bug (batch 9-3)
                // indistinguishable from a message that was simply not hybrid.
                Logging.LogDebug(
                    $"ECIESSessionKeyManager.ProcessNewSession: hybrid variant {variant} failed: {ex}");
            }
        }

        Logging.LogDebug($"ECIESSessionKeyManager.ProcessNewSession: Falling back to standard IK (len={messageData.Length})");

        // Fallback to standard X25519
        try
        {
            var newSessionMsg = ECIESNewSessionMessage.Parse(messageData);
            var (payload, remoteStaticKey) = newSessionMsg.Decrypt(_localStaticPrivateKey, _localStaticPublicKey);

            var remoteHash = GetRemoteHash(remoteStaticKey);

            var session = _sessions.GetOrAdd(remoteHash, _ =>
            {
                return new ECIESSession(
                    _localDestination,
                    remoteStaticKey,
                    _localStaticPrivateKey,
                    _localStaticPublicKey);
            });

            Logging.LogDebug($"ECIESSessionKeyManager.ProcessNewSession: Handled standard IK for {remoteHash.Id32Short}");

            var reply = session.CreateNewSessionReply(messageData, replyPayload, out _, out _);
            TrackInboundTags(session, remoteHash);

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
        byte[] replyData)
    {
        if (remoteDestination == null)
            throw new ArgumentNullException(nameof(remoteDestination));

        if (replyData == null)
            throw new ArgumentNullException(nameof(replyData));

        if (!_sessions.TryGetValue(remoteDestination, out var session))
            throw new InvalidOperationException($"No session for {remoteDestination.Id32Short}");

        return session.ProcessNewSessionReply(replyData);
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

        if (!_sessions.TryGetValue(remoteDestination, out var session))
            throw new InvalidOperationException($"No session for {remoteDestination.Id32Short}");

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
        var hybridWaiting = 0;
        foreach (var sess in _sessions.Values)
        {
            if (sess.IsHybridWaitingForReply)
            {
                hybridWaiting++;
                try
                {
                    var payload = sess.ProcessNewSessionReply(message);

                    // Register deterministic handshake tags for this session
                    TrackInboundTags(sess, sess.RemoteHash);

                    Logging.LogDebug($"ECIESSessionKeyManager: Step 3 matched hybrid reply for {sess.RemoteHash?.Id32Short}");
                    return new ProcessedDestinationMessage
                    {
                        Success = true,
                        Payload = payload,
                        RemoteDestination = sess.RemoteHash,
                        IsNewSession = false,
                        IsHandshakeReply = true
                    };
                }
                catch (Exception ex)
                {
                    // Expected: this is a trial loop over every pending hybrid session, and all
                    // but at most one of them must fail. Debug rather than Warning for that
                    // reason — at Warning a single reply would log once per pending session.
                    // The exception is still carried, because "none matched" with no record of
                    // *how* each one failed is the blindfolded case this audit exists to remove.
                    Logging.LogDebug(
                        $"ECIESSessionKeyManager: Step 3 hybrid session "
                        + $"{sess.RemoteHash?.Id32Short} did not match this reply: {ex}");
                }
            }
        }

        if (message.Length > 500)
            Logging.LogDebug($"ECIESSessionKeyManager.ProcessMessage: Step 3 tried {hybridWaiting} hybrid sessions, none matched (len={message.Length}). Trying step 4 (NewSession).");

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
        _sessions.GetOrAdd(result.RemoteDestination, _ =>
        {
            return new ECIESSession(
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
        if (!_sessions.TryGetValue(remoteHash, out var session))
            return new ProcessedDestinationMessage { Success = false, Error = "Session not found" };

        try
        {
            var payload = session.ProcessNewSessionReply(message);

            // Register deterministic handshake tags for this session
            TrackInboundTags(session, remoteHash);

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
            // Propagated rather than logged at Warning here: SessionManager.DecryptMessage logs
            // Error for the caller and this is a trial path it recovers from. The exception type
            // travels with the message because the string is all the caller ever sees.
            return new ProcessedDestinationMessage
            {
                Success = false,
                Error = $"HandshakeReply:{ex.GetType().Name}:{ex.Message}"
            };
        }
    }

    /// <summary>
    ///     Process existing session message
    /// </summary>
    private ProcessedDestinationMessage ProcessExistingSessionMessage(
        I2PIdentHash remoteHash,
        byte[] message)
    {
        if (!_sessions.TryGetValue(remoteHash, out var session))
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
            // As above: SessionManager.DecryptMessage is the logging consumer of Error, and a
            // failure here is recoverable (it falls through to the NewSession path). Carrying
            // the type distinguishes "wrong session" from "malformed message", which is the
            // distinction batch 5-3's tag-window work will need.
            return new ProcessedDestinationMessage
            {
                Success = false,
                Error = $"ExistingSession:{ex.GetType().Name}:{ex.Message}"
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

        var errors = new List<string>();

        foreach (var variant in variants)
        {
            try
            {
                var hybridMsg = ECIESHybridNewSessionMessage.Parse(message, variant);

                // Diagnostic: test Elligator2 decode of the ephemeral key. Batch 5-2 — this ran at
                // Information on every inbound session, and the decode itself is real work done
                // solely to print it, so the guard covers the computation and not just the write.
                if (Logging.IsEnabled(Logging.LogLevels.Debug))
                {
                    var ephDecoded = Crypto.Elligator2.Decode(hybridMsg.EphemeralPublicKey);
                    var ephFp = ephDecoded != null ? BitConverter.ToString(ephDecoded, 0, Math.Min(8, ephDecoded.Length)) : "NULL";
                    var ephEncFp = BitConverter.ToString(hybridMsg.EphemeralPublicKey, 0, 8);
                    Logging.LogDebug($"ProcessNewSessionMessage: {variant} ephemeral encoded=[{ephEncFp}] decoded=[{ephFp}] decodedLen={ephDecoded?.Length ?? -1}");
                }

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
            catch (Exception ex)
            {
                // No log: this is a trial over every variant, and the accumulated `errors` list
                // is returned to the caller as a single joined string below, which
                // SessionManager.DecryptMessage logs. Recording the exception *type* per variant
                // is what makes that string diagnostic rather than a wall of "Bad Data".
                errors.Add($"{variant}:{ex.GetType().Name}:{ex.Message}");
            }
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
            // Terminal: every variant and the classical IK path have now failed, and this is the
            // one return that carries the whole trial history out to the caller.
            errors.Add($"IK:{ex.GetType().Name}:{ex.Message}");
            return new ProcessedDestinationMessage
            {
                Success = false,
                Error = $"All variants failed: [{string.Join(" | ", errors)}]"
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

        if (_sessions.TryRemove(temporaryHash, out var session))
        {
            _sessions[realHash] = session;
            session.RemoteHash = realHash;

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
    }

    /// <summary>
    ///     Seed the tag routing table from a session, and keep it seeded. Batch 5-3.
    ///
    ///     <para>
    ///         Five call sites used to copy <c>session.InboundTags</c> into
    ///         <c>_tagToDestination</c> once and never again, which was correct only while the
    ///         session's tags were a fixed block generated at handshake time. With a sliding
    ///         window that snapshot routes the first 5000 messages and drops everything after —
    ///         and it fails as an unrecognised tag, so it looks like a crypto fault rather than a
    ///         bookkeeping one. That is how it presented while 5-3 was being written.
    ///     </para>
    ///     <para>
    ///         The hash is resolved when a tag is added rather than captured here, because
    ///         <see cref="ConfirmRemoteHash" /> replaces a responder's temporary ident hash with
    ///         the real one part-way through a session's life.
    ///     </para>
    /// </summary>
    private void TrackInboundTags(ECIESSession session, I2PIdentHash remoteHash)
    {
        if (session == null) return;

        lock (_trackedSessions)
        {
            if (_trackedSessions.Add(session))
            {
                session.InboundTagAdded += tag =>
                    _tagToDestination[tag] = CurrentHashFor(session, remoteHash);
                session.InboundTagExpired += tag => _tagToDestination.TryRemove(tag, out _);
            }
        }

        foreach (var tag in session.InboundTags) _tagToDestination[tag] = remoteHash;
    }

    /// <summary>Sessions whose tag events are already wired, by reference.</summary>
    private readonly HashSet<ECIESSession> _trackedSessions = new();

    /// <summary>
    ///     The key <paramref name="session" /> is currently filed under in <c>_sessions</c>, which
    ///     is what a tag must route to. Batch 5-3.
    ///
    ///     <para>
    ///         It is not simply <c>session.RemoteHash</c>: a responder's session carries a
    ///         *temporary* hash derived straight from the remote static key, while the dictionary
    ///         is keyed by <see cref="GetRemoteHash" />, which may already know the real one.
    ///         Routing tags to the temporary hash makes them resolve to no session at all, which
    ///         surfaces as "Session not found" — a message that reads like a lost session rather
    ///         than a misfiled tag, and cost a debugging round to tell apart.
    ///     </para>
    ///     <para>
    ///         <see cref="ConfirmRemoteHash" /> re-keys the dictionary and updates
    ///         <c>RemoteHash</c> together, so once it has run the two agree and this returns the
    ///         real hash.
    ///     </para>
    /// </summary>
    private I2PIdentHash CurrentHashFor(ECIESSession session, I2PIdentHash fallback)
    {
        if (session.RemoteHash != null
            && _sessions.TryGetValue(session.RemoteHash, out var filed)
            && ReferenceEquals(filed, session))
            return session.RemoteHash;

        return fallback;
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

        // Clean up sessions
        var expired = _sessions
            .Where(kvp => (now - kvp.Value.LastUsed).TotalMinutes > SessionExpirationMinutes)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var hash in expired)
            if (_sessions.TryRemove(hash, out var session))
                session.Dispose();
    }

    /// <summary>
    ///     Check if outbound session exists
    /// </summary>
    public bool HasOutboundSession(I2PIdentHash destination)
    {
        return _sessions.ContainsKey(destination);
    }

    /// <summary>
    ///     Check if outbound session has available tags
    /// </summary>
    public bool HasAvailableOutboundTags(I2PIdentHash destination)
    {
        if (_sessions.TryGetValue(destination, out var session)) return session.HasAvailableOutboundTags;
        return false;
    }

    /// <summary>
    ///     Create a handshake reply for a pending session
    /// </summary>
    public byte[] CreateHandshakeReply(I2PIdentHash remoteHash, byte[] newSessionData, byte[] replyPayload = null)
    {
        if (!_sessions.TryGetValue(remoteHash, out var session))
            throw new InvalidOperationException($"No session for {remoteHash.Id32Short}");

        var reply = session.CreateNewSessionReply(newSessionData, replyPayload, out _, out _);
        
        // Register tags derived during reply generation
        TrackInboundTags(session, remoteHash);
        
        return reply;
    }

    /// <summary>
    ///     Check if we have an inbound session for this destination
    /// </summary>
    public bool HasInboundSession(I2PIdentHash destination)
    {
        return _sessions.TryGetValue(destination, out var s) && s.IsEstablished;
    }

    public bool IsOutboundHandshakeInProgress(I2PIdentHash destination)
    {
        if (destination == null) return false;
        return _sessions.TryGetValue(destination, out var session) && !session.IsEstablished;
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