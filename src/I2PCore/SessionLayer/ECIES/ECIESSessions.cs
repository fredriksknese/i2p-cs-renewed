using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using HKDF = I2PCore.Crypto.HKDF;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES;

// Batch 5-1 (docs/PRODUCTION-PLAN.md) — the decision, recorded where the code used to be.
//
// Deleted: `ECIESRatchet`, which lived at the bottom of this file. It was constructed once at the
// end of session establishment and never read again — no caller ever invoked RatchetForward,
// GetSendKey or GetReceiveKey — and its derivation, HKDF(key, counter, "ratchet"), is not the I2P
// ECIES ratchet. Keeping a non-spec ratchet that nothing drives is worse than having none: it
// reads as forward secrecy that is not there.
//
// Also deleted in this batch: `ECIESGarlicProcessor` and `NTCP2AckManager`, both entirely
// unreferenced.
//
// **Kept: `RatchetTagSet.NextKeyHandler`.** It models i2pd's HandleNextKey and is the DH-ratchet
// mechanism batch 5-4 implements. It is unused today for the same reason the above was — that is
// precisely why the distinction had to be written down rather than left to the next reader's
// judgement.

/// <summary>
///     ECIES deterministic tag set generation (Proposal 144)
/// </summary>
internal class ECIESTagSet
{
    private const string INFO_0 = "SessionReplyTags";
    private const string INFO_1 = "KDFDHRatchetStep";
    private const string INFO_2 = "TagAndKeyGenKeys";
    private const string INFO_3 = "STInitialization";
    private const string INFO_4 = "SessionTagKeyGen";
    private const string INFO_5 = "SymmetricRatchet";
    private static readonly byte[] ZEROLEN = Array.Empty<byte>();
    private readonly byte[] _sesstag_ck;
    private readonly byte[] _sesstag_constant;
    private readonly byte[] _symmkey_ck;

    public ECIESTagSet(byte[] ck, byte[] tk)
    {
        // KDFDHRatchetStep (INFO_1)
        var res1 = HKDF.DeriveKey(ck, tk, Encoding.ASCII.GetBytes(INFO_1), 64);
        var ck1 = new byte[32];
        Array.Copy(res1, 32, ck1, 0, 32);

        // TagAndKeyGenKeys (INFO_2)
        var res2 = HKDF.DeriveKey(ck1, ZEROLEN, Encoding.ASCII.GetBytes(INFO_2), 64);
        _sesstag_ck = new byte[32];
        Array.Copy(res2, 0, _sesstag_ck, 0, 32);
        _symmkey_ck = new byte[32];
        Array.Copy(res2, 32, _symmkey_ck, 0, 32);

        // STInitialization (INFO_3)
        var res3 = HKDF.DeriveKey(_sesstag_ck, ZEROLEN, Encoding.ASCII.GetBytes(INFO_3), 64);
        Array.Copy(res3, 0, _sesstag_ck, 0, 32);
        _sesstag_constant = new byte[32];
        Array.Copy(res3, 32, _sesstag_constant, 0, 32);
    }

    public (SessionTag tag, byte[] key) ConsumeNext()
    {
        // SessionTagKeyGen (INFO_4)
        var res4 = HKDF.DeriveKey(_sesstag_ck, _sesstag_constant, Encoding.ASCII.GetBytes(INFO_4), 64);
        Array.Copy(res4, 0, _sesstag_ck, 0, 32);
        var tagBytes = new byte[8];
        Array.Copy(res4, 32, tagBytes, 0, 8); // Per i2pd: return buf64toh (res + 32)

        // SymmetricRatchet (INFO_5)
        var res5 = HKDF.DeriveKey(_symmkey_ck, ZEROLEN, Encoding.ASCII.GetBytes(INFO_5), 64);
        Array.Copy(res5, 0, _symmkey_ck, 0, 32);
        var keyBytes = new byte[32];
        Array.Copy(res5, 32, keyBytes, 0, 32);

        return (new SessionTag(tagBytes), keyBytes);
    }
}

/// <summary>
///     ECIES Outbound Session
///     Manages encryption for messages we send to a remote destination
/// </summary>
/// <summary>
///     ECIES Session
///     Manages bi-directional encryption and tags for a destination
/// </summary>
public class ECIESSession
{
    private readonly Dictionary<SessionTag, TagInfo> _inboundTags = new();
    private readonly Queue<(SessionTag tag, TagInfo info)> _outboundTags = new();
    private readonly NoiseIKhfs.KEMVariant? _kemVariant;
    private readonly I2PDestination _localDestination;
    private readonly byte[] _localStaticPrivateKey;
    private readonly byte[] _localStaticPublicKey;
    private I2PIdentHash _remoteHash;
    private readonly I2PPublicKey _remotePublicKey;
    private readonly object _sessionLock = new();

    private NoiseIK _noiseIK;
    private NoiseIKhfs _noiseIKhfs;
    private byte[] _receiveKey;
    private byte[] _sendKey;
    private byte[] _ck;
    private byte[] _cachedHandshakeMessage;
    private byte[] _cachedHandshakeReplyTag;

    // Initiator constructor
    public ECIESSession(
        I2PDestination localDestination,
        I2PIdentHash remoteHash,
        I2PPublicKey remotePublicKey,
        byte[] localStaticPrivateKey,
        byte[] localStaticPublicKey,
        NoiseIKhfs.KEMVariant? kemVariant = null)
    {
        _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));
        _remoteHash = remoteHash ?? throw new ArgumentNullException(nameof(remoteHash));
        _remotePublicKey = remotePublicKey;
        _localStaticPrivateKey = localStaticPrivateKey;
        _localStaticPublicKey = localStaticPublicKey;
        _kemVariant = kemVariant;

        Created = DateTime.UtcNow;
        LastUsed = DateTime.UtcNow;
    }

    // Responder constructor
    public ECIESSession(
        I2PDestination localDestination,
        byte[] remoteStaticPublicKey,
        byte[] localStaticPrivateKey,
        byte[] localStaticPublicKey,
        NoiseIKhfs.KEMVariant? kemVariant = null)
    {
        _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));
        _localStaticPrivateKey = localStaticPrivateKey;
        _localStaticPublicKey = localStaticPublicKey;
        _kemVariant = kemVariant;

        // Remote static key is known from Message A
        RemoteStaticKey = remoteStaticPublicKey;

        // Use the literal key as the temporary IdentHash, matching GetRemoteHash logic
        _remoteHash = new I2PIdentHash(new I2PBufferCursor(remoteStaticPublicKey, 0));

        Created = DateTime.UtcNow;
        LastUsed = DateTime.UtcNow;
    }

    public DateTime Created { get; }
    public DateTime LastUsed { get; private set; }

    public I2PIdentHash RemoteHash
    {
        get => _remoteHash;
        set => _remoteHash = value;
    }

    public byte[] RemoteStaticKey { get; private set; }

    /// <summary>
    ///     Batch 5-3. Inbound tags are no longer a block generated once at handshake time, so a
    ///     key manager that snapshotted <see cref="InboundTags" /> would be able to route the
    ///     first 5000 messages and nothing after. These fire as the window slides.
    /// </summary>
    public event Action<SessionTag> InboundTagAdded;

    public event Action<SessionTag> InboundTagExpired;

    public bool IsEstablished => _sendKey != null;
    public bool IsHybridWaitingForReply => _kemVariant.HasValue && !IsEstablished;

    public IEnumerable<SessionTag> HandshakeTags
    {
        get
        {
            lock (_sessionLock)
            {
                return _outboundTags.Select(t => t.tag).ToList();
            }
        }
    }

    public IEnumerable<SessionTag> InboundTags
    {
        get
        {
            lock (_sessionLock)
            {
                return _inboundTags.Keys.ToList();
            }
        }
    }

    public bool HasAvailableOutboundTags
    {
        get
        {
            lock (_sessionLock)
            {
                return _outboundTags.Count > 0;
            }
        }
    }

    /// <summary>
    ///     Initiator: Create first message (Message A)
    /// </summary>
    public (byte[] message, byte[] expectedReplyTag) CreateNewSessionMessage(byte[] payload)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));

        lock (_sessionLock)
        {
            if (_cachedHandshakeMessage != null) return (_cachedHandshakeMessage, _cachedHandshakeReplyTag);
        }

        var remoteStaticKey = RemoteStaticKey ?? ExtractPublicKey(_remotePublicKey);
        RemoteStaticKey = remoteStaticKey;

        byte[] message;
        byte[] ck;

        if (_kemVariant.HasValue)
        {
            _noiseIKhfs = NoiseIKhfs.CreateInitiator(
                _localStaticPrivateKey,
                _localStaticPublicKey,
                remoteStaticKey,
                _kemVariant.Value);

            var (ephemeralPublic, encryptedKemPublicKey, encryptedStatic, encryptedPayload) =
                _noiseIKhfs.WriteMessageA(payload);

            // Diagnostic: the encoded ephemeral key against the actual X25519 key. Batch 5-2 —
            // this ran at Information, so every session establishment printed it by default. The
            // guard is not redundant with the level: both fingerprints are built before the call,
            // and an argument already evaluated is one no log handler can skip.
            if (Logging.IsEnabled(Logging.LogLevels.Debug))
            {
                var ephEncFp = BitConverter.ToString(ephemeralPublic, 0, 8);
                var ephRawFp = _noiseIKhfs.LocalEphemeralPublicKey != null
                    ? BitConverter.ToString(_noiseIKhfs.LocalEphemeralPublicKey, 0, 8) : "NULL";
                Logging.LogDebug($"CreateNewSessionMessage: {_kemVariant} ephemeral encoded=[{ephEncFp}] raw_x25519=[{ephRawFp}]");
            }

            var hybridMsg = new ECIESHybridNewSessionMessage
            {
                EphemeralPublicKey = ephemeralPublic,
                EncryptedKEMPublicKey = encryptedKemPublicKey,
                EncryptedStaticKey = encryptedStatic,
                EncryptedPayload = encryptedPayload
            };
            message = hybridMsg.ToByteArray();
            ck = _noiseIKhfs.GetChainingKey();
        }
        else
        {
            _noiseIK = NoiseIK.CreateInitiator(
                _localStaticPrivateKey,
                _localStaticPublicKey,
                remoteStaticKey);

            message = _noiseIK.CreateNewSessionMessage(payload);
            ck = _noiseIK.GetChainingKey();
        }

        // Derive expected 8-byte tag for Message B
        var tagsetKey = HKDF.DeriveKey(ck, Array.Empty<byte>(), Encoding.ASCII.GetBytes("SessionReplyTags"), 32);
        var handshakeTagSet = new ECIESTagSet(ck, tagsetKey);
        var (bTag, _) = handshakeTagSet.ConsumeNext();
        var expectedReplyTag = bTag.ToByteArray().AsSpan(0, 8).ToArray();

        lock (_sessionLock)
        {
            _cachedHandshakeMessage = message;
            _cachedHandshakeReplyTag = expectedReplyTag;
        }

        LastUsed = DateTime.UtcNow;
        return (message, expectedReplyTag);
    }

    /// <summary>
    ///     Initiator: Process Message B from Bob
    /// </summary>
    public byte[] ProcessNewSessionReply(byte[] replyData)
    {
        if (replyData == null) throw new ArgumentNullException(nameof(replyData));

        byte[] payload;
        byte[] sendK, receiveK, ck;

        if (_kemVariant.HasValue)
        {
            if (_noiseIKhfs == null) throw new InvalidOperationException("Handshake not initialized");

            var hybridReply = ECIESHybridNewSessionReplyMessage.Parse(replyData, _kemVariant.Value);
            payload = _noiseIKhfs.ReadMessageB(hybridReply.EphemeralPublicKey, hybridReply.EncryptedKEMCiphertext,
                hybridReply.EmptySectionMac, hybridReply.HandshakeMac, hybridReply.EncryptedPayload);

            (sendK, receiveK, ck) = _noiseIKhfs.FinalizeHandshake();
        }
        else
        {
            if (_noiseIK == null) throw new InvalidOperationException("Handshake not initialized");

            var (p, _) = _noiseIK.ProcessNewSessionReplyMessage(replyData);
            payload = p;

            (sendK, receiveK, ck) = _noiseIK.FinalizeHandshake();
        }

        _sendKey = sendK;
        _receiveKey = receiveK;
        _ck = ck;

        InitializeBiDirectionalTags();

        _noiseIK?.Dispose();
        _noiseIK = null;
        _noiseIKhfs?.Dispose();
        _noiseIKhfs = null;

        lock (_sessionLock)
        {
            _cachedHandshakeMessage = null;
            _cachedHandshakeReplyTag = null;
        }

        LastUsed = DateTime.UtcNow;
        return payload;
    }

    /// <summary>
    ///     Responder: Create Message B in response to Message A
    /// </summary>
    public byte[] CreateNewSessionReply(byte[] newSessionData, byte[] replyPayload, out byte[] sendK, out byte[] ck)
    {
        if (newSessionData == null) throw new ArgumentNullException(nameof(newSessionData));
        replyPayload ??= Array.Empty<byte>();

        byte[] message;

        if (_kemVariant.HasValue)
        {
            _noiseIKhfs = NoiseIKhfs.CreateResponder(_localStaticPrivateKey, _localStaticPublicKey, _kemVariant.Value);
            var hybridMsg = ECIESHybridNewSessionMessage.Parse(newSessionData, _kemVariant.Value);
            _noiseIKhfs.ReadMessageA(hybridMsg.EphemeralPublicKey, hybridMsg.EncryptedKEMPublicKey,
                hybridMsg.EncryptedStaticKey, hybridMsg.EncryptedPayload);

            var ckAfterA = _noiseIKhfs.GetChainingKey();
            var tagsetKey = HKDF.DeriveKey(ckAfterA, Array.Empty<byte>(), Encoding.ASCII.GetBytes("SessionReplyTags"), 32);
            var handshakeTagSet = new ECIESTagSet(ckAfterA, tagsetKey);
            var (bTag, _) = handshakeTagSet.ConsumeNext();

            var hybridReply = ECIESHybridNewSessionReplyMessage.Create(bTag.ToByteArray().AsSpan(0, 8).ToArray(),
                replyPayload, _noiseIKhfs);
            message = hybridReply.ToByteArray();

            var (resSendK, resReceiveK, resCk) = _noiseIKhfs.FinalizeHandshake();
            _sendKey = resSendK;
            _receiveKey = resReceiveK;
            _ck = resCk;
        }
        else
        {
            _noiseIK = NoiseIK.CreateResponder(_localStaticPrivateKey, _localStaticPublicKey);
            _noiseIK.ProcessNewSessionMessage(newSessionData);

            var ckAfterA = _noiseIK.GetChainingKey();
            var tagsetKey = HKDF.DeriveKey(ckAfterA, Array.Empty<byte>(), Encoding.ASCII.GetBytes("SessionReplyTags"), 32);
            var handshakeTagSet = new ECIESTagSet(ckAfterA, tagsetKey);
            var (bTag, _) = handshakeTagSet.ConsumeNext();

            message = _noiseIK.CreateNewSessionReplyMessage(bTag.ToByteArray().AsSpan(0, 8).ToArray(), replyPayload);

            var (resSendK, resReceiveK, resCk) = _noiseIK.FinalizeHandshake();
            _sendKey = resSendK;
            _receiveKey = resReceiveK;
            _ck = resCk;
        }

        InitializeBiDirectionalTags();

        _noiseIK?.Dispose();
        _noiseIK = null;
        _noiseIKhfs?.Dispose();
        _noiseIKhfs = null;

        sendK = _sendKey;
        ck = _ck;
        LastUsed = DateTime.UtcNow;
        return message;
    }

    /// <summary>
    ///     How many unused tags each direction keeps available. Batch 5-3 — this used to be the
    ///     total a session would ever have: <c>InitializeBiDirectionalTags</c> generated exactly
    ///     this many once and never another, so message 5001 threw "No available outbound tags"
    ///     and the destination went mute. At 1 KB a message that is about 5 MB, under half of
    ///     Gate 5's ">10 MB sustained without a session reset".
    /// </summary>
    private const int TagsPerDirection = 5000;

    /// <summary>
    ///     How far behind the newest inbound tag a straggler is still accepted. Tags are consumed
    ///     out of order whenever the network reorders or drops, so the unconsumed ones must not be
    ///     dropped the moment the window moves past them — the point of expiring behind is to
    ///     bound memory on a long session, not to enforce ordering.
    /// </summary>
    private const int InboundTagsKeptBehind = TagsPerDirection;

    // The generators, kept alive rather than drained. Both sides walk the same deterministic KDF
    // chain, so as long as each keeps consuming in order the indices stay aligned however long
    // the session lives.
    private ECIESTagSet _inboundTagSet;
    private ECIESTagSet _outboundTagSet;
    private int _nextInboundIndex;
    private int _nextOutboundIndex;

    private void InitializeBiDirectionalTags()
    {
        lock (_sessionLock)
        {
            _inboundTags.Clear();
            _outboundTags.Clear();

            // Inbound: derived from ck and our receive key (what we expect from remote).
            // Outbound: from ck and our send key.
            _inboundTagSet = new ECIESTagSet(_ck, _receiveKey);
            _outboundTagSet = new ECIESTagSet(_ck, _sendKey);
            _nextInboundIndex = 0;
            _nextOutboundIndex = 0;

            GenerateInboundTags(TagsPerDirection);
            GenerateOutboundTags(TagsPerDirection);
        }
    }

    /// <summary>Generate ahead. Callers hold <c>_sessionLock</c>.</summary>
    private void GenerateInboundTags(int count)
    {
        for (var i = 0; i < count; i++)
        {
            var (tag, key) = _inboundTagSet.ConsumeNext();
            _inboundTags[tag] = new TagInfo
            {
                Key = key, Index = _nextInboundIndex++, Created = DateTime.UtcNow
            };
            InboundTagAdded?.Invoke(tag);
        }

        // Expire behind, but only when the set has actually grown past its bound. In the normal
        // case one tag is consumed for every one generated, so the count is flat and this is a
        // single comparison — the sweep below is O(n) and must not run per message.
        if (_inboundTags.Count <= TagsPerDirection + InboundTagsKeptBehind) return;

        var cutoff = _nextInboundIndex - (TagsPerDirection + InboundTagsKeptBehind);
        foreach (var stale in _inboundTags.Where(kv => kv.Value.Index < cutoff)
                     .Select(kv => kv.Key).ToList())
        {
            _inboundTags.Remove(stale);
            InboundTagExpired?.Invoke(stale);
        }
    }

    /// <summary>Generate ahead. Callers hold <c>_sessionLock</c>.</summary>
    private void GenerateOutboundTags(int count)
    {
        for (var i = 0; i < count; i++)
        {
            var (tag, key) = _outboundTagSet.ConsumeNext();
            _outboundTags.Enqueue((tag, new TagInfo
            {
                Key = key, Index = _nextOutboundIndex++, Created = DateTime.UtcNow
            }));
        }
    }

    public byte[] ProcessExistingSessionMessage(ECIESExistingSessionMessage message)
    {
        if (message == null) throw new ArgumentNullException(nameof(message));

        TagInfo tagInfo;
        lock (_sessionLock)
        {
            if (!_inboundTags.TryGetValue(message.Tag, out tagInfo))
                throw new InvalidOperationException($"Unknown or expired tag: {message.Tag}");

            _inboundTags.Remove(message.Tag);

            // Batch 5-3: slide the window forward by exactly what was consumed, so the peer never
            // catches up with the end of what we have derived.
            GenerateInboundTags(1);

            LastUsed = DateTime.UtcNow;
        }

        return message.Decrypt(tagInfo.Key, tagInfo.Index);
    }

    public ECIESExistingSessionMessage CreateExistingSessionMessage(byte[] payload)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));

        SessionTag tag;
        TagInfo tagInfo;

        lock (_sessionLock)
        {
            if (_sendKey == null)
                throw new InvalidOperationException("Session not established");

            // Batch 5-3: an empty queue is no longer the end of the session. It used to throw
            // "No available outbound tags" on message 5001; the generator is still here, so the
            // window simply slides.
            if (_outboundTags.Count == 0) GenerateOutboundTags(TagsPerDirection);

            (tag, tagInfo) = _outboundTags.Dequeue();
            GenerateOutboundTags(1);

            LastUsed = DateTime.UtcNow;
        }

        return ECIESExistingSessionMessage.Create(tag, tagInfo.Key, payload, tagInfo.Index);
    }

    private byte[] ExtractPublicKey(I2PPublicKey pubKey)
    {
        if (pubKey == null) return null;
        var keyBytes = pubKey.ToByteArray();
        if (keyBytes.Length == 32) return keyBytes;
        var type = pubKey.Certificate.PublicKeyType;

        switch (type)
        {
            case I2PKeyType.KeyTypes.MLKEM512_X25519:
            case I2PKeyType.KeyTypes.MLKEM768_X25519:
            case I2PKeyType.KeyTypes.MLKEM1024_X25519:
                if (keyBytes.Length >= 32)
                {
                    var res = new byte[32];
                    Array.Copy(keyBytes, keyBytes.Length - 32, res, 0, 32);
                    return res;
                }
                break;
        }

        if (keyBytes.Length >= 32)
        {
            var res = new byte[32];
            Array.Copy(keyBytes, 0, res, 0, 32);
            return res;
        }

        throw new InvalidOperationException($"Unsupported key type for ECIES: {type}");
    }

    public void Dispose()
    {
        lock (_sessionLock)
        {
            _inboundTags.Clear();
            _outboundTags.Clear();
        }
        _noiseIK?.Dispose();
        _noiseIKhfs?.Dispose();
    }

    private class TagInfo
    {
        public byte[] Key { get; set; }
        public int Index { get; set; }
        public DateTime Created { get; set; }
    }
}
