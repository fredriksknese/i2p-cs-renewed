using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TransportLayer.Crypto;
using I2PCore.Crypto;

namespace I2PCore.SessionLayer.ECIES
{
    /// <summary>
    /// ECIES deterministic tag set generation (Proposal 144)
    /// </summary>
    internal class ECIESTagSet
    {
        private byte[] _sesstag_ck;
        private byte[] _sesstag_constant;
        private byte[] _symmkey_ck;
        private static readonly byte[] ZEROLEN = Array.Empty<byte>();

        private const string INFO_0 = "SessionReplyTags";
        private const string INFO_1 = "KDFDHRatchetStep";
        private const string INFO_2 = "TagAndKeyGenKeys";
        private const string INFO_3 = "STInitialization";
        private const string INFO_4 = "SessionTagKeyGen";
        private const string INFO_5 = "SymmetricRatchet";

        public ECIESTagSet(byte[] ck, byte[] tk)
        {
            // KDFDHRatchetStep (INFO_1)
            var res1 = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(ck, tk, System.Text.Encoding.ASCII.GetBytes(INFO_1), 64);
            var ck1 = new byte[32];
            Array.Copy(res1, 32, ck1, 0, 32);

            // TagAndKeyGenKeys (INFO_2)
            var res2 = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(ck1, ZEROLEN, System.Text.Encoding.ASCII.GetBytes(INFO_2), 64);
            _sesstag_ck = new byte[32];
            Array.Copy(res2, 0, _sesstag_ck, 0, 32);
            _symmkey_ck = new byte[32];
            Array.Copy(res2, 32, _symmkey_ck, 0, 32);

            // STInitialization (INFO_3)
            var res3 = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(_sesstag_ck, ZEROLEN, System.Text.Encoding.ASCII.GetBytes(INFO_3), 64);
            Array.Copy(res3, 0, _sesstag_ck, 0, 32);
            _sesstag_constant = new byte[32];
            Array.Copy(res3, 32, _sesstag_constant, 0, 32);
        }

        public (SessionTag tag, byte[] key) ConsumeNext()
        {
            // SessionTagKeyGen (INFO_4)
            var res4 = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(_sesstag_ck, _sesstag_constant, System.Text.Encoding.ASCII.GetBytes(INFO_4), 64);
            Array.Copy(res4, 0, _sesstag_ck, 0, 32);
            var tagBytes = new byte[8];
            Array.Copy(res4, 32, tagBytes, 0, 8); // Per i2pd: return buf64toh (res + 32)

            // SymmetricRatchet (INFO_5)
            var res5 = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(_symmkey_ck, ZEROLEN, System.Text.Encoding.ASCII.GetBytes(INFO_5), 64);
            Array.Copy(res5, 0, _symmkey_ck, 0, 32);
            var keyBytes = new byte[32];
            Array.Copy(res5, 32, keyBytes, 0, 32);

            return (new SessionTag(tagBytes), keyBytes);
        }
    }

    /// <summary>
    /// ECIES Outbound Session
    /// Manages encryption for messages we send to a remote destination
    /// </summary>
    public class ECIESOutboundSession
    {
        private readonly I2PDestination _localDestination;
        private readonly I2PIdentHash _remoteHash;
        private readonly I2PPublicKey _remotePublicKey;
        private readonly byte[] _localStaticPrivateKey;
        private readonly byte[] _localStaticPublicKey;
        private readonly NoiseIKhfs.KEMVariant? _kemVariant;

        private class TagInfo
        {
            public byte[] Key { get; set; }
            public int Index { get; set; }
        }

        // Session state
        private byte[] _sendKey;
        private byte[] _receiveKey;
        private readonly Queue<(SessionTag tag, TagInfo info)> _availableTags = new Queue<(SessionTag tag, TagInfo info)>();
        private readonly object _sessionLock = new object();
        private ECIESRatchet _ratchet;

        // Retain the Noise state across handshake messages
        private NoiseIK _noiseIK;
        private NoiseIKhfs _noiseIKhfs;

        public DateTime Created { get; }
        public DateTime LastUsed { get; private set; }

        public ECIESOutboundSession(
            I2PDestination localDestination,
            I2PIdentHash remoteHash,
            I2PPublicKey remotePublicKey,
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey,
            NoiseIKhfs.KEMVariant? kemVariant = null )
        {
            _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));
            _remoteHash = remoteHash ?? throw new ArgumentNullException(nameof(remoteHash));
            _remotePublicKey = remotePublicKey ?? throw new ArgumentNullException(nameof(remotePublicKey));
            _localStaticPrivateKey = localStaticPrivateKey;
            _localStaticPublicKey = localStaticPublicKey;
            _kemVariant = kemVariant;

            _availableTags = new Queue<(SessionTag tag, TagInfo info)>();
            Created = DateTime.UtcNow;
            LastUsed = DateTime.UtcNow;
        }

        /// <summary>
        /// Create a new session message (Noise IK or IKhfs pattern)
        /// </summary>
        public (byte[] message, byte[] expectedReplyTag) CreateNewSessionMessage(byte[] payload)
        {
            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            // Get remote static public key from I2PPublicKey
            var remoteStaticKey = ExtractPublicKey(_remotePublicKey);

            byte[] message;
            byte[] ck;

            if ( _kemVariant.HasValue )
            {
                _noiseIKhfs = NoiseIKhfs.CreateInitiator(
                    _localStaticPrivateKey,
                    _localStaticPublicKey,
                    remoteStaticKey,
                    _kemVariant.Value );

                var (ephemeralPublic, encryptedKemPublicKey, encryptedStatic, encryptedPayload) =
                    _noiseIKhfs.WriteMessageA( payload );

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
                // Create Noise IK initiator
                _noiseIK = NoiseIK.CreateInitiator(
                    _localStaticPrivateKey,
                    _localStaticPublicKey,
                    remoteStaticKey);

                // Create new session message: -> e, es, s, ss, payload
                message = _noiseIK.CreateNewSessionMessage(payload);
                ck = _noiseIK.GetChainingKey();
            }

            // Derive expected 8-byte tag for Message B
            var tagsetKey = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(ck, Array.Empty<byte>(), System.Text.Encoding.ASCII.GetBytes("SessionReplyTags"), 32);
            var handshakeTagSet = new ECIESTagSet(ck, tagsetKey);
            var (bTag, _) = handshakeTagSet.ConsumeNext();
            var expectedReplyTag = bTag.ToByteArray().AsSpan(0, 8).ToArray();

            LastUsed = DateTime.UtcNow;

            return (message, expectedReplyTag);
        }

        /// <summary>
        /// Process New Session Reply
        /// </summary>
        public byte[] ProcessNewSessionReply(byte[] replyData, List<SessionTag> tags)
        {
            if (replyData == null)
                throw new ArgumentNullException(nameof(replyData));

            byte[] payload;

            if ( _kemVariant.HasValue )
            {
                if ( _noiseIKhfs == null )
                    throw new InvalidOperationException( "Must create new session message first" );

                var hybridReply = ECIESHybridNewSessionReplyMessage.Parse( replyData, _kemVariant.Value );
                payload = _noiseIKhfs.ReadMessageB( hybridReply.EphemeralPublicKey, hybridReply.EncryptedKEMCiphertext, hybridReply.EmptySectionMac, hybridReply.EncryptedPayload );

                // Now finalize the handshake and derive transport keys
                var (sendK, receiveK, ck) = _noiseIKhfs.FinalizeHandshake();
                _sendKey = sendK;
                _receiveKey = receiveK;

                // Alice uses deterministic tags derived from handshake shared secret for ES messages
                lock (_sessionLock)
                {
                    // ES tags: rootKey = ck, data = sendKey
                    var tagSet = new ECIESTagSet(ck, _sendKey);
                    for (int i = 0; i < 50; i++)
                    {
                        var (tag, key) = tagSet.ConsumeNext();
                        _availableTags.Enqueue((tag, new TagInfo { Key = key, Index = i }));
                    }
                }
            }
            else
            {
                if (_noiseIK == null)
                    throw new InvalidOperationException("Must create new session message first");

                // Alice receiving Message B from Bob
                // Process the reply using the retained Noise IK state
                var (p, replyTag) = _noiseIK.ProcessNewSessionReplyMessage(replyData);
                payload = p;

                // Now finalize the handshake and derive transport keys
                var (sendK, receiveK, ck) = _noiseIK.FinalizeHandshake();
                _sendKey = sendK;
                _receiveKey = receiveK;

                // Alice uses deterministic tags derived from handshake shared secret for ES messages
                lock (_sessionLock)
                {
                    // ES tags: rootKey = ck, data = sendKey
                    var tagSet = new ECIESTagSet(ck, _sendKey);
                    for (int i = 0; i < 50; i++)
                    {
                        var (tag, key) = tagSet.ConsumeNext();
                        _availableTags.Enqueue((tag, new TagInfo { Key = key, Index = i }));
                    }
                }
            }

            // Initialize ratchet with derived keys
            _ratchet = new ECIESRatchet(_sendKey, _receiveKey);

            // Clear Noise state - no longer needed
            _noiseIK?.Dispose();
            _noiseIK = null;
            _noiseIKhfs?.Dispose();
            _noiseIKhfs = null;

            LastUsed = DateTime.UtcNow;

            return payload;
        }

        /// <summary>
        /// Create existing session message using a tag
        /// </summary>
        public ECIESExistingSessionMessage CreateExistingSessionMessage(byte[] payload)
        {
            if (payload == null)
                throw new ArgumentNullException(nameof(payload));

            SessionTag tag;
            TagInfo tagInfo;

            lock (_sessionLock)
            {
                if (_availableTags.Count == 0)
                    throw new InvalidOperationException("No available tags for existing session");

                if (_sendKey == null)
                    throw new InvalidOperationException("Session not established - handshake not complete");

                (tag, tagInfo) = _availableTags.Dequeue();

                // Ratchet forward after using tag
                _ratchet?.RatchetForward();

                LastUsed = DateTime.UtcNow;
            }

            // Create existing session message with nonce derived from tag index
            return ECIESExistingSessionMessage.Create(tag, tagInfo.Key, payload, tagInfo.Index);
        }

        /// <summary>
        /// Get currently available tags for this session
        /// </summary>
        public IEnumerable<SessionTag> HandshakeTags
        {
            get
            {
                lock (_sessionLock)
                {
                    return _availableTags.Select(t => t.tag).ToList();
                }
            }
        }

        /// <summary>
        /// Whether the session has available tags for sending
        /// </summary>
        public bool HasAvailableTags
        {
            get
            {
                lock (_sessionLock)
                {
                    return _availableTags.Count > 0;
                }
            }
        }

        /// <summary>
        /// Whether the handshake is complete and keys are available
        /// </summary>
        public bool IsEstablished => _sendKey != null;

        /// <summary>
        /// Extract X25519 public key from I2PPublicKey.
        /// For ECIES destinations, the public key is X25519 (32 bytes).
        /// For ElGamal destinations, this returns the first 32 bytes (which is NOT valid X25519).
        /// Callers should only use this with ECIES-capable destinations.
        /// </summary>
        private byte[] ExtractPublicKey(I2PPublicKey pubKey)
        {
            var keyBytes = pubKey.ToByteArray();
            var type = pubKey.Certificate.PublicKeyType;

            // X25519 key is 32 bytes and usually at the end for hybrid types
            if (keyBytes.Length == 32)
                return keyBytes;

            switch ( type )
            {
                case I2PKeyType.KeyTypes.MLKEM512_X25519:
                case I2PKeyType.KeyTypes.MLKEM768_X25519:
                case I2PKeyType.KeyTypes.MLKEM1024_X25519:
                    if ( keyBytes.Length >= 32 )
                    {
                        var result = new byte[32];
                        Array.Copy( keyBytes, keyBytes.Length - 32, result, 0, 32 );
                        return result;
                    }
                    break;
            }

            // Fallback for legacy or other types
            if (keyBytes.Length >= 32)
            {
                var result = new byte[32];
                Array.Copy(keyBytes, 0, result, 0, 32);
                return result;
            }

            throw new InvalidOperationException($"Cannot extract X25519 key from destination with key length {keyBytes.Length} and type {type}");
        }

        public void Cleanup()
        {
            lock (_sessionLock)
            {
                _availableTags.Clear();
            }
            _noiseIK?.Dispose();
            _noiseIK = null;
        }
    }

    /// <summary>
    /// ECIES Inbound Session
    /// Manages decryption for messages we receive from a remote destination
    /// </summary>
    public class ECIESInboundSession
    {
        private readonly I2PDestination _localDestination;
        private readonly byte[] _remoteStaticPublicKey;
        private readonly byte[] _localStaticPrivateKey;
        private readonly byte[] _localStaticPublicKey;
        private readonly NoiseIKhfs.KEMVariant? _kemVariant;

        // Session state
        private byte[] _sendKey;
        private byte[] _receiveKey;
        private readonly Dictionary<SessionTag, TagInfo> _inboundTags;
        private readonly object _sessionLock = new object();
        private ECIESRatchet _ratchet;

        // Retain the Noise state across handshake
        private NoiseIK _noiseIK;
        private NoiseIKhfs _noiseIKhfs;

        public DateTime Created { get; }
        public DateTime LastUsed { get; private set; }

        private class TagInfo
        {
            public byte[] Key { get; set; }
            public DateTime Created { get; set; }
            public int Index { get; set; }
        }

        public ECIESInboundSession(
            I2PDestination localDestination,
            byte[] remoteStaticPublicKey,
            byte[] localStaticPrivateKey,
            byte[] localStaticPublicKey,
            NoiseIKhfs.KEMVariant? kemVariant = null )
        {
            _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));
            _remoteStaticPublicKey = remoteStaticPublicKey;
            _localStaticPrivateKey = localStaticPrivateKey;
            _localStaticPublicKey = localStaticPublicKey;
            _kemVariant = kemVariant;

            _inboundTags = new Dictionary<SessionTag, TagInfo>();
            Created = DateTime.UtcNow;
            LastUsed = DateTime.UtcNow;
        }

        /// <summary>
        /// Create New Session Reply
        /// </summary>
        public byte[] CreateNewSessionReply(
            byte[] newSessionData,
            byte[] replyPayload,
            out List<SessionTag> tags)
        {
            if (newSessionData == null)
                throw new ArgumentNullException(nameof(newSessionData));

            if (replyPayload == null)
                replyPayload = Array.Empty<byte>();

            byte[] message;

            if ( _kemVariant.HasValue )
            {
                _noiseIKhfs = NoiseIKhfs.CreateResponder(
                    _localStaticPrivateKey,
                    _localStaticPublicKey,
                    _kemVariant.Value );

                var hybridMsg = ECIESHybridNewSessionMessage.Parse( newSessionData, _kemVariant.Value );
                _noiseIKhfs.ReadMessageA( hybridMsg.EphemeralPublicKey, hybridMsg.EncryptedKEMPublicKey, hybridMsg.EncryptedStaticKey, hybridMsg.EncryptedPayload );

                var (sendK, receiveK, ck) = _noiseIKhfs.FinalizeHandshake();
                _sendKey = sendK;
                _receiveKey = receiveK;

                // Bob uses deterministic tags derived from handshake shared secret
                // 1. Handshake tags for Message B
                var tagsetKey = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(ck, Array.Empty<byte>(), System.Text.Encoding.ASCII.GetBytes("SessionReplyTags"), 32);
                var handshakeTagSet = new ECIESTagSet(ck, tagsetKey);
                var (bTag, _) = handshakeTagSet.ConsumeNext();

                var hybridReply = ECIESHybridNewSessionReplyMessage.Create( bTag.ToByteArray().AsSpan(0, 8).ToArray(), replyPayload, _noiseIKhfs );
                message = hybridReply.ToByteArray();

                // 2. ES tags: rootKey = ck, data = receiveKey (Bob receives Alice's messages)
                lock (_sessionLock)
                {
                    var tagSet = new ECIESTagSet(ck, _receiveKey);
                    for (int i = 0; i < 800; i++)
                    {
                        var (tag, key) = tagSet.ConsumeNext();
                        _inboundTags[tag] = new TagInfo { Key = key, Created = DateTime.UtcNow, Index = i };
                    }
                }
            }
            else
            {
                // Create Noise IK responder - must process the new session first
                _noiseIK = NoiseIK.CreateResponder(
                    _localStaticPrivateKey,
                    _localStaticPublicKey);

                // Process the incoming new session message to establish shared state
                _noiseIK.ProcessNewSessionMessage(newSessionData);

                // Create reply: <- tag, e, ee, se, payload
                var (sendK, receiveK, ck) = _noiseIK.FinalizeHandshake();
                _sendKey = sendK;
                _receiveKey = receiveK;

                // Bob uses deterministic tags derived from handshake shared secret
                // 1. Handshake tags for Message B
                var tagsetKey = I2PCore.TransportLayer.Crypto.HKDF.DeriveKey(ck, Array.Empty<byte>(), System.Text.Encoding.ASCII.GetBytes("SessionReplyTags"), 32);
                var handshakeTagSet = new ECIESTagSet(ck, tagsetKey);
                var (bTag, _) = handshakeTagSet.ConsumeNext();

                message = _noiseIK.CreateNewSessionReplyMessage(bTag.ToByteArray().AsSpan(0, 8).ToArray(), replyPayload);

                // 2. ES tags: rootKey = ck, data = receiveKey (Bob receives Alice's messages)
                lock (_sessionLock)
                {
                    var tagSet = new ECIESTagSet(ck, _receiveKey);
                    for (int i = 0; i < 800; i++)
                    {
                        var (tag, key) = tagSet.ConsumeNext();
                        _inboundTags[tag] = new TagInfo { Key = key, Created = DateTime.UtcNow, Index = i };
                    }
                }
            }

            // Initialize ratchet
            _ratchet = new ECIESRatchet(_sendKey, _receiveKey);

            // Clear Noise state
            _noiseIK?.Dispose();
            _noiseIK = null;
            _noiseIKhfs?.Dispose();
            _noiseIKhfs = null;

            LastUsed = DateTime.UtcNow;
            tags = null; // Tags are stored internally in deterministic derivation

            return message;
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

        /// <summary>
        /// Process existing session message
        /// </summary>
        public byte[] ProcessExistingSessionMessage(ECIESExistingSessionMessage message)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            TagInfo tagInfo;
            lock (_sessionLock)
            {
                // Find tag
                if (!_inboundTags.TryGetValue(message.Tag, out tagInfo))
                    throw new InvalidOperationException("Unknown or expired tag");

                // Remove used tag (each tag is single-use)
                _inboundTags.Remove(message.Tag);

                // Ratchet forward
                _ratchet?.RatchetForward();

                LastUsed = DateTime.UtcNow;
            }

            // Decrypt payload with tag-specific key and tag index for nonce derivation
            return message.Decrypt(tagInfo.Key, tagInfo.Index);
        }

        public void Cleanup()
        {
            lock (_sessionLock)
            {
                _inboundTags.Clear();
            }
            _noiseIK?.Dispose();
            _noiseIK = null;
        }
    }

    /// <summary>
    /// ECIES Ratchet implementation
    /// Provides forward secrecy by advancing keys after each message
    /// Uses HKDF for key derivation per I2P ECIES spec
    /// </summary>
    public class ECIESRatchet
    {
        private byte[] _sendKey;
        private byte[] _receiveKey;
        private int _sendCounter;
        private int _receiveCounter;

        public ECIESRatchet(byte[] sendKey, byte[] receiveKey)
        {
            _sendKey = (byte[])(sendKey?.Clone() ?? throw new ArgumentNullException(nameof(sendKey)));
            _receiveKey = (byte[])(receiveKey?.Clone() ?? throw new ArgumentNullException(nameof(receiveKey)));
            _sendCounter = 0;
            _receiveCounter = 0;
        }

        /// <summary>
        /// Ratchet the send key forward
        /// </summary>
        public void RatchetForward()
        {
            _sendKey = HKDF.DeriveKey(
                _sendKey,
                BitConverter.GetBytes(_sendCounter++),
                System.Text.Encoding.ASCII.GetBytes("ratchet"),
                32);

            _receiveKey = HKDF.DeriveKey(
                _receiveKey,
                BitConverter.GetBytes(_receiveCounter++),
                System.Text.Encoding.ASCII.GetBytes("ratchet"),
                32);
        }

        public byte[] GetSendKey() => (byte[])_sendKey.Clone();
        public byte[] GetReceiveKey() => (byte[])_receiveKey.Clone();
        public int SendCounter => _sendCounter;
        public int ReceiveCounter => _receiveCounter;
    }
}
