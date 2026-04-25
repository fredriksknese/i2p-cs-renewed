using System;
using System.Collections.Generic;
using System.Text;
using I2PCore.Crypto;
using I2PCore.Utils;
using X25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace I2PCore.SessionLayer.ECIES;

/// <summary>
///     ECIES-X25519-AEAD-Ratchet Tag Set
///     Implements the tag generation and symmetric key derivation per the I2P ECIES spec.
///     Each tag set is initialized from a root key and a DH-derived tagset key.
///     Tags and symmetric keys are derived via HKDF ratcheting.
///     Matches i2pd's RatchetTagSet / ReceiveRatchetTagSet classes.
/// </summary>
public class RatchetTagSet
{
    public const int MAX_NUM_GENERATED_TAGS = 800;
    private const string SESSION_TAG_CONSTANT = "STInitialization";
    private const string SYMMETRIC_KEY_CONSTANT = "SessionTagKeyGen";
    private const string NEXT_ROOT_KEY_CONSTANT = "TagAndKeyGenKeys";
    private readonly Queue<ulong> _generatedTags = new();

    // Stored session tags and their associated symmetric keys
    private readonly Dictionary<ulong, (byte[] key, int index)> _tagToKey = new();
    private byte[] _nextRootKey; // root key for next DH ratchet
    private int _nextSymmKeyIndex; // next symmetric key index
    private byte[] _sessionTagCK; // chaining key for session tag ratchet
    private byte[] _symmKeyCK; // chaining key for symmetric key derivation

    public int TagSetID { get; private set; }

    public int NextIndex { get; private set; }

    public int AvailableTagCount => _tagToKey.Count;

    public void SetTagSetID(int id)
    {
        TagSetID = id;
    }

    /// <summary>
    ///     Initialize tag set from DH-derived keys.
    ///     rootKey: from previous tag set's GetNextRootKey()
    ///     k: HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32) from DH agreement
    /// </summary>
    public void DHInitialize(byte[] rootKey, byte[] k)
    {
        if (rootKey == null || rootKey.Length != 32)
            throw new ArgumentException("Root key must be 32 bytes", nameof(rootKey));
        if (k == null || k.Length != 32)
            throw new ArgumentException("Tagset key must be 32 bytes", nameof(k));

        // keydata = HKDF(rootKey, k, "TagAndKeyGenKeys", 64)
        // keydata[0..31] = tag generation key
        // keydata[32..63] = next root key
        var keydata = HKDF.DeriveKey(rootKey, k,
            Encoding.ASCII.GetBytes(NEXT_ROOT_KEY_CONSTANT), 64);

        var tagGenKey = new byte[32];
        _nextRootKey = new byte[32];
        Array.Copy(keydata, 0, tagGenKey, 0, 32);
        Array.Copy(keydata, 32, _nextRootKey, 0, 32);

        // Initialize session tag chaining key
        // [sessionTag_ck, sessionTag_constant] = HKDF(tagGenKey, ZEROLEN, "STInitialization", 64)
        var stInit = HKDF.DeriveKey(tagGenKey, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes(SESSION_TAG_CONSTANT), 64);

        _sessionTagCK = new byte[32];
        Array.Copy(stInit, 0, _sessionTagCK, 0, 32);
        // stInit[32..63] is the initial constant (not used directly)

        // Initialize symmetric key chaining key
        // [symmKey_ck, symmKey_constant] = HKDF(tagGenKey, ZEROLEN, "SessionTagKeyGen", 64)
        var skInit = HKDF.DeriveKey(tagGenKey, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes(SYMMETRIC_KEY_CONSTANT), 64);

        _symmKeyCK = new byte[32];
        Array.Copy(skInit, 0, _symmKeyCK, 0, 32);

        NextIndex = 0;
        _nextSymmKeyIndex = 0;
    }

    /// <summary>
    ///     Advance the session tag ratchet to generate the next tag.
    ///     Each call produces one 8-byte session tag.
    /// </summary>
    public void NextSessionTagRatchet()
    {
        // [sessionTag_ck, tag] = HKDF(sessionTag_ck, ZEROLEN, "", 64)
        var output = HKDF.DeriveKey(_sessionTagCK, Array.Empty<byte>(), null, 64);

        _sessionTagCK = new byte[32];
        Array.Copy(output, 0, _sessionTagCK, 0, 32);

        // Tag is first 8 bytes of output[32..63]
        var tag = BitConverter.ToUInt64(output, 32);

        // Derive symmetric key for this tag index
        var symmKey = DeriveSymmetricKey(_nextSymmKeyIndex);
        _nextSymmKeyIndex++;

        _tagToKey[tag] = (symmKey, NextIndex);
        _generatedTags.Enqueue(tag);
        NextIndex++;
    }

    /// <summary>
    ///     Derive symmetric key for a given index.
    ///     [symmKey_ck, key] = HKDF(symmKey_ck, ZEROLEN, "", 64)
    /// </summary>
    private byte[] DeriveSymmetricKey(int index)
    {
        // Advance symmetric key CK to match index
        var output = HKDF.DeriveKey(_symmKeyCK, Array.Empty<byte>(), null, 64);

        _symmKeyCK = new byte[32];
        Array.Copy(output, 0, _symmKeyCK, 0, 32);

        var key = new byte[32];
        Array.Copy(output, 32, key, 0, 32);

        return key;
    }

    /// <summary>
    ///     Get the next root key for the following DH ratchet
    /// </summary>
    public byte[] GetNextRootKey()
    {
        return (byte[])_nextRootKey?.Clone();
    }

    /// <summary>
    ///     Look up the symmetric key for a given session tag
    /// </summary>
    public byte[] FindSymmetricKey(ulong tag, out int tagIndex)
    {
        if (_tagToKey.TryGetValue(tag, out var info))
        {
            tagIndex = info.index;
            _tagToKey.Remove(tag); // Single-use
            return info.key;
        }

        tagIndex = -1;
        return null;
    }

    /// <summary>
    ///     Generate multiple tags up to the limit
    /// </summary>
    public void GenerateTags(int count)
    {
        for (var i = 0; i < count && NextIndex < MAX_NUM_GENERATED_TAGS; i++) NextSessionTagRatchet();
    }

    /// <summary>
    ///     Trim old tags when tag set is being replaced
    /// </summary>
    public void Expire()
    {
        _tagToKey.Clear();
        _generatedTags.Clear();
    }
}

/// <summary>
///     DH Ratchet state for ECIES-X25519 key rotation.
///     Matches i2pd's DHRatchet struct.
/// </summary>
public class DHRatchet
{
    public int KeyID { get; set; }
    public byte[] PrivateKey { get; set; } // 32 bytes, local X25519 private key
    public byte[] PublicKey { get; set; } // 32 bytes, local X25519 public key
    public byte[] RemotePublicKey { get; set; } // 32 bytes, last received remote key
    public bool NewKey { get; set; } // Whether this is a newly generated key

    /// <summary>
    ///     Calculate the receive tag set ID for this ratchet state
    ///     Forward key: 2 * keyID
    ///     Reverse key: 2 * keyID + 1
    /// </summary>
    public int GetReceiveTagSetID()
    {
        return NewKey ? 2 * KeyID : 2 * KeyID + 1;
    }

    /// <summary>
    ///     Generate a new X25519 keypair for this ratchet
    /// </summary>
    public void GenerateNewKeyPair()
    {
        PrivateKey = BufUtils.RandomBytes(32);
        PublicKey = new byte[32];
        X25519.ScalarMultBase(PrivateKey, 0, PublicKey, 0);
        NewKey = true;
    }

    /// <summary>
    ///     Perform X25519 DH agreement
    /// </summary>
    public byte[] Agree()
    {
        if (PrivateKey == null || RemotePublicKey == null)
            throw new InvalidOperationException("Both private and remote public keys required for agreement");

        var sharedSecret = new byte[32];
        X25519.ScalarMult(
            PrivateKey, 0, RemotePublicKey, 0, sharedSecret, 0);
        return sharedSecret;
    }
}

/// <summary>
///     NextKey handler for ECIES ratchet sessions.
///     Processes NextKey blocks to advance the DH ratchet.
///     Matches i2pd's ECIESX25519AEADRatchetSession::HandleNextKey().
/// </summary>
public class NextKeyHandler
{
    private DHRatchet _nextReceiveRatchet;
    private DHRatchet _nextSendRatchet;

    // Current tag sets

    public NextKeyHandler(RatchetTagSet sendTagSet, RatchetTagSet receiveTagSet)
    {
        SendTagSet = sendTagSet ?? throw new ArgumentNullException(nameof(sendTagSet));
        ReceiveTagSet = receiveTagSet ?? throw new ArgumentNullException(nameof(receiveTagSet));
    }

    public RatchetTagSet SendTagSet { get; private set; }

    public RatchetTagSet ReceiveTagSet { get; private set; }

    public bool NeedsSendForwardKey { get; private set; }

    public bool NeedsSendReverseKey { get; private set; }

    /// <summary>
    ///     Handle incoming NextKey block from a decrypted garlic message.
    /// </summary>
    public void HandleNextKey(NextKeyBlock nextKey)
    {
        if (nextKey == null) return;

        if (nextKey.IsReverseKey)
            HandleReverseKey(nextKey);
        else
            HandleForwardKey(nextKey);
    }

    /// <summary>
    ///     Process reverse key - peer acknowledges our forward key proposal.
    ///     Advances the send ratchet.
    /// </summary>
    private void HandleReverseKey(NextKeyBlock nextKey)
    {
        if (!NeedsSendForwardKey || _nextSendRatchet == null)
        {
            Logging.LogDebug("NextKeyHandler: Unexpected reverse key");
            return;
        }

        if (nextKey.KeyID != _nextSendRatchet.KeyID &&
            !(nextKey.KeyID == _nextSendRatchet.KeyID - 1 && _nextSendRatchet.NewKey))
        {
            Logging.LogDebug($"NextKeyHandler: Unexpected reverse key ID {nextKey.KeyID}");
            return;
        }

        // If key present, update remote public key
        if (nextKey.IsKeyPresent && nextKey.PublicKey != null) _nextSendRatchet.RemotePublicKey = nextKey.PublicKey;

        // Perform DH and derive new send tag set
        var sharedSecret = _nextSendRatchet.Agree();
        var tagsetKey = HKDF.DeriveKey(sharedSecret, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes("XDHRatchetTagSet"), 32);

        var newTagSet = new RatchetTagSet();
        newTagSet.SetTagSetID(1 + _nextSendRatchet.KeyID + nextKey.KeyID);
        newTagSet.DHInitialize(SendTagSet.GetNextRootKey(), tagsetKey);
        newTagSet.NextSessionTagRatchet();

        SendTagSet = newTagSet;
        NeedsSendForwardKey = false;

        Logging.LogDebug($"NextKeyHandler: New send tagset {newTagSet.TagSetID} created");
    }

    /// <summary>
    ///     Process forward key - peer sends us their new key.
    ///     Advances the receive ratchet.
    /// </summary>
    private void HandleForwardKey(NextKeyBlock nextKey)
    {
        var requestReverseKey = nextKey.IsRequestReverseKey;

        if (_nextReceiveRatchet == null)
        {
            _nextReceiveRatchet = new DHRatchet { KeyID = nextKey.KeyID };
        }
        else
        {
            if (nextKey.KeyID == _nextReceiveRatchet.KeyID &&
                requestReverseKey == _nextReceiveRatchet.NewKey)
            {
                Logging.LogDebug($"NextKeyHandler: Duplicate key {nextKey.KeyID}");
                return;
            }

            _nextReceiveRatchet.KeyID = nextKey.KeyID;
        }

        if (requestReverseKey)
        {
            // Generate new ephemeral keypair for reverse response
            _nextReceiveRatchet.GenerateNewKeyPair();
            _nextReceiveRatchet.NewKey = true;
        }
        else
        {
            _nextReceiveRatchet.NewKey = false;
        }

        // Store remote public key if present
        if (nextKey.IsKeyPresent && nextKey.PublicKey != null) _nextReceiveRatchet.RemotePublicKey = nextKey.PublicKey;

        // Perform DH and derive new receive tag set
        var sharedSecret = _nextReceiveRatchet.Agree();
        var tagsetKey = HKDF.DeriveKey(sharedSecret, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes("XDHRatchetTagSet"), 32);

        var tagsetID = _nextReceiveRatchet.GetReceiveTagSetID();

        var newReceiveTagSet = new RatchetTagSet();
        newReceiveTagSet.SetTagSetID(tagsetID);
        newReceiveTagSet.DHInitialize(ReceiveTagSet.GetNextRootKey(), tagsetKey);
        newReceiveTagSet.NextSessionTagRatchet();

        // Generate receive tags
        newReceiveTagSet.GenerateTags(RatchetTagSet.MAX_NUM_GENERATED_TAGS);

        // Expire old tag set and install new one
        ReceiveTagSet.Expire();
        ReceiveTagSet = newReceiveTagSet;

        // Signal that we need to send a reverse key in our next message
        NeedsSendReverseKey = true;

        Logging.LogDebug($"NextKeyHandler: New receive tagset {tagsetID} created");
    }

    /// <summary>
    ///     Create a NextKey block for sending in our next message.
    ///     Call this when building outbound garlic message payload.
    /// </summary>
    public NextKeyBlock CreateNextKeyBlock()
    {
        if (NeedsSendReverseKey && _nextReceiveRatchet != null)
        {
            // Send reverse key acknowledging peer's forward key
            var block = new NextKeyBlock
            {
                Flag = ECIESBlockFormat.NEXT_KEY_REVERSE_KEY_FLAG,
                KeyID = (ushort)(_nextReceiveRatchet.KeyID - (_nextReceiveRatchet.NewKey ? 1 : 0)),
                IsReverseKey = true
            };

            if (_nextReceiveRatchet.NewKey)
            {
                block.Flag |= ECIESBlockFormat.NEXT_KEY_KEY_PRESENT_FLAG;
                block.PublicKey = _nextReceiveRatchet.PublicKey;
                block.IsKeyPresent = true;
            }

            NeedsSendReverseKey = false;
            return block;
        }

        if (NeedsSendForwardKey && _nextSendRatchet != null)
        {
            // Send forward key proposing ratchet advance
            var flag = _nextSendRatchet.NewKey
                ? ECIESBlockFormat.NEXT_KEY_KEY_PRESENT_FLAG
                : ECIESBlockFormat.NEXT_KEY_REQUEST_REVERSE_KEY_FLAG;

            // For first key, also request reverse
            if (_nextSendRatchet.KeyID == 0)
                flag |= ECIESBlockFormat.NEXT_KEY_REQUEST_REVERSE_KEY_FLAG;

            var block = new NextKeyBlock
            {
                Flag = flag,
                KeyID = (ushort)_nextSendRatchet.KeyID,
                IsKeyPresent = _nextSendRatchet.NewKey,
                IsRequestReverseKey = (flag & ECIESBlockFormat.NEXT_KEY_REQUEST_REVERSE_KEY_FLAG) != 0
            };

            if (_nextSendRatchet.NewKey)
                block.PublicKey = _nextSendRatchet.PublicKey;

            return block;
        }

        return null;
    }

    /// <summary>
    ///     Initiate a forward key rotation.
    ///     Generates a new keypair and signals that a NextKey block should be sent.
    /// </summary>
    public void InitiateForwardKey()
    {
        if (_nextSendRatchet == null)
            _nextSendRatchet = new DHRatchet();

        _nextSendRatchet.GenerateNewKeyPair();
        _nextSendRatchet.KeyID++;
        NeedsSendForwardKey = true;
    }
}