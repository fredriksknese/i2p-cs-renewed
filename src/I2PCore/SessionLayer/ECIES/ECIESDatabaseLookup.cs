using System;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES;

/// <summary>
///     ECIES DatabaseLookup Encryption Support
///     Handles encryption of DatabaseLookup replies when the reply router is ECIES
///     When a DatabaseLookup has the Ecies flag set:
///     - The reply key field contains the X25519 public key for encryption
///     - Replies are encrypted using ECIES router messages
/// </summary>
public static class ECIESDatabaseLookup
{
    /// <summary>
    ///     Check if a DatabaseLookup requires ECIES encryption
    /// </summary>
    public static bool RequiresECIES(DatabaseLookupMessage lookup)
    {
        if (lookup == null)
            return false;

        return (lookup.LookupType & DatabaseLookupMessage.LookupTypes.Ecies) != 0;
    }

    /// <summary>
    ///     Extract ECIES reply key from DatabaseLookup
    ///     When Ecies flag is set, the ReplyKey field contains the X25519 public key
    /// </summary>
    public static byte[] ExtractReplyPublicKey(DatabaseLookupMessage lookup)
    {
        if (lookup == null)
            throw new ArgumentNullException(nameof(lookup));

        if (!RequiresECIES(lookup))
            throw new InvalidOperationException("DatabaseLookup does not have ECIES flag set");

        // ReplyKey contains the X25519 public key (32 bytes)
        var replyKey = lookup.ReplyKey;
        if (replyKey == null)
            throw new InvalidOperationException("DatabaseLookup has ECIES flag but no reply key");

        // Convert I2PByteBlock to byte array
        var keyBytes = new byte[replyKey.Key.Length];
        Array.Copy(replyKey.Key.BaseArray, replyKey.Key.BaseArrayOffset, keyBytes, 0, replyKey.Key.Length);
        return keyBytes;
    }

    /// <summary>
    ///     Create a DatabaseLookup with ECIES encryption enabled
    /// </summary>
    public static DatabaseLookupMessage CreateECIESLookup(
        I2PIdentHash key,
        I2PIdentHash from,
        I2PTunnelId tunnelId,
        byte[] replyPublicKey,
        bool lookupRouterInfo = false,
        bool lookupLeaseSet = false)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        if (from == null)
            throw new ArgumentNullException(nameof(from));

        if (replyPublicKey == null || replyPublicKey.Length != 32)
            throw new ArgumentException("Reply public key must be 32 bytes (X25519)", nameof(replyPublicKey));

        // Build lookup type flags
        var lookupType = DatabaseLookupMessage.LookupTypes.Tunnel |
                         DatabaseLookupMessage.LookupTypes.Ecies;

        if (lookupRouterInfo)
            lookupType |= DatabaseLookupMessage.LookupTypes.RouterInfo;
        else if (lookupLeaseSet)
            lookupType |= DatabaseLookupMessage.LookupTypes.LeaseSet;

        // Build key info with ECIES flag and X25519 reply key
        var keyInfo = new DatabaseLookupKeyInfo
        {
            EncryptionFlag = false,
            EciesFlag = true,
            ReplyKey = new I2PByteBlock(replyPublicKey),
            Tags = Array.Empty<I2PByteBlock>()
        };

        return new DatabaseLookupMessage(
            key,
            from,
            tunnelId,
            lookupType,
            null,
            keyInfo);
    }

    /// <summary>
    ///     Encrypt a DatabaseStore reply using ECIES
    /// </summary>
    public static byte[] EncryptReply(
        byte[] replyPublicKey,
        DatabaseStoreMessage reply,
        ECIESRouterSKM sessionManager,
        I2PIdentHash localRouterHash = null)
    {
        if (replyPublicKey == null || replyPublicKey.Length != 32)
            throw new ArgumentException("Reply public key must be 32 bytes", nameof(replyPublicKey));

        if (reply == null)
            throw new ArgumentNullException(nameof(reply));

        if (sessionManager == null)
            throw new ArgumentNullException(nameof(sessionManager));

        // Serialize the reply message
        var replyData = SerializeMessage(reply);

        // Use the local router hash for routing context, or the
        // RouterContext identity hash if available
        var routerHash = localRouterHash ?? RouterContext.Inst?.MyRouterIdentity?.IdentHash;
        if (routerHash == null)
        {
            Logging.LogWarning("ECIESDatabaseLookup: No local router hash available, using random hash");
            routerHash = new I2PIdentHash(true);
        }

        var encryptedReply = sessionManager.CreateNewSessionMessage(
            routerHash,
            replyPublicKey,
            replyData);

        return encryptedReply;
    }

    /// <summary>
    ///     Decrypt a DatabaseStore reply using ECIES
    /// </summary>
    public static DatabaseStoreMessage DecryptReply(
        byte[] encryptedReply,
        ECIESRouterSKM sessionManager)
    {
        if (encryptedReply == null)
            throw new ArgumentNullException(nameof(encryptedReply));

        if (sessionManager == null)
            throw new ArgumentNullException(nameof(sessionManager));

        // Decrypt using session manager
        var (replyData, routerHash) = sessionManager.ProcessMessage(encryptedReply);

        // Deserialize the reply message
        return DeserializeMessage(replyData);
    }

    /// <summary>
    ///     Serialize a DatabaseStore message to bytes
    /// </summary>
    private static byte[] SerializeMessage(DatabaseStoreMessage message)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));

        // Get the message payload
        var payload = message.Payload;
        var result = new byte[payload.Length];
        Array.Copy(payload.BaseArray, payload.BaseArrayOffset, result, 0, payload.Length);
        return result;
    }

    /// <summary>
    ///     Deserialize a DatabaseStore message from bytes
    /// </summary>
    private static DatabaseStoreMessage DeserializeMessage(byte[] data)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentException("Data cannot be null or empty", nameof(data));

        // Parse as DatabaseStore message
        return new DatabaseStoreMessage(new I2PBufferCursor(data));
    }
}

/// <summary>
///     Helper for building ECIES-enabled DatabaseLookup messages
/// </summary>
public class ECIESDatabaseLookupBuilder
{
    private I2PIdentHash _from;
    private I2PIdentHash _key;
    private bool _lookupLeaseSet;
    private bool _lookupRouterInfo;
    private byte[] _replyPublicKey;
    private I2PTunnelId _tunnelId;

    public ECIESDatabaseLookupBuilder WithKey(I2PIdentHash key)
    {
        _key = key;
        return this;
    }

    public ECIESDatabaseLookupBuilder WithFrom(I2PIdentHash from)
    {
        _from = from;
        return this;
    }

    public ECIESDatabaseLookupBuilder WithTunnelId(I2PTunnelId tunnelId)
    {
        _tunnelId = tunnelId;
        return this;
    }

    public ECIESDatabaseLookupBuilder WithReplyPublicKey(byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length != 32)
            throw new ArgumentException("Reply public key must be 32 bytes", nameof(publicKey));
        _replyPublicKey = (byte[])publicKey.Clone();
        return this;
    }

    public ECIESDatabaseLookupBuilder ForRouterInfo()
    {
        _lookupRouterInfo = true;
        _lookupLeaseSet = false;
        return this;
    }

    public ECIESDatabaseLookupBuilder ForLeaseSet()
    {
        _lookupLeaseSet = true;
        _lookupRouterInfo = false;
        return this;
    }

    public DatabaseLookupMessage Build()
    {
        if (_key == null)
            throw new InvalidOperationException("Key must be set");

        if (_from == null)
            throw new InvalidOperationException("From must be set");

        if (_replyPublicKey == null)
            throw new InvalidOperationException("Reply public key must be set");

        return ECIESDatabaseLookup.CreateECIESLookup(
            _key,
            _from,
            _tunnelId,
            _replyPublicKey,
            _lookupRouterInfo,
            _lookupLeaseSet);
    }
}