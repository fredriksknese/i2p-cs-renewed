using System;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES;

/// <summary>
///     ECIES Router Message Processor
///     Handles incoming and outgoing ECIES router messages
///     Integrates with the session key manager for encryption/decryption
/// </summary>
public class ECIESRouterProcessor
{
    private readonly I2PIdentHash _localRouterHash;
    private readonly byte[] _localStaticPrivateKey;
    private readonly byte[] _localStaticPublicKey;

    /// <summary>
    ///     The identity this processor was built for. Batch 2-1 test seam: Router caches the
    ///     processor lazily and used to keep it across a restart, where it would silently fail to
    ///     decrypt everything addressed to the router's new identity.
    /// </summary>
    internal I2PIdentHash LocalRouterHash => _localRouterHash;

    public ECIESRouterProcessor(
        I2PIdentHash localRouterHash,
        byte[] localStaticPrivateKey,
        byte[] localStaticPublicKey)
    {
        if (localRouterHash == null)
            throw new ArgumentNullException(nameof(localRouterHash));

        if (localStaticPrivateKey == null || localStaticPrivateKey.Length != 32)
            throw new ArgumentException("Static private key must be 32 bytes", nameof(localStaticPrivateKey));

        if (localStaticPublicKey == null || localStaticPublicKey.Length != 32)
            throw new ArgumentException("Static public key must be 32 bytes", nameof(localStaticPublicKey));

        _localRouterHash = localRouterHash;
        _localStaticPrivateKey = localStaticPrivateKey;
        _localStaticPublicKey = localStaticPublicKey;
        SessionManager = new ECIESRouterSKM(localStaticPrivateKey, localStaticPublicKey);
    }

    public ECIESRouterSKM SessionManager { get; }

    /// <summary>
    ///     Get the number of active sessions
    /// </summary>
    public int SessionCount => SessionManager.SessionCount;

    /// <summary>
    ///     Get the local router's static public key
    /// </summary>
    public byte[] LocalPublicKey => (byte[])_localStaticPublicKey.Clone();

    /// <summary>
    ///     Send a message to an ECIES router
    ///     Automatically handles session creation or reuse
    /// </summary>
    public byte[] SendMessage(I2PIdentHash remoteRouterHash, byte[] remotePublicKey, byte[] payload)
    {
        if (remoteRouterHash == null)
            throw new ArgumentNullException(nameof(remoteRouterHash));

        if (remotePublicKey == null || remotePublicKey.Length != 32)
            throw new ArgumentException("Remote public key must be 32 bytes", nameof(remotePublicKey));

        if (payload == null)
            throw new ArgumentNullException(nameof(payload));

        // Check if we have an existing session
        if (SessionManager.HasSession(remoteRouterHash))
            try
            {
                // Try to use existing session
                return SessionManager.CreateExistingSessionMessage(remoteRouterHash, payload);
            }
            catch (InvalidOperationException ex)
            {
                // Falling back to a fresh handshake is correct and recoverable, so this is not an
                // error path. It is logged at Warning anyway because the usual cause is outbound
                // tag exhaustion (batch 5-3: InitializeBiDirectionalTags pre-generates a fixed
                // 5000 tags per direction and never generates more, so a long-lived session
                // simply stops being able to speak). Swallowed silently, that defect presents as
                // nothing worse than "this peer re-handshakes a lot".
                Logging.LogWarning(
                    $"ECIESRouterProcessor: existing session to {remoteRouterHash.Id32Short} "
                    + $"could not be used, falling back to a new handshake: {ex}");
            }

        // Create new session
        return SessionManager.CreateNewSessionMessage(remoteRouterHash, remotePublicKey, payload);
    }

    /// <summary>
    ///     Process an incoming ECIES router message
    ///     Automatically handles new session or existing session messages
    /// </summary>
    public ProcessedMessage ProcessMessage(byte[] message)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));

        try
        {
            // Let session manager determine message type and decrypt
            var (payload, routerHash) = SessionManager.ProcessMessage(message);

            return new ProcessedMessage
            {
                Success = true,
                Payload = payload,
                RemoteRouterHash = routerHash,
                IsNewSession = routerHash != null && !SessionManager.HasSession(routerHash)
            };
        }
        catch (Exception ex)
        {
            // Debug, not Warning: the only caller (Router.HandleGarlic) uses this as a trial
            // decrypt and returns false to fall through to the ElGamal path, so failure is the
            // normal outcome for any router garlic not addressed to our static key.
            //
            // Logged here rather than left to the caller because that caller reads only
            // Payload and never looks at Error — so before this line the exception had nowhere
            // to go at all. The type is carried alongside the message for the same reason
            // ProcessNewSessionMessage carries it: "Bad Data" names no layer on its own.
            Logging.LogDebug(
                $"ECIESRouterProcessor: ProcessMessage could not decrypt {message.Length} bytes: {ex}");

            return new ProcessedMessage
            {
                Success = false,
                Error = $"{ex.GetType().Name}: {ex.Message}"
            };
        }
    }

    /// <summary>
    ///     Process a DatabaseLookup and prepare encrypted reply
    /// </summary>
    public byte[] ProcessDatabaseLookup(DatabaseLookupMessage lookup, DatabaseStoreMessage reply)
    {
        if (lookup == null)
            throw new ArgumentNullException(nameof(lookup));

        if (reply == null)
            throw new ArgumentNullException(nameof(reply));

        // Check if ECIES encryption is required
        if (!ECIESDatabaseLookup.RequiresECIES(lookup))
            throw new InvalidOperationException("DatabaseLookup does not require ECIES encryption");

        // Extract reply public key
        var replyPublicKey = ECIESDatabaseLookup.ExtractReplyPublicKey(lookup);

        // Encrypt the reply
        return ECIESDatabaseLookup.EncryptReply(replyPublicKey, reply, SessionManager, _localRouterHash);
    }

    /// <summary>
    ///     Decrypt a DatabaseStore reply that was encrypted with ECIES
    /// </summary>
    public DatabaseStoreMessage DecryptDatabaseStoreReply(byte[] encryptedReply)
    {
        if (encryptedReply == null)
            throw new ArgumentNullException(nameof(encryptedReply));

        return ECIESDatabaseLookup.DecryptReply(encryptedReply, SessionManager);
    }

    /// <summary>
    ///     Handle a NextKey block from a decrypted garlic message.
    ///     Processes ratchet key rotation for forward secrecy.
    /// </summary>
    public void HandleNextKey(NextKeyBlock nextKey)
    {
        if (nextKey == null) return;

        try
        {
            SessionManager.HandleNextKey(nextKey);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"ECIESRouterProcessor: HandleNextKey error: {ex}");
        }
    }

    /// <summary>
    ///     Clean up expired sessions
    ///     Should be called periodically
    /// </summary>
    public void CleanupSessions()
    {
        SessionManager.CleanupExpired();
    }
}

/// <summary>
///     Result of processing an ECIES router message
/// </summary>
public class ProcessedMessage
{
    /// <summary>
    ///     True if message was successfully decrypted
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    ///     Decrypted payload
    /// </summary>
    public byte[] Payload { get; set; }

    /// <summary>
    ///     Router hash of the sender (if available)
    /// </summary>
    public I2PIdentHash RemoteRouterHash { get; set; }

    /// <summary>
    ///     True if this was a new session message
    /// </summary>
    public bool IsNewSession { get; set; }

    /// <summary>
    ///     Error message if Success is false
    /// </summary>
    public string Error { get; set; }
}

/// <summary>
///     Statistics for ECIES router message processing
/// </summary>
public class ECIESRouterStats
{
    public long NewSessionsSent { get; set; }
    public long ExistingSessionsSent { get; set; }
    public long NewSessionsReceived { get; set; }
    public long ExistingSessionsReceived { get; set; }
    public long DecryptionFailures { get; set; }
    public long SessionsExpired { get; set; }

    public long TotalSent => NewSessionsSent + ExistingSessionsSent;
    public long TotalReceived => NewSessionsReceived + ExistingSessionsReceived;

    public void Reset()
    {
        NewSessionsSent = 0;
        ExistingSessionsSent = 0;
        NewSessionsReceived = 0;
        ExistingSessionsReceived = 0;
        DecryptionFailures = 0;
        SessionsExpired = 0;
    }

    public override string ToString()
    {
        return $"ECIES Stats: Sent={TotalSent} (NS={NewSessionsSent}, ES={ExistingSessionsSent}), " +
               $"Recv={TotalReceived} (NS={NewSessionsReceived}, ES={ExistingSessionsReceived}), " +
               $"Failures={DecryptionFailures}, Expired={SessionsExpired}";
    }
}