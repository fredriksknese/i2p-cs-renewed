using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Crypto;
using I2PCore.Crypto.MLKEM;
using I2PCore.Data;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using GarlicClove = I2PCore.TunnelLayer.I2NP.Data.GarlicClove;

namespace I2PCore.SessionLayer;

/// <summary>
///     Manages temporary crypto keys and sessions with remote destinations
///     and encrypts and decrypts communication.
/// </summary>
public class SessionManager
{
    internal readonly ClientDestination Context;

    private readonly EgaesDecryptReceivedSessions IncommingSessions;

    internal readonly ConcurrentDictionary<I2PIdentHash, Session> Sessions = new();
    internal ECIESSessionKeyManager EciesManager;
    private List<I2PPrivateKey> PrivateKeysField;

    public SessionManager(ClientDestination context)
    {
        Context = context;
        IncommingSessions = new EgaesDecryptReceivedSessions(this);
    }

    /// <summary>
    ///     Used to decrypt ElGamal blocks.
    /// </summary>
    public List<I2PPrivateKey> PrivateKeys
    {
        get => PrivateKeysField;
        set
        {
            PrivateKeysField = value;
            IncommingSessions.PrivateKeys = value;
        }
    }

    /// <summary>
    ///     Used when constructing LeaseSets for this Destination.
    /// </summary>
    public List<I2PPublicKey> PublicKeys { get; set; }

    public void GenerateTemporaryKeys()
    {
        PrivateKeys = new List<I2PPrivateKey>();
        PublicKeys = new List<I2PPublicKey>();

        var eciesprivkey = new I2PPrivateKey(new I2PCertificate(I2PKeyType.KeyTypes.X25519));
        var eciespubkey = new I2PPublicKey(eciesprivkey);

        if (Context.Options.TryGetValue("i2cp.leaseSetEncType", out var encTypesStr))
        {
            var types = encTypesStr.Split(',', StringSplitOptions.RemoveEmptyEntries);
            foreach (var typeStr in types)
            {
                var kt = I2PKeyType.Parse(typeStr.Trim());
                if (kt != I2PKeyType.KeyTypes.Invalid)
                {
                    AddKeyForType(kt, eciesprivkey, eciespubkey);
                }
            }
        }

        if (!PublicKeys.Any())
        {
            switch (RouterContext.Inst.ProxyEncryption)
            {
                case RouterContext.HttpProxyEncryptionType.Ecies:
                    AddKeyForType(I2PKeyType.KeyTypes.X25519, eciesprivkey, eciespubkey);
                    break;

                case RouterContext.HttpProxyEncryptionType.Mlkem:
                    AddKeyForType(I2PKeyType.KeyTypes.MLKEM768_X25519, eciesprivkey, eciespubkey);
                    break;

                case RouterContext.HttpProxyEncryptionType.Hybrid:
                    AddKeyForType(I2PKeyType.KeyTypes.X25519, eciesprivkey, eciespubkey);
                    AddKeyForType(I2PKeyType.KeyTypes.MLKEM768_X25519, eciesprivkey, eciespubkey);
                    break;
            }
        }

        EciesManager =
            new ECIESSessionKeyManager(Context.Destination, eciesprivkey.ToByteArray(), eciespubkey.ToByteArray());
    }

    private void AddKeyForType(I2PKeyType.KeyTypes kt, I2PPrivateKey eciesprivkey, I2PPublicKey eciespubkey)
    {
        if (PublicKeys.Any(pk => pk.Certificate.PublicKeyType == kt)) return;

        switch (kt)
        {
            case I2PKeyType.KeyTypes.X25519:
                PrivateKeys.Add(eciesprivkey);
                PublicKeys.Add(eciespubkey);
                break;

            case I2PKeyType.KeyTypes.MLKEM512_X25519:
            case I2PKeyType.KeyTypes.MLKEM768_X25519:
            case I2PKeyType.KeyTypes.MLKEM1024_X25519:
            {
                // In Proposal 169, the LS2 encryption key for hybrid types is just the X25519 key (32 bytes).
                // The ML-KEM part is handled ephemeral-only in the Ratchet handshake.
                // We use the same X25519 key as the base ECIES key to ensure ECIESSessionKeyManager can decrypt it.
                var hybridPrivKey = new I2PPrivateKey(new I2PBufferCursor(eciesprivkey.ToByteArray()),
                    new I2PCertificate(kt));
                var hybridPubKey = new I2PPublicKey(new I2PBufferCursor(eciespubkey.ToByteArray()),
                    new I2PCertificate(kt));
                PrivateKeys.Add(hybridPrivKey);
                PublicKeys.Add(hybridPubKey);
            }
            break;

            case I2PKeyType.KeyTypes.ElGamal2048:
                // Already in Destination.PublicKey
                break;
        }
    }

    public Garlic DecryptMessage(GarlicMessage message)
    {
        var msgData = message.EgData.ToByteArray();

        // Try ECIES first if available
        if (EciesManager != null)
        {
            var eciesResult = EciesManager.ProcessMessage(msgData);
            if (eciesResult.Success)
            {
                Logging.LogDebug(
                    $"{Context}: DecryptMessage: ECIES decrypt OK (NewSession={eciesResult.IsNewSession}, Reply={eciesResult.IsHandshakeReply})");
                HttpProxyLogger.Inst.Log("GARLIC", Context?.Destination?.IdentHash?.Id32Short ?? "?",
                    "Decrypted",
                    $"ECIES garlic decrypted (NewSession={eciesResult.IsNewSession}, Reply={eciesResult.IsHandshakeReply}, len={msgData.Length})");
                if (eciesResult.IsNewSession)
                {
                    var session = GetSession(eciesResult.RemoteDestination);
                    session.SetPendingHandshake(msgData);
                }

                if (eciesResult.IsHandshakeReply)
                {
                    var session = GetSession(eciesResult.RemoteDestination);
                    session.HandshakeCompleted();
                }

                return TranslateEciesGarlic(eciesResult.Payload, eciesResult.RemoteDestination);
            }

            var (inbound, outbound) = EciesManager.SessionCounts;
            // Log to proxy page only when we have active outbound sessions (expecting replies)
            if (outbound > 0)
                HttpProxyLogger.Inst.Log("GARLIC", Context?.Destination?.IdentHash?.Id32Short ?? "?",
                    "Error",
                    $"ECIES decrypt failed: {eciesResult.Error ?? "?"} (len={msgData.Length}, sessions: in={inbound} out={outbound})");
            Logging.LogDebug(
                $"{Context}: DecryptMessage: ECIES failed: {eciesResult.Error ?? "?"} (len={msgData.Length}, sessions: in={inbound} out={outbound})");
        }

        // Only fall back to ElGamal if we have an ElGamal key
        if (PrivateKeys.Any(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.ElGamal2048))
            return IncommingSessions.DecryptMessage(message);

        return null;
    }

    /// <summary>
    ///     Parse ECIES garlic payload using Proposal 144 block format.
    ///     The payload contains DateTimeBlock + GarlicCloveBlock(s) + PaddingBlock.
    ///     Each GarlicCloveBlock has ECIES delivery instructions (bits 5-6) and
    ///     an I2NP message in NTCP2/short format (type + msgId + expiration + body).
    /// </summary>
    private Garlic TranslateEciesGarlic(byte[] payload, I2PIdentHash remoteHash)
    {
        try
        {
            var blocks = ECIESBlockFormat.ParseBlocks(payload);
            var cloves = new List<GarlicClove>();

            foreach (var block in blocks)
            {
                if (block is not GarlicCloveBlock garlicClove)
                    continue;

                try
                {
                    var cloveBuf = new I2PBufferCursor(garlicClove.Data);

                    // Parse ECIES delivery instructions (flag byte, bits 5-6 = delivery type)
                    var di = GarlicCloveDelivery.CreateGarlicCloveDelivery(cloveBuf);
                    if (di == null) continue;

                    // Parse I2NP message in NTCP2/short format: type(1) + msgId(4) + expiration(4) + body
                    var msgType = (I2NpMessage.MessageTypes)cloveBuf.ReadByte();
                    var msgId = cloveBuf.ReadUInt32BigEndian();
                    var expirationSeconds = cloveBuf.ReadUInt32BigEndian();

                    // I2NpUtil.GetMessage requires 16 bytes of headroom before payload
                    var payloadWithHeadroom = new byte[cloveBuf.Remaining + I2NpMessage.I2NpMaxHeaderSize];
                    cloveBuf.ReadBytes(payloadWithHeadroom, I2NpMessage.I2NpMaxHeaderSize, cloveBuf.Remaining);
                    var msg = I2NpUtil.GetMessage(msgType,
                        new I2PBufferCursor(payloadWithHeadroom, I2NpMessage.I2NpMaxHeaderSize), msgId);

                    if (msg == null) continue;

                    msg.Expiration = new I2PDate((ulong)expirationSeconds * 1000);
                    di.Message = msg;

                    cloves.Add(new GarlicClove(di, msg.Expiration) { CloveId = msgId });
                }
                catch (Exception ex)
                {
                    Logging.LogDebug($"{Context}: TranslateEciesGarlic: Error parsing clove: {ex.Message}");
                }
            }

            if (cloves.Count == 0) return null;

            var garlic = new Garlic(cloves);
            garlic.RemoteHash = remoteHash;
            return garlic;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{Context}: TranslateEciesGarlic: Failed to parse ECIES blocks: {ex.Message}");
            return null;
        }
    }

    private Session GetSession(I2PIdentHash dest)
    {
        return Sessions.GetOrAdd(
            dest, d => new Session(
                Context,
                Context.Destination,
                dest));
    }

    public GarlicMessage Encrypt(
        I2PIdentHash dest,
        IEnumerable<I2PPublicKey> remotepublickeys,
        InboundTunnel replytunnel,
        IList<GarlicClove> cloves)
    {
        var sess = GetSession(dest);
        return sess.Encrypt(remotepublickeys, replytunnel, cloves);
    }

    public void MySignedLeasesUpdated()
    {
        foreach (var sess in Sessions) sess.Value.MySignedLeasesUpdated(sess.Key);
    }

    public void LeaseSetReceived(ILeaseSet ls)
    {
        if (ls.Destination.IdentHash == Context.Destination.IdentHash)
        {
            // that is me
            Logging.LogDebug(
                $"{this}: Sessions: LeaseSetReceived: " +
                $"discarding my lease set.");
            return;
        }

        if (ls.Expire < DateTime.UtcNow)
        {
            Logging.LogDebug(
                $"{this}: Sessions: LeaseSetReceived: " +
                $"discarding expired lease set. {ls}");
            return;
        }

        var sess = GetSession(ls.Destination.IdentHash);
        sess.LeaseSetReceived(ls);
    }

    internal void DeliveryStatusReceived(DeliveryStatusMessage msg, InboundTunnel from)
    {
        foreach (var sess in Sessions) sess.Value.DeliveryStatusReceived(msg, from);
    }

    public ILeaseSet GetLeaseSet(I2PIdentHash dest)
    {
        var sess = GetSession(dest);

        if (sess?.RemoteLeaseSet is null)
        {
            var localDest = Router.GetClientDestination(dest);
            if (localDest != null)
            {
                if (localDest.SignedLeases != null)
                {
                    sess.LeaseSetReceived(localDest.SignedLeases);
                    return localDest.SignedLeases;
                }

                // Synthetic LeaseSet for local bypass
                var keys = localDest.MySessions.PublicKeys;
                if (keys != null && keys.Any())
                {
                    Logging.LogDebug($"{Context}: Sessions: Creating synthetic LeaseSet for local {dest.Id32Short}");
                    var synthetic = new I2PLeaseSet2(
                        localDest.Destination,
                        new List<I2PLease2>(),
                        keys,
                        localDest.Destination.SigningPublicKey,
                        null);
                    sess.LeaseSetReceived(synthetic);
                    return synthetic;
                }
            }

            var cachedls = NetDb.Inst.FindLeaseSet(dest);
            if (cachedls != null)
            {
                LeaseSetReceived(cachedls);
                return cachedls;
            }

            return null;
        }

        return sess.RemoteLeaseSet;
    }

    public ILease GetTunnelPair(I2PIdentHash dest, OutboundTunnel outtunnel)
    {
        var sess = GetSession(dest);
        return sess.GetTunnelPair(outtunnel);
    }

    internal void DataSentToRemote(I2PIdentHash dest)
    {
        if (Sessions.TryGetValue(dest, out var sess)) sess.DataSentToRemote(dest);
    }

    public void RemoteIsActive(I2PIdentHash dest)
    {
        if (Sessions.TryGetValue(dest, out var sess)) sess.RemoteIsActive(dest);
    }

    public void ConfirmRemoteHash(I2PIdentHash temporaryHash, I2PIdentHash realHash)
    {
        if (temporaryHash == null || realHash == null || temporaryHash == realHash) return;

        if (Sessions.TryRemove(temporaryHash, out var session))
        {
            session.UpdateRemoteDestination(realHash);
            Sessions[realHash] = session;
            EciesManager?.ConfirmRemoteHash(temporaryHash, realHash);
            Logging.LogDebug($"{Context}: Sessions: Confirmed remote hash {temporaryHash.Id32Short} -> {realHash.Id32Short}");
        }
    }

    public DatabaseLookupKeyInfo KeyGenerator(I2PIdentHash ffrouterid)
    {
        return IncommingSessions.KeyGenerator(ffrouterid);
    }

    public override string ToString()
    {
        return $"{Context} {GetType().Name}";
    }
}