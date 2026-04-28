using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Collections.Concurrent;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using GarlicClove = I2PCore.TunnelLayer.I2NP.Data.GarlicClove;

namespace I2PCore.SessionLayer;

internal class Session
{
    public static TimeSpan RemoteLeaseSetUpdateMargin = TimeSpan.FromMinutes(3);

    public static TickSpan SessionInactivityTimeout = TickSpan.Minutes(25);

    public static TickSpan WaitForLsUpdateAck = TickSpan.Seconds(45);

    internal readonly ClientDestination Context;

    private readonly EgaesSessionKeyOrigin EgaesKeys;

    private readonly TickCounter LastSendToRemote = new();

    private readonly I2PDestination MyDestination;

    private readonly TimeWindowDictionary<uint, LeaseSetUpdateAck> NotAckedLsUpdates = new(WaitForLsUpdateAck);

    private readonly TimeWindowDictionary<OutboundTunnel, ILease> OutboundRemoteLeasePairs = new(TickSpan.Minutes(1));
    private readonly I2PIdentHash RemoteDestination;

    private readonly TimeSpan TimeCompareEpsilon = TimeSpan.FromSeconds(2);


    /// <summary>
    ///     Expiry time of the newest ACKed LeaseSet transferred to RemoteDestination
    /// </summary>
    protected DateTime AcKedLeaseSetExpireTime = DateTime.MinValue;

    private byte[] _pendingHandshakeData;

    private class PendingGarlic
    {
        public IEnumerable<I2PPublicKey> PublicKeys;
        public InboundTunnel ReplyTunnel;
        public IList<GarlicClove> Cloves;
    }

    private readonly ConcurrentQueue<PendingGarlic> _outboundHandshakeQueue = new();

    internal Session(ClientDestination context, I2PDestination mydest, I2PIdentHash remotedest)
    {
        Context = context;
        MyDestination = mydest;
        RemoteDestination = remotedest;

        EgaesKeys = new EgaesSessionKeyOrigin(
            Context,
            mydest,
            remotedest);
    }

    /// <summary>
    ///     ECIES SKM - shared with SessionManager so outbound handshake tags
    ///     are visible to the inbound decrypt path.
    /// </summary>
    private ECIESSessionKeyManager EciesKeys => Context?.MySessions?.EciesManager;

    public ILeaseSet RemoteLeaseSet { get; protected set; }

    internal bool RemoteNeedsLeaseSetUpdate
    {
        get
        {
            if (Context is null)
            {
                Logging.LogWarning($"{this}: RemoteNeedsLeaseSetUpdate: Context is null!");
                return false;
            }

            var isLocal = Router.GetClientDestination(RemoteDestination) != null;
            var signed = Context.SignedLeases;

            if (signed is null)
            {
                // For local bypass, we can send a synthetic LeaseSet if we have public keys
                if (isLocal)
                {
                    return AcKedLeaseSetExpireTime == DateTime.MinValue ||
                           AcKedLeaseSetExpireTime < DateTime.UtcNow + RemoteLeaseSetUpdateMargin;
                }

                return false;
            }

            // remote never received our leases?
            if (AcKedLeaseSetExpireTime == DateTime.MinValue) return true;

            return signed.Expire > AcKedLeaseSetExpireTime + TimeCompareEpsilon;
        }
    }

    /// <summary>
    ///     Check if remote destination uses ECIES (X25519 or ML-KEM hybrid keys)
    /// </summary>
    private bool IsECIESDestination(IEnumerable<I2PPublicKey> remotepublickeys)
    {
        return remotepublickeys.Any(pk =>
            pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.X25519 ||
            pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
            pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
            pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519);
    }

    internal void SetPendingHandshake(byte[] msgData)
    {
        _pendingHandshakeData = msgData;
    }

    internal void HandshakeCompleted()
    {
        Logging.LogInformation($"{this}: Handshake completed. Flushing {_outboundHandshakeQueue.Count} queued messages.");
        while (_outboundHandshakeQueue.TryDequeue(out var pending))
        {
            var msg = EncryptECIES(pending.PublicKeys, pending.ReplyTunnel, pending.Cloves);
            if (msg != null)
            {
                Context.Send(RemoteDestination, msg);
            }
        }
    }

    internal GarlicMessage Encrypt(
        IEnumerable<I2PPublicKey> remotepublickeys,
        InboundTunnel replytunnel,
        IList<GarlicClove> cloves,
        bool checkremotelsage = true)
    {
        var isLocal = Router.GetClientDestination(RemoteDestination) != null;
        if (checkremotelsage && RemoteNeedsLeaseSetUpdate)
        {
            if (replytunnel != null || isLocal)
            {
                Logging.LogDebug($"{this}: Sending my leases to remote {RemoteDestination.Id32Short}.");
                GenerateRemoteLsUpdate(cloves, replytunnel);
            }
            else
            {
                Logging.LogWarning(
                    $"{this}: Remote needs LeaseSet update but no reply tunnel available! Bob might not be able to respond.");
            }
        }

        // Detect ECIES destination and use appropriate encryption
        if (IsECIESDestination(remotepublickeys))
        {
            if (EciesKeys != null) return EncryptECIES(remotepublickeys, replytunnel, cloves);

            Logging.LogWarning(
                $"{this}: Remote {RemoteDestination.Id32Short} is ECIES but no shared ECIES SKM available");
        }

        // Fall back to ElGamal for legacy destinations
        return EgaesKeys.Encrypt(remotepublickeys, replytunnel, cloves);
    }

    /// <summary>
    ///     Encrypt Garlic message using ECIES (Noise IK pattern)
    ///     Payload uses Proposal 144 block format (DateTimeBlock + GarlicCloveBlock + PaddingBlock)
    /// </summary>
    private GarlicMessage EncryptECIES(
        IEnumerable<I2PPublicKey> remotepublickeys,
        InboundTunnel replytunnel,
        IList<GarlicClove> cloves)
    {
        // Build ECIES Proposal 144 blocks (NOT legacy Garlic format)
        var payload = BuildECIESPayload(cloves);

        // Check if we have an existing session with this destination
        var hasSession = EciesKeys.HasOutboundSession(RemoteDestination) &&
                         EciesKeys.HasAvailableOutboundTags(RemoteDestination);

        if (!hasSession && _pendingHandshakeData == null && EciesKeys.IsOutboundHandshakeInProgress(RemoteDestination))
        {
            Logging.LogInformation($"{this}: ECIES handshake already in progress for {RemoteDestination.Id32Short}. Queuing message.");
            _outboundHandshakeQueue.Enqueue(new PendingGarlic
            {
                PublicKeys = remotepublickeys,
                ReplyTunnel = replytunnel,
                Cloves = cloves
            });
            return null;
        }

        byte[] eciesMessage = null;

        if (_pendingHandshakeData != null)
        {
            try
            {
                eciesMessage = EciesKeys.CreateHandshakeReply(RemoteDestination, _pendingHandshakeData, payload);
                _pendingHandshakeData = null;

                Logging.LogInformation(
                    $"{this}: Encrypted ECIES handshake reply to {RemoteDestination.Id32Short}: {eciesMessage.Length} bytes");
                HttpProxyLogger.Inst.Log("GARLIC", RemoteDestination.Id32Short,
                    "Sent",
                    $"ECIES Handshake Reply sent: {eciesMessage.Length} bytes, {cloves.Count} clove(s)");
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{this}: Failed to create ECIES handshake reply: {ex.Message}");
            }
        }

        if (eciesMessage == null && hasSession)
            // Use existing session with session tag
            try
            {
                var existingMsg = EciesKeys.CreateExistingSession(RemoteDestination, payload);
                eciesMessage = existingMsg.ToByteArray();

                Logging.LogDebug(
                    $"{this}: Encrypted ECIES message using existing session to {RemoteDestination.Id32Short}, {eciesMessage.Length} bytes");
            }
            catch (Exception ex)
            {
                // Fall back to new session if existing session fails
                Logging.LogWarning($"{this}: Existing ECIES session failed, creating new session: {ex.Message}");
                hasSession = false;
            }

        if (!hasSession || eciesMessage == null)
        {
            // Find best hybrid variant from remotepublickeys
            NoiseIKhfs.KEMVariant? variant = null;
            if (remotepublickeys.Any(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519))
                variant = NoiseIKhfs.KEMVariant.MLKEM1024;
            else if (remotepublickeys.Any(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519))
                variant = NoiseIKhfs.KEMVariant.MLKEM768;
            else if (remotepublickeys.Any(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519))
                variant = NoiseIKhfs.KEMVariant.MLKEM512;

            // Create new session with Noise IK or hybrid IKhfs handshake
            var x25519Key = remotepublickeys.FirstOrDefault(pk =>
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.X25519 ||
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519);

            if (x25519Key == null) x25519Key = remotepublickeys.FirstOrDefault();

            if (x25519Key == null)
            {
                Logging.LogWarning(
                    $"{this}: No public keys available for {RemoteDestination.Id32Short}, cannot encrypt.");
                return null;
            }

            var remoteKeyTypes =
                string.Join(", ", remotepublickeys.Select(pk => pk.Certificate.PublicKeyType.ToString()));
            Logging.LogInformation($"{this}: EncryptECIES: Remote has key types [{remoteKeyTypes}]. " +
                                   $"Selected {x25519Key.Certificate.PublicKeyType} " +
                                   $"(variant={variant?.ToString() ?? "plain IK"}) for {RemoteDestination.Id32Short}. " +
                                   $"Payload={payload.Length} bytes, {cloves.Count} clove(s).");

            eciesMessage = EciesKeys.CreateNewSession(RemoteDestination, x25519Key, payload, variant);

            Logging.LogInformation(
                $"{this}: Encrypted ECIES new session to {RemoteDestination.Id32Short}: {eciesMessage.Length} bytes");
            HttpProxyLogger.Inst.Log("GARLIC", RemoteDestination.Id32Short,
                "Sent",
                $"ECIES New Session sent: {eciesMessage.Length} bytes, {cloves.Count} clove(s), variant={variant?.ToString() ?? "IK"}");
        }

        // Wrap ECIES message in GarlicMessage format (I2NP type 11)
        // Format: 4-byte length + ECIES data
        var destbuf = new byte[eciesMessage.Length + I2NpMessage.I2NpMaxHeaderSize + 4];
        var writer = new I2PBufferCursor(destbuf, I2NpMessage.I2NpMaxHeaderSize);

        // Write length (big-endian)
        writer.WriteUInt32BigEndian((uint)eciesMessage.Length);

        // Write ECIES message
        writer.WriteBytes(eciesMessage);

        var totalLength = 4 + eciesMessage.Length;
        return new GarlicMessage(new I2PBufferCursor(destbuf, I2NpMessage.I2NpMaxHeaderSize, totalLength));
    }

    internal void MySignedLeasesUpdated(I2PIdentHash dest)
    {
        // Send ASAP
        AcKedLeaseSetExpireTime = DateTime.MinValue;

        if (LastSendToRemote.DeltaToNow < SessionInactivityTimeout) SendLeaseSetUpdate(dest);
    }

    public void LeaseSetReceived(ILeaseSet ls)
    {
        lock (OutboundRemoteLeasePairs)
        {
            if (RemoteLeaseSet != null
                && ls.Expire < RemoteLeaseSet.Expire + TimeCompareEpsilon)
            {
                Logging.LogDebug(
                    $"{this} Session: LeaseSetReceived: ignoring older remote LS {ls}");

                return;
            }

            Logging.LogDebug(
                $"{this} Session: LeaseSetReceived: updating remote LS {ls}");

            RemoteLeaseSet = ls;

            // Did a remote pair dissappear?
            var nolongeravailable = OutboundRemoteLeasePairs
                .Where(p => !ls.Leases.Any(l => l.TunnelId == p.Value.TunnelId
                                                && l.TunnelGw == p.Value.TunnelGw))
                .ToArray();

            foreach (var toremove in nolongeravailable) OutboundRemoteLeasePairs.TryRemove(toremove.Key, out _);
        }
    }

    internal void DeliveryStatusReceived(DeliveryStatusMessage msg, InboundTunnel from)
    {
        EgaesKeys.DeliveryStatusReceived(msg, from);

        if (NotAckedLsUpdates.TryRemove(msg.StatusMessageId, out var lsupdate))
        {
            Logging.LogDebug($"{this}: Remote LS update ACKed, expire {lsupdate.ExpireTimeForLeaseSet}");

            RemoteLeaseSetUpdateAckReceived(lsupdate.ExpireTimeForLeaseSet);
        }
    }

    internal void SendLeaseSetUpdate(I2PIdentHash dest)
    {
        if (RemoteLeaseSet is null)
            return;

        Logging.LogDebug(
            $"{this} Session: SendLeaseSetUpdate: sending LS to {dest.Id32Short}");

        var replytunnel = Context.SelectInboundTunnel();
        var cloves = GenerateRemoteLsUpdate(new List<GarlicClove>(), replytunnel);

        Context.Send(
            RemoteLeaseSet.Destination,
            Encrypt(
                RemoteLeaseSet.PublicKeys,
                replytunnel,
                cloves,
                false));
    }

    internal void DataSentToRemote(I2PIdentHash dest)
    {
        LastSendToRemote.SetNow();
    }

    internal void RemoteIsActive(I2PIdentHash dest)
    {
        if (RemoteNeedsLeaseSetUpdate
            && LastSendToRemote.DeltaToNow < SessionInactivityTimeout)
            SendLeaseSetUpdate(dest);
    }

    internal void RemoteLeaseSetUpdateAckReceived(DateTime expiration)
    {
        if (expiration > AcKedLeaseSetExpireTime) AcKedLeaseSetExpireTime = expiration;
    }

    internal ILease GetTunnelPair(OutboundTunnel outtunnel)
    {
        if (RemoteLeaseSet is null)
            return null;

        if (OutboundRemoteLeasePairs.TryGetValue(outtunnel, out var lease))
        {
            if (lease.Expire > DateTime.UtcNow) return lease;

            OutboundRemoteLeasePairs.TryRemove(outtunnel, out _);
        }

        var usedleases = OutboundRemoteLeasePairs
            .Select(p => p.Value)
            .ToHashSet();

        var unused = RemoteLeaseSet
            .Leases
            .Where(lease => !usedleases.Contains(lease))
            .ToArray();

        ILease result;

        if (unused.Length > 0)
            result = ClientDestination.SelectLease(unused);
        else
            result = ClientDestination.SelectLease(RemoteLeaseSet.Leases);

        if (result is null) return null;

        OutboundRemoteLeasePairs[outtunnel] = result;

        return result;
    }

    private IList<GarlicClove> GenerateRemoteLsUpdate(IList<GarlicClove> cloves, InboundTunnel replytunnel)
    {
        var isLocal = Router.GetClientDestination(RemoteDestination) != null;
        var signedleases = Context.SignedLeases;
        if (signedleases is null)
        {
            if (isLocal)
            {
                var keys = Context.MySessions.PublicKeys;
                if (keys != null && keys.Any())
                {
                    signedleases = new I2PLeaseSet2(
                        Context.Destination,
                        new List<I2PLease2>(),
                        keys,
                        Context.Destination.SigningPublicKey,
                        null);
                }
            }

            if (signedleases is null)
            {
                Logging.LogWarning($"{this}: GenerateRemoteLsUpdate: SignedLeases is null! Cannot send update.");
                return cloves;
            }
        }

        if (replytunnel is null && !isLocal)
        {
            Logging.LogWarning($"{this}: GenerateRemoteLsUpdate: replytunnel is null! Cannot send update.");
            return cloves;
        }

        var myleases = new DatabaseStoreMessage(signedleases);

        // Use LOCAL delivery for LeaseSet, matching Java I2P behavior.
        // The remote router stores the LeaseSet in its NetDB when it
        // receives a DatabaseStoreMessage with LOCAL delivery.
        cloves.Add(
            new GarlicClove(
                new GarlicCloveDeliveryLocal(
                    myleases)));

        if (replytunnel != null)
        {
            var lsack = new DeliveryStatusMessage(I2NpMessage.GenerateMessageId());
            cloves.Add(
                new GarlicClove(
                    new GarlicCloveDeliveryTunnel(
                        lsack,
                        replytunnel.Destination, replytunnel.GatewayTunnelId)));


            NotAckedLsUpdates[lsack.StatusMessageId] = new LeaseSetUpdateAck
            {
                ExpireTimeForLeaseSet = signedleases.Expire,
                MessageId = lsack.MessageId
            };
        }
        else
        {
            AcKedLeaseSetExpireTime = signedleases.Expire;
        }

        return cloves;
    }

    /// <summary>
    ///     Build ECIES Proposal 144 block-format payload from garlic cloves.
    ///     Format: DateTimeBlock + GarlicCloveBlock(s) + PaddingBlock
    ///     Each clove uses ECIES delivery instructions + NTCP2-format I2NP message.
    /// </summary>
    private static byte[] BuildECIESPayload(IList<GarlicClove> cloves)
    {
        var blocks = new List<Block>();

        // DateTime block (type 0)
        blocks.Add(new DateTimeBlock
        {
            Timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        });

        // GarlicClove blocks (type 11) - one per clove
        foreach (var clove in cloves)
            blocks.Add(new GarlicCloveBlock
            {
                Data = SerializeECIESClove(clove)
            });

        // Padding block (type 254) - aligned to 16 bytes
        var currentSize = 0;
        foreach (var b in blocks)
            currentSize += 3 + b.ToByteArray().Length; // 3 = type(1) + length(2)
        var padLen = 16 + (16 - (currentSize + 3) % 16) % 16;
        blocks.Add(new PaddingBlock
        {
            Data = BufUtils.RandomBytes(padLen)
        });

        return ECIESBlockFormat.BuildBlocks(blocks);
    }

    /// <summary>
    ///     Serialize a single garlic clove in ECIES/ratchet format:
    ///     delivery_instructions(variable) + type(1) + msgId(4) + expiration_seconds(4) + payload
    ///     This is the NTCP2/short I2NP format, NOT the legacy 16-byte header format.
    /// </summary>
    private static byte[] SerializeECIESClove(GarlicClove clove)
    {
        var stream = new ArrayBufferWriter<byte>();

        // Delivery instructions: mode is in bits 5-6 of the flag byte
        // (matches Java I2P DeliveryInstructions: FLAG_MODE = 0x60, mode << 5)
        switch (clove.Delivery)
        {
            case GarlicCloveDeliveryLocal:
                stream.WriteByte(0x00); // LOCAL = 0 << 5
                break;

            case GarlicCloveDeliveryDestination dd:
                stream.WriteByte(0x20); // DESTINATION = 1 << 5
                dd.Destination.Write(stream);
                break;

            case GarlicCloveDeliveryRouter dr:
                stream.WriteByte(0x40); // ROUTER = 2 << 5
                dr.Destination.Write(stream);
                break;

            case GarlicCloveDeliveryTunnel dt:
                stream.WriteByte(0x60); // TUNNEL = 3 << 5
                dt.Destination.Write(stream);
                dt.Tunnel.Write(stream);
                break;
        }

        // I2NP message in NTCP2/short format (9-byte header, not 16-byte)
        var msg = clove.Delivery.Message;
        stream.WriteByte((byte)msg.MessageType);
        stream.WriteUInt32BigEndian(msg.MessageId);
        var expirationSeconds = (uint)Math.Round(
            ((DateTime)msg.Expiration - I2PDate.RefDate).TotalSeconds);
        stream.WriteUInt32BigEndian(expirationSeconds);
        stream.WriteBlock(msg.Payload);

        return stream.WrittenSpan.ToArray();
    }

    public override string ToString()
    {
        return $"{Context} {MyDestination} -> {RemoteDestination?.Id32Short}";
    }

    private class LeaseSetUpdateAck
    {
        public DateTime ExpireTimeForLeaseSet;

        /// <summary>MessageId of the DeliveryStatusMessage of the ACK.</summary>
        public uint MessageId;
    }
}