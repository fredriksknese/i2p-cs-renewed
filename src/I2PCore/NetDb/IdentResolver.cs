using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using Block = I2PCore.SessionLayer.ECIES.Block;
using GarlicClove = I2PCore.TunnelLayer.I2NP.Data.GarlicClove;

namespace I2PCore;

public class IdentResolver
{
    public delegate void IdentResolverResultFail(I2PIdentHash key);

    public delegate void IdentResolverResultFailEx(I2PIdentHash key, IdentUpdateRequestInfo info);

    public delegate void IdentResolverResultLeaseSet(ILeaseSet ls);

    public delegate void IdentResolverResultLeaseSetEx(ILeaseSet ls, IdentUpdateRequestInfo info);

    public delegate void IdentResolverResultRouterInfo(I2PRouterInfo ri);

    public delegate void IdentResolverResultRouterInfoEx(I2PRouterInfo ri, IdentUpdateRequestInfo info);

    public enum ReceivedFloodfillResponses
    {
        NoResponse,
        Timeout,
        SearchReply,
        DatabaseStore,
        SendFailed
    }

    public const int DatabaseLookupRetriesRi = 4;
    public const int DatabaseLookupRetriesLs = 40;
    public const int DatabaseLookupSelectFloodfillCountRi = 3;
    public const int DatabaseLookupSelectFloodfillCountLs = 6;
    public static TickSpan WaitForRouterInfo = TickSpan.Seconds(15);
    public static TickSpan WaitForLeaseSet = TickSpan.Seconds(20);

    private readonly PeriodicAction CheckForTimouts = new(TickSpan.Seconds(3));
    private readonly PeriodicAction ExploreNewRouters = new(TickSpan.Seconds(15));

    private readonly TimeWindowDictionary<I2PIdentHash, IdentUpdateRequestInfo> FinishedLookups =
        new(TickSpan.Minutes(5));

    private readonly ConcurrentDictionary<I2PIdentHash, IdentUpdateRequestInfo> OutstandingQueries = new();
    private readonly ConcurrentDictionary<I2PIdentHash, ConcurrentBag<IdentUpdateRequestInfo>> WaitingForRi = new();

    public IdentResolver(NetDb db)
    {
        db.RouterInfoUpdates += NetDb_RouterInfoUpdates;
        db.LeaseSetUpdates += NetDb_LeaseSetUpdates;
        db.DatabaseSearchReplies += NetDb_DatabaseSearchReplies;
    }

    public event IdentResolverResultFail LookupFailure;
    public event IdentResolverResultRouterInfo RouterInfoReceived;
    public event IdentResolverResultLeaseSet LeaseSetReceived;

    public event IdentResolverResultFailEx LookupFailureEx;
    public event IdentResolverResultRouterInfoEx RouterInfoReceivedEx;
    public event IdentResolverResultLeaseSetEx LeaseSetReceivedEx;

    public IdentUpdateRequestInfo GetQueryInfo(I2PIdentHash key)
    {
        if (OutstandingQueries.TryGetValue(key, out var info)) return info;
        if (FinishedLookups.TryGetValue(key, out info)) return info;
        return null;
    }

    public bool LookupRouterInfo(I2PIdentHash ident)
    {
        var inprogress = true;

        var updateinfo = OutstandingQueries.GetOrAdd(
            ident, id =>
            {
                inprogress = false;
                return new IdentUpdateRequestInfo(
                    ident,
                    DatabaseLookupMessage.LookupTypes.RouterInfo);
            });

        if (inprogress)
        {
#if LOG_ALL_IDENT_LOOKUPS
                Logging.LogDebug( $"IdentResolver: Lookup of RouterInfo {ident.Id32Short} already in progress." );
#endif
            return false;
        }

#if LOG_ALL_IDENT_LOOKUPS
            Logging.Log( $"IdentResolver: Starting lookup of RouterInfo for {ident.Id32Short}." );
#endif

        SendRiDatabaseLookup(ident, updateinfo);

        return true;
    }

    public bool LookupLeaseSet(I2PIdentHash ident, ClientDestination clientContext = null, int? parallelQueries = null,
        bool useDirectQueries = false)
    {
        var inprogress = true;

        var updateinfo = OutstandingQueries.GetOrAdd(
            ident, id =>
            {
                inprogress = false;
                return new IdentUpdateRequestInfo(
                    ident,
                    DatabaseLookupMessage.LookupTypes.LeaseSet)
                {
                    ClientContext = clientContext,
                    ParallelQueries = parallelQueries,
                    UseDirectQueries = useDirectQueries
                };
            });

        if (inprogress)
        {
            Logging.LogDebug($"IdentResolver: Lookup of LeaseSet {ident.Id32Short} already in progress.");
            return false;
        }

        Logging.LogDebug($"IdentResolver: Starting lookup of LeaseSet for {ident.Id32Short}.");
        SendLsDatabaseLookup(ident, updateinfo);

        return true;
    }

    private void NetDb_DatabaseSearchReplies(DatabaseSearchReplyMessage dsm)
    {
        if (dsm == null || dsm.From == null) return;

        if (!OutstandingQueries.TryGetValue(dsm.Key, out var info)) return;

        info.UnheardFrom.TryRemove(dsm.From, out _);

        var peerCount = dsm.Peers?.Count ?? 0;
        var newCount = 0;
        var addedCount = 0;
        var alreadyTriedCount = 0;

        foreach (var router in dsm.Peers)
        {
            if (!NetDb.Inst.Contains(router))
            {
                newCount++;
                LookupRouterInfo(router);
            }

            if (!info.FloodfillResponses.ContainsKey(router) &&
                !info.FailedPeers.Contains(router) &&
                !info.PendingRi.ContainsKey(router))
            {
                lock (info.ToTry)
                {
                    info.ToTry.Add(router);
                }

                addedCount++;
            }
            else
            {
                alreadyTriedCount++;
            }
        }

        if (newCount > 0)
            Logging.LogInformation(
                $"IdentResolver: Exploration found {newCount} new routers (of {peerCount} total) from {dsm.From.Id32Short}");

        var dist = dsm.From ^ info.LookupIdent.RoutingKey;
        var distStr = BufUtils.ToBase32String(dist).Substring(0, 8);

        var detailParts = new List<string>();
        detailParts.Add($"Dist: {distStr}");
        if (peerCount == 0)
        {
            detailParts.Add("not found, 0 peers returned");
        }
        else
        {
            detailParts.Add($"{peerCount} peers");
            if (addedCount > 0) detailParts.Add($"{addedCount} new");
            if (alreadyTriedCount > 0) detailParts.Add($"{alreadyTriedCount} already tried");
        }

        var details = string.Join(", ", detailParts);

        // Collect router performance
        NetDb.Inst.Statistics.IdentResolveReply(dsm.From);

        var update = new FloodfillResponse
        {
            Floodfill = dsm.From,
            Response = ReceivedFloodfillResponses.SearchReply,
            Details = details
        };
        info.FloodfillResponses[dsm.From] = update;
        lock (info.Attempts)
        {
            if (info.Attempts.Any()) info.Attempts.Last().FloodfillResponses[dsm.From] = update;
        }
    }

    private void NetDb_LeaseSetUpdates(ILeaseSet ls)
    {
        if (!OutstandingQueries.TryRemove(ls.Destination.IdentHash, out var info)) return;
        FinishedLookups[ls.Destination.IdentHash] = info;

        // Collect router performance
        var noresponse = info.FloodfillResponses
            .Where(r => r.Value.Response == ReceivedFloodfillResponses.NoResponse);

        // Give all the credit
        foreach (var one in noresponse)
        {
            var from = one.Key;

            NetDb.Inst.Statistics.IdentResolveSuccess(from);

            var update = new FloodfillResponse
            {
                Floodfill = from,
                Response = ReceivedFloodfillResponses.DatabaseStore
            };
            info.FloodfillResponses[from] = update;
            lock (info.Attempts)
            {
                if (info.Attempts.Any()) info.Attempts.Last().FloodfillResponses[from] = update;
            }
        }

        if (ls.Expire < DateTime.UtcNow)
        {
            Logging.LogDebug($"IdentResolver: Lookup of LeaseSet " +
                             $"{ls} succeeded, but has expired. {info.Start.DeltaToNow}");

            // Put back in OutstandingQueries and keep trying
            if (OutstandingQueries.TryAdd(ls.Destination.IdentHash, info)) StartMoreQueries(info);

            return;
        }

        Logging.Log($"IdentResolver: Lookup of LeaseSet " +
                    $"{ls.Destination.IdentHash.Id32Short} succeeded. {info.Start.DeltaToNow}");

        if (LeaseSetReceived != null) ThreadPool.QueueUserWorkItem(a => LeaseSetReceived(ls));
        if (LeaseSetReceivedEx != null) ThreadPool.QueueUserWorkItem(a => LeaseSetReceivedEx(ls, info));
    }

    private void NetDb_RouterInfoUpdates(I2PRouterInfo ri)
    {
        var ident = ri.Identity.IdentHash;

        // Resume any lookups waiting for this RI
        if (WaitingForRi.TryRemove(ident, out var lookups))
            foreach (var lookup in lookups)
            {
                if (!OutstandingQueries.ContainsKey(lookup.LookupIdent)) continue;

                lookup.PendingRi.TryRemove(ident, out _);
                lock (lookup.ToTry)
                {
                    lookup.ToTry.Add(ident);
                }

                StartMoreQueries(lookup);
            }

        if (!OutstandingQueries.TryRemove(ident, out var info)) return;
        FinishedLookups[ident] = info;

        // Collect router performance
        var noresponse = info.FloodfillResponses
            .Where(r => r.Value.Response == ReceivedFloodfillResponses.NoResponse);

        // Give all the credit
        foreach (var one in noresponse)
        {
            var from = one.Key;

            NetDb.Inst.Statistics.IdentResolveSuccess(from);

            var update = new FloodfillResponse
            {
                Floodfill = from,
                Response = ReceivedFloodfillResponses.DatabaseStore
            };
            info.FloodfillResponses[from] = update;
            lock (info.Attempts)
            {
                if (info.Attempts.Any()) info.Attempts.Last().FloodfillResponses[from] = update;
            }
        }

        Logging.Log($"IdentResolver: Lookup of RouterInfo " +
                    $"{ri.Identity.IdentHash.Id32Short} succeeded. {info.Start.DeltaToNow}");

        if (RouterInfoReceived != null) ThreadPool.QueueUserWorkItem(a => RouterInfoReceived(ri));
        if (RouterInfoReceivedEx != null) ThreadPool.QueueUserWorkItem(a => RouterInfoReceivedEx(ri, info));
    }

    public void Run()
    {
        CheckForTimouts.Do(CheckTimeouts);
        ExploreNewRouters.Do(ExplorationRouterLookup);
    }

    private void SendRiDatabaseLookup(I2PIdentHash ident, IdentUpdateRequestInfo info)
    {
        var excluded = IdentUpdateRequestInfo.AlreadyQueried.Select(d => d.Key).ToHashSet();
        var allFf = NetDb.Inst.GetClosestFloodfill(
            ident, 10 + 3 * info.Retries, excluded, true);

        lock (info.ToTry)
        {
            foreach (var ff in allFf) info.ToTry.Add(ff);
        }

        StartMoreQueries(info);
    }

    private void SendOneRiDatabaseLookup(IdentUpdateRequestInfo info, I2PIdentHash oneff)
    {
        var ident = info.LookupIdent;
        var excluded = IdentUpdateRequestInfo.AlreadyQueried.Select(d => d.Key).ToHashSet();
        var connectedRouters = TransportProvider.Inst.GetConnectedRouterHashes().ToHashSet();

        var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.RequireExploratory)
                        ?? TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.AllowExploratory);
        var replytunnel = TunnelProvider.Inst.GetEstablishedInboundTunnel(TunnelPoolSelection.RequireExploratory)
                          ?? TunnelProvider.Inst.GetEstablishedInboundTunnel(TunnelPoolSelection.AllowExploratory);
        var useTunnels = outtunnel != null && replytunnel != null;

        try
        {
            DatabaseLookupMessage msg;

            info.UnheardFrom[oneff] = TickCounter.Now;
            var dist = oneff ^ info.LookupIdent.RoutingKey;
            var distStr = BufUtils.ToBase32String(dist).Substring(0, 8);

            var resp = new FloodfillResponse { Floodfill = oneff, Details = $"Dist: {distStr}" };
            info.FloodfillResponses[oneff] = resp;

            lock (info.Attempts)
            {
                var lastAttempt = info.Attempts.LastOrDefault();
                if (lastAttempt == null || lastAttempt.Details != null ||
                    lastAttempt.OutboundTunnelGateway != outtunnel?.Destination ||
                    lastAttempt.InboundTunnelGateway != replytunnel?.Destination)
                {
                    lastAttempt = new LookupAttempt
                    {
                        OutboundTunnelGateway = outtunnel?.Destination,
                        OutboundTunnelId = outtunnel?.SendTunnelId is not null ? (uint)outtunnel.SendTunnelId : null,
                        InboundTunnelGateway = replytunnel?.Destination,
                        InboundTunnelId = replytunnel?.GatewayTunnelId is not null
                            ? (uint)replytunnel.GatewayTunnelId
                            : null
                    };
                    info.Attempts.Add(lastAttempt);
                }

                lastAttempt.FloodfillResponses[oneff] = resp;
            }

            if (useTunnels)
            {
                msg = new DatabaseLookupMessage(
                    ident,
                    replytunnel.Destination,
                    replytunnel.GatewayTunnelId,
                    DatabaseLookupMessage.LookupTypes.RouterInfo,
                    excluded);
                outtunnel.Send(new TunnelMessageRouter(msg, oneff));
            }
            else
            {
                msg = new DatabaseLookupMessage(
                    ident,
                    RouterContext.Inst.MyRouterIdentity.IdentHash,
                    DatabaseLookupMessage.LookupTypes.RouterInfo,
                    excluded);

                if (!TransportProvider.Send(oneff, msg))
                {
                    resp.Response = ReceivedFloodfillResponses.SendFailed;
                    resp.Details = "TransportProvider.Send returned false (unresolvable or connection failed)";
                    info.UnheardFrom.TryRemove(oneff, out _);
                    info.FailedPeers.Add(oneff);
                }
            }

            IdentUpdateRequestInfo.AlreadyQueried[oneff] = 1;

            Logging.LogInformation(
                $"IdentResolver: RI lookup {ident.Id32Short} -> ff {oneff.Id32Short} ({(useTunnels ? "tunnel" : "direct")})");
        }
        catch (Exception ex)
        {
            Logging.Log("SendOneRiDatabaseLookup", ex);
        }
    }

    private void SendLsDatabaseLookup(I2PIdentHash ident, IdentUpdateRequestInfo info)
    {
        var excluded = info.FloodfillResponses.Keys.ToHashSet();
        var queryCount = info.ParallelQueries ?? DatabaseLookupSelectFloodfillCountLs;
        var allFf = NetDb.Inst.GetClosestFloodfill(
            ident,
            queryCount + 2 * info.Retries,
            excluded,
            true);

        lock (info.ToTry)
        {
            foreach (var ff in allFf) info.ToTry.Add(ff);
        }

        StartMoreQueries(info);
    }

    private void SendOneLsDatabaseLookup(IdentUpdateRequestInfo info, I2PIdentHash oneffid)
    {
        var ident = info.LookupIdent;
        try
        {
            // Select tunnels: prefer client's own tunnels, fall back to exploratory tunnels.
            OutboundTunnel outboundTunnel = null;
            InboundTunnel inboundReplyTunnel = null;

            var useTunnels = !info.UseDirectQueries;

            if (useTunnels)
            {
                if (info.ClientContext != null)
                {
                    outboundTunnel = info.ClientContext.SelectOutboundTunnel();
                    inboundReplyTunnel = info.ClientContext.SelectInboundTunnel();
                }

                outboundTunnel ??=
                    TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.RequireExploratory)
                    ?? TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.AllowExploratory);

                inboundReplyTunnel ??=
                    TunnelProvider.Inst.GetEstablishedInboundTunnel(TunnelPoolSelection.RequireExploratory)
                    ?? TunnelProvider.Inst.GetEstablishedInboundTunnel(TunnelPoolSelection.AllowExploratory);

                if (outboundTunnel == null || inboundReplyTunnel == null)
                {
                    Logging.LogDebug(
                        $"IdentResolver: LS lookup {ident.Id32Short} -> ff {oneffid.Id32Short} deferred - no tunnels");
                    return;
                }
            }

            var ri = NetDb.Inst[oneffid];
            if (ri == null)
            {
                WaitingForRi.GetOrAdd(oneffid, _ => new ConcurrentBag<IdentUpdateRequestInfo>()).Add(info);
                info.PendingRi.TryAdd(oneffid, 0);

                // Double check to avoid race condition
                if (NetDb.Inst[oneffid] != null)
                    if (WaitingForRi.TryRemove(oneffid, out _))
                    {
                        info.PendingRi.TryRemove(oneffid, out _);
                        lock (info.ToTry)
                        {
                            info.ToTry.Add(oneffid);
                        }
                    }

                Logging.LogDebug(
                    $"IdentResolver: LS lookup {ident.Id32Short} -> ff {oneffid.Id32Short} waiting for RouterInfo");
                return;
            }

            var excluded = info.FloodfillResponses.Keys.ToHashSet();

            var ffKeyType = ri.Identity.Certificate.PublicKeyType;
            var isEcies = ffKeyType == I2PKeyType.KeyTypes.X25519
                          || ffKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519
                          || ffKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519
                          || ffKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519;

            I2NpMessage outMsg;
            outMsg = isEcies
                ? CreateEciesWrappedLookup(ident, inboundReplyTunnel, excluded, ri, oneffid)
                : CreateElGamalWrappedLookup(ident, inboundReplyTunnel, excluded, ri, oneffid);

            if (outMsg == null)
            {
                if (inboundReplyTunnel != null)
                    outMsg = new DatabaseLookupMessage(
                        ident,
                        inboundReplyTunnel.Destination,
                        inboundReplyTunnel.GatewayTunnelId,
                        DatabaseLookupMessage.LookupTypes.LeaseSet,
                        excluded);
                else
                    outMsg = new DatabaseLookupMessage(
                        ident,
                        RouterContext.Inst.MyRouterIdentity.IdentHash,
                        DatabaseLookupMessage.LookupTypes.LeaseSet,
                        excluded);
            }

            info.UnheardFrom[oneffid] = TickCounter.Now;
            var dist = oneffid ^ info.LookupIdent.RoutingKey;
            var distStr = BufUtils.ToBase32String(dist).Substring(0, 8);

            var resp = new FloodfillResponse { Floodfill = oneffid, Details = $"Dist: {distStr}" };
            info.FloodfillResponses[oneffid] = resp;

            lock (info.Attempts)
            {
                var lastAttempt = info.Attempts.LastOrDefault();
                if (lastAttempt == null || lastAttempt.Details != null ||
                    lastAttempt.OutboundTunnelGateway != outboundTunnel?.Destination ||
                    lastAttempt.InboundTunnelGateway != inboundReplyTunnel?.Destination)
                {
                    lastAttempt = new LookupAttempt
                    {
                        OutboundTunnelGateway = outboundTunnel?.Destination,
                        OutboundTunnelId = outboundTunnel?.SendTunnelId is not null
                            ? (uint)outboundTunnel.SendTunnelId
                            : null,
                        InboundTunnelGateway = inboundReplyTunnel?.Destination,
                        InboundTunnelId = inboundReplyTunnel?.GatewayTunnelId is not null
                            ? (uint)inboundReplyTunnel.GatewayTunnelId
                            : null
                    };
                    info.Attempts.Add(lastAttempt);
                }

                lastAttempt.FloodfillResponses[oneffid] = resp;
            }

            if (useTunnels)
            {
                outboundTunnel.Send(new TunnelMessageRouter(outMsg, oneffid));
            }
            else
            {
                if (!TransportProvider.Send(oneffid, outMsg))
                {
                    resp.Response = ReceivedFloodfillResponses.SendFailed;
                    resp.Details = "TransportProvider.Send returned false (unresolvable or connection failed)";
                    info.UnheardFrom.TryRemove(oneffid, out _);
                    info.FailedPeers.Add(oneffid);
                }
            }

            Logging.LogInformation(
                $"IdentResolver: LS lookup {ident.Id32Short} -> ff {oneffid.Id32Short} ({(isEcies ? "ECIES" : "ElG")} garlic-wrapped, {(useTunnels ? "tunnel" : "direct")})");
            IdentUpdateRequestInfo.AlreadyQueried[oneffid] = 1;
        }
        catch (Exception ex)
        {
            Logging.Log("SendOneLsDatabaseLookup", ex);
        }
    }

    /// <summary>
    ///     Create an ECIES garlic-wrapped DatabaseLookupMessage for LS lookups.
    ///     Mirrors Java I2P IterativeSearchJob.sendQuery() for ECIES floodfills:
    ///     1. Generate reply session (ratchet tag + key) so FF encrypts the reply
    ///     2. Set the reply session on the DLM
    ///     3. Garlic-wrap the DLM to the floodfill's X25519 public key using Noise N
    /// </summary>
    private I2NpMessage CreateEciesWrappedLookup(
        I2PIdentHash ident,
        InboundTunnel replyTunnel,
        ICollection<I2PIdentHash> excluded,
        I2PRouterInfo ri,
        I2PIdentHash ffHash)
    {
        try
        {
            var ffPubKey = ri.GetECIESPublicKey();
            if (ffPubKey == null || ffPubKey.Length != 32)
            {
                Logging.LogWarning($"IdentResolver: ff {ffHash.Id32Short} has no ECIES public key");
                return null;
            }

            // Generate a one-time reply session (ratchet tag + key).
            // The floodfill will use these to encrypt its DatabaseStoreMessage reply.
            // Java: MessageWrapper.generateSession(ctx, skm, SINGLE_SEARCH_MSG_TIME, false)
            var replyKey = BufUtils.RandomBytes(32);
            var ratchetTag = SessionTag.Generate();

            // Register the one-time session so we can decrypt the reply when it arrives
            var eciesProcessor = Router.EciesRouterProcessor;
            eciesProcessor?.SessionManager?.RegisterOneTimeSession(ratchetTag, replyKey);

            // Build the DLM with ECIES reply encryption.
            // The DLM includes: Ecies flag + Encryption flag + reply key (symmetric) + ratchet tag (8 bytes)
            // Java: dlm.setReplySession(sess.key, sess.rtag)
            var replyKeyInfo = new DatabaseLookupKeyInfo
            {
                EncryptionFlag = true,
                EciesFlag = true,
                ReplyKey = new I2PByteBlock(replyKey),
                Tags = new[] { new I2PByteBlock(ratchetTag.ToByteArray()) }
            };

            DatabaseLookupMessage dlm;
            if (replyTunnel != null)
                dlm = new DatabaseLookupMessage(
                    ident,
                    replyTunnel.Destination,
                    replyTunnel.GatewayTunnelId,
                    DatabaseLookupMessage.LookupTypes.LeaseSet,
                    excluded,
                    replyKeyInfo);
            else
                dlm = new DatabaseLookupMessage(
                    ident,
                    RouterContext.Inst.MyRouterIdentity.IdentHash,
                    DatabaseLookupMessage.LookupTypes.LeaseSet,
                    excluded,
                    replyKeyInfo);

            // Garlic-wrap the DLM to the floodfill's ECIES public key using Noise N.
            // Java: outMsg = MessageWrapper.wrap(ctx, dlm, ri)
            // This creates a GarlicMessage containing the DLM as a local-delivery clove.
            var garlicMsg = WrapInEciesGarlic(dlm, ffPubKey);

            Logging.LogDebug($"IdentResolver: ECIES garlic-wrapped DLM for {ident.Id32Short} to ff {ffHash.Id32Short}");
            return garlicMsg;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"IdentResolver: ECIES garlic wrap failed for ff {ffHash.Id32Short}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    ///     Wrap a DatabaseLookupMessage in an ECIES garlic message (Noise N).
    ///     Uses the same ECIES block format as TunnelProvider.CreateECIESGarlicMessage().
    ///     The clove uses local delivery instructions so the floodfill processes the DLM locally.
    /// </summary>
    private static GarlicMessage WrapInEciesGarlic(DatabaseLookupMessage dlm, byte[] ffPublicKey)
    {
        // Build the garlic clove with local delivery instructions.
        // ECIES clove format (per Proposal 144 / readBytesRatchet):
        //   DeliveryInstructions(1 byte: 0x00 = local) + type(1) + msgID(4) + expiration_secs(4) + payload
        var cloveStream = new ArrayBufferWriter<byte>();
        cloveStream.WriteByte(0); // Local delivery
        cloveStream.WriteByte((byte)dlm.MessageType);
        cloveStream.WriteBlock(BufUtils.Flip32Bl(dlm.MessageId));
        var expirationSecs =
            (uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20); // 20s like Java SINGLE_SEARCH_MSG_TIME
        cloveStream.WriteBlock(BufUtils.Flip32Bl(expirationSecs));
        cloveStream.WriteBlock(dlm.Payload);

        // Build ECIES blocks: DateTime + GarlicClove + Padding
        var blocks = new List<Block>
        {
            new DateTimeBlock { Timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
            new GarlicCloveBlock { Data = cloveStream.WrittenSpan.ToArray() },
            new PaddingBlock { Data = BufUtils.RandomBytes(16 + BufUtils.RandomInt(32)) }
        };

        var plaintext = ECIESBlockFormat.BuildBlocks(blocks);

        // Encrypt using Noise N to the floodfill's X25519 public key
        var noiseN = NoiseN.CreateInitiator(ffPublicKey);
        var encrypted = noiseN.CreateMessage(plaintext);
        noiseN.Dispose();

        // The Noise N output IS the garlic payload (no tag prefix for new sessions).
        // Wrap in GarlicMessage which adds the 4-byte length prefix.
        return new GarlicMessage(encrypted);
    }

    /// <summary>
    ///     Create an ElGamal garlic-wrapped DatabaseLookupMessage for legacy floodfills.
    ///     Java: MessageWrapper.wrap(ctx, dlm, ri) with ElGamal encryption.
    /// </summary>
    private I2NpMessage CreateElGamalWrappedLookup(
        I2PIdentHash ident,
        InboundTunnel replyTunnel,
        ICollection<I2PIdentHash> excluded,
        I2PRouterInfo ri,
        I2PIdentHash ffHash)
    {
        try
        {
            // For ElGamal floodfills, create a plain DLM without reply encryption
            // (ElGamal reply encryption uses AES session tags which is complex;
            // send the DLM garlic-wrapped but with unencrypted reply for now).
            DatabaseLookupMessage dlm;
            if (replyTunnel != null)
                dlm = new DatabaseLookupMessage(
                    ident,
                    replyTunnel.Destination,
                    replyTunnel.GatewayTunnelId,
                    DatabaseLookupMessage.LookupTypes.LeaseSet,
                    excluded);
            else
                dlm = new DatabaseLookupMessage(
                    ident,
                    RouterContext.Inst.MyRouterIdentity.IdentHash,
                    DatabaseLookupMessage.LookupTypes.LeaseSet,
                    excluded);

            // Garlic-wrap using ElGamal to the floodfill's public key
            var sessionkey = new I2PSessionKey();
            var clove = new GarlicClove(new GarlicCloveDeliveryLocal(dlm));
            var garlic = new Garlic(
                new I2PDate(DateTime.UtcNow.AddSeconds(20)),
                clove);

            var garlicMsg = Garlic.EgEncryptGarlic(
                garlic,
                ri.Identity.PublicKey,
                sessionkey,
                new List<I2PSessionTag>());

            Logging.LogDebug(
                $"IdentResolver: ElGamal garlic-wrapped DLM for {ident.Id32Short} to ff {ffHash.Id32Short}");
            return garlicMsg;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"IdentResolver: ElGamal garlic wrap failed for ff {ffHash.Id32Short}: {ex.Message}");
            return null;
        }
    }

    /*
     Exploration

     Exploration is a special form of netdb lookup, where a router attempts to learn about new routers.
     It does this by sending a floodfill router a I2NP DatabaseLookupMessage, looking for a random key.
     As this lookup will fail, the floodfill would normally respond with a I2NP DatabaseSearchReplyMessage
     containing hashes of floodfill routers close to the key. This would not be helpful, as the requesting
     router probably already knows those floodfills, and it would be impractical to add ALL floodfill
     routers to the "don't include" field of the lookup. For an exploration query, the requesting router
     adds a router hash of all zeros to the "don't include" field of the DatabaseLookupMessage.

     The floodfill will then respond only with non-floodfill routers close to the requested key.

     https://geti2p.net/en/docs/how/network-database
     *
        11  => exploration lookup, return DatabaseSearchReplyMessage
                containing non-floodfill routers only (replaces an
                excludedPeer of all zeroes)
     https://geti2p.net/spec/i2np#databaselookup
     */
    private void ExplorationRouterLookup()
    {
        // Adapt exploration frequency based on router count (matches Java I2P StartExplorersJob)
        var routerCount = NetDb.Inst.RouterCount;
        if (routerCount > 1000)
            ExploreNewRouters.Frequency = TickSpan.Minutes(3);
        else if (routerCount > 500)
            ExploreNewRouters.Frequency = TickSpan.Seconds(45);
        else
            // Aggressive exploration when < 500 routers
            ExploreNewRouters.Frequency = TickSpan.Seconds(15);

        // Get an inbound tunnel for receiving replies.
        // For firewalled routers, MUST use a real (non-zero-hop) tunnel because
        // floodfills can't connect directly to us to deliver the reply.
        InboundTunnel replyTunnel;
        if (RouterContext.Inst.IsFirewalled)
        {
            // Get only real (non-zero-hop) inbound tunnels
            var realTunnels = TunnelProvider.Inst.GetInboundTunnels()
                .Where(t => t is not ZeroHopTunnel)
                .ToArray();

            if (realTunnels.Length == 0)
            {
                Logging.LogDebug("IdentResolver: Exploration skipped - no real inbound tunnels (firewalled)");
                return;
            }

            replyTunnel = realTunnels[BufUtils.RandomInt(realTunnels.Length)];
        }
        else
        {
            replyTunnel = TunnelProvider.Inst.GetEstablishedInboundTunnel(TunnelPoolSelection.RequireExploratory)
                          ?? TunnelProvider.Inst.GetEstablishedInboundTunnel(TunnelPoolSelection.AllowExploratory);
        }

        if (replyTunnel == null)
        {
            Logging.LogDebug("IdentResolver: Exploration skipped - no inbound tunnels");
            return;
        }

        // For firewalled/hidden routers: prefer direct transport with reply tunnel.
        // This is more reliable than outbound tunnel delivery because:
        // Always prefer established exploratory tunnels for anonymity and reliability.
        // Firewalled routers MUST use tunnels for reliable NetDb updates, unless no tunnels 
        // are established yet (bootstrap).
        var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.RequireExploratory)
                        ?? TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.AllowExploratory);

        var useTunnels = outtunnel != null && replyTunnel != null;

        // Send exploration queries to multiple floodfills when our NetDb is small
        var queriesPerRound = routerCount < 200 ? 3 : routerCount < 500 ? 2 : 1;

        // For direct transport mode: STRONGLY prefer floodfills we're already connected to.
        // New connections fail ~85% of the time, so sending to unconnected floodfills usually
        // means the query never reaches the floodfill.
        var connectedRouters = TransportProvider.Inst.GetConnectedRouterHashes().ToHashSet();
        var allFloodfills = NetDb.Inst.GetClosestFloodfill(new I2PIdentHash(true), 50, null);
        var connectedFloodfills = allFloodfills.Where(ff => connectedRouters.Contains(ff)).ToArray();

        for (var q = 0; q < queriesPerRound; q++)
        {
            var ident = new I2PIdentHash(true);

            // Select floodfill: prefer connected, fall back to any
            I2PIdentHash[] ff;
            if (RouterContext.Inst.IsFirewalled && !useTunnels)
            {
                // Firewalled and NO tunnels: MUST use a connected floodfill
                if (connectedFloodfills.Length == 0)
                {
                    Logging.LogDebug("IdentResolver: Exploration deferred - no connected floodfills");
                    return;
                }

                var chosen = connectedFloodfills[BufUtils.RandomInt(connectedFloodfills.Length)];
                ff = new[] { chosen };
            }
            else
            {
                // Through tunnels or reachable: query multiple floodfills (standard)
                ff = BufUtils.Shuffle(NetDb.Inst.GetClosestFloodfill(ident, 10, null))
                    .Take(DatabaseLookupSelectFloodfillCountRi)
                    .ToArray();
            }

            foreach (var oneff in ff)
            {
                DatabaseLookupMessage msg;
                string mode;

                if (useTunnels)
                {
                    // Through tunnels: specify reply tunnel
                    msg = new DatabaseLookupMessage(
                        ident,
                        replyTunnel.Destination,
                        replyTunnel.GatewayTunnelId,
                        DatabaseLookupMessage.LookupTypes.Exploration,
                        new I2PIdentHash[] { new(false) });
                    mode = "tunnels";
                }
                else if (connectedRouters.Contains(oneff))
                {
                    // Direct to connected floodfill: specify our IdentHash as "from"
                    // so the floodfill responds on the SAME NTCP2 connection.
                    // This is the most reliable method for firewalled routers.
                    msg = new DatabaseLookupMessage(
                        ident,
                        RouterContext.Inst.MyRouterIdentity.IdentHash,
                        DatabaseLookupMessage.LookupTypes.Exploration,
                        new I2PIdentHash[] { new(false) });
                    mode = "direct-connected";
                }
                else
                {
                    // Direct to unconnected floodfill: specify reply tunnel
                    msg = new DatabaseLookupMessage(
                        ident,
                        replyTunnel.Destination,
                        replyTunnel.GatewayTunnelId,
                        DatabaseLookupMessage.LookupTypes.Exploration,
                        new I2PIdentHash[] { new(false) });
                    mode = "direct+replyTunnel";
                }

                Logging.LogDebug($"IdentResolver: Exploration {ident.Id32Short} -> ff {oneff.Id32Short} ({mode})");

                try
                {
                    if (useTunnels)
                        outtunnel.Send(new TunnelMessageRouter(msg, oneff));
                    else
                        TransportProvider.Send(oneff, msg);
                }
                catch (Exception ex)
                {
                    Logging.Log(ex);
                }
            }
        }
    }

    private void CheckTimeouts()
    {
        foreach (var info in OutstandingQueries.Values.ToArray())
        {
            if (info == null) continue;

            // Overall timeout check (120 seconds for NetDbLookup page consistency)
            if (info.Start.DeltaToNow > TickSpan.Seconds(120))
            {
                FailLookup(info, "overall timeout");
                continue;
            }

            // Per-peer timeout check (Java uses 3s, we use 4s for safety)
            var peersToFail = info.UnheardFrom
                .Where(kvp => kvp.Value.DeltaToNow > TickSpan.Seconds(4))
                .Select(kvp => kvp.Key)
                .ToArray();

            foreach (var peer in peersToFail)
            {
                info.UnheardFrom.TryRemove(peer, out _);
                info.FailedPeers.Add(peer);

                if (info.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet)
                    NetDb.Inst.Statistics.IdentResolveLsTimeout(peer);
                else
                    NetDb.Inst.Statistics.IdentResolveRiTimeout(peer);

                var dist = peer ^ info.LookupIdent.RoutingKey;
                var distStr = BufUtils.ToBase32String(dist).Substring(0, 8);

                var update = new FloodfillResponse
                {
                    Floodfill = peer,
                    Response = ReceivedFloodfillResponses.Timeout,
                    Details = $"Dist: {distStr}"
                };
                info.FloodfillResponses[peer] = update;
                lock (info.Attempts)
                {
                    if (info.Attempts.Any()) info.Attempts.Last().FloodfillResponses[peer] = update;
                }
            }

            // Start more queries if we have capacity and targets
            StartMoreQueries(info);

            // If we have no active queries and nothing left to try, it's a failure
            if (info.UnheardFrom.IsEmpty && !info.ToTry.Any() && info.PendingRi.IsEmpty)
                FailLookup(info, "no more floodfills to try");
        }
    }


    private void StartMoreQueries(IdentUpdateRequestInfo info)
    {
        var parallelLimit = info.ParallelQueries ?? (info.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet
            ? DatabaseLookupSelectFloodfillCountLs
            : DatabaseLookupSelectFloodfillCountRi);

        // If we've exhausted our current candidate list, try getting more from NetDb
        lock (info.ToTry)
        {
            if (!info.ToTry.Any() && info.UnheardFrom.Count < parallelLimit)
            {
                var maxRetries = info.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet
                    ? DatabaseLookupRetriesLs
                    : DatabaseLookupRetriesRi;
                if (info.Retries < maxRetries)
                {
                    info.Retries++;
                    var excluded = info.FloodfillResponses.Keys.Union(info.FailedPeers).ToHashSet();
                    var moreFf = NetDb.Inst.GetClosestFloodfill(
                        info.LookupIdent,
                        parallelLimit + 2 * info.Retries,
                        excluded,
                        true);

                    foreach (var ff in moreFf) info.ToTry.Add(ff);

                    if (moreFf.Any())
                        Logging.LogDebug(
                            $"IdentResolver: {info.LookupIdent.Id32Short} iterative search expanded (retry {info.Retries}, found {moreFf.Count()} more candidates)");
                }
            }
        }

        while (info.UnheardFrom.Count < parallelLimit)
        {
            I2PIdentHash target = null;
            lock (info.ToTry)
            {
                if (info.ToTry.Any())
                {
                    target = info.ToTry.First();
                    info.ToTry.Remove(target);
                }
            }

            if (target == null) break;

            if (info.FloodfillResponses.ContainsKey(target) ||
                info.FailedPeers.Contains(target) ||
                info.PendingRi.ContainsKey(target)) continue;

            if (info.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet)
                SendOneLsDatabaseLookup(info, target);
            else
                SendOneRiDatabaseLookup(info, target);
        }
    }

    private void FailLookup(IdentUpdateRequestInfo info, string reason)
    {
        var isLeaseSet = info.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet;

        if (OutstandingQueries.TryRemove(info.LookupIdent, out _))
        {
            FinishedLookups[info.LookupIdent] = info;

            if (!isLeaseSet)
            {
                var ident = info.LookupIdent;
                if (WaitingForRi.TryRemove(ident, out var lookups))
                    foreach (var lookup in lookups)
                    {
                        lookup.PendingRi.TryRemove(ident, out _);
                        lookup.FailedPeers.Add(ident);

                        var dist = ident ^ lookup.LookupIdent.RoutingKey;
                        var distStr = BufUtils.ToBase32String(dist).Substring(0, 8);

                        var ffResp = new FloodfillResponse
                        {
                            Floodfill = ident,
                            Response = ReceivedFloodfillResponses.SendFailed,
                            Details = $"Dist: {distStr}, RouterInfo lookup failed"
                        };
                        lookup.FloodfillResponses[ident] = ffResp;
                        lock (lookup.Attempts)
                        {
                            if (lookup.Attempts.Any()) lookup.Attempts.Last().FloodfillResponses[ident] = ffResp;
                        }

                        // Check if this was the last thing it was waiting for
                        if (lookup.UnheardFrom.IsEmpty && !lookup.ToTry.Any() && lookup.PendingRi.IsEmpty)
                            FailLookup(lookup, "no more floodfills to try (after RI lookup failure)");
                    }
            }

            Logging.Log(string.Format("IdentResolver: Lookup of {0} {1} failed: {2}",
                isLeaseSet ? "LeaseSet" : "RouterInfo",
                info.LookupIdent.Id32Short, reason));

            if (LookupFailure != null) ThreadPool.QueueUserWorkItem(a => LookupFailure(info.LookupIdent));
            if (LookupFailureEx != null) ThreadPool.QueueUserWorkItem(a => LookupFailureEx(info.LookupIdent, info));
        }
    }

    public class XORComparator : IComparer<I2PIdentHash>
    {
        private readonly I2PRoutingKey _routingKey;

        public XORComparator(I2PRoutingKey routingKey)
        {
            _routingKey = routingKey;
        }

        public int Compare(I2PIdentHash x, I2PIdentHash y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;
            var dx = x ^ _routingKey;
            var dy = y ^ _routingKey;
            var cmp = dx.CompareTo(dy);
            return cmp != 0 ? cmp : x.CompareTo(y);
        }
    }

    public class FloodfillResponse
    {
        public string Details;
        public I2PIdentHash Floodfill;
        public ReceivedFloodfillResponses Response = ReceivedFloodfillResponses.NoResponse;
    }

    public class LookupAttempt
    {
        public readonly TickCounter Start = TickCounter.Now;
        public string Details;
        public ConcurrentDictionary<I2PIdentHash, FloodfillResponse> FloodfillResponses = new();
        public I2PIdentHash InboundTunnelGateway;
        public uint? InboundTunnelId;
        public I2PIdentHash OutboundTunnelGateway;
        public uint? OutboundTunnelId;
    }

    public class IdentUpdateRequestInfo
    {
        public static TimeWindowDictionary<I2PIdentHash, object> AlreadyQueried = new(TickSpan.Seconds(30));
        public readonly TickSpan DatabaseLookupWaitTime;
        public readonly I2PIdentHash LookupIdent;
        public readonly DatabaseLookupMessage.LookupTypes LookupType;
        public readonly TickCounter Start = TickCounter.Now;
        public List<LookupAttempt> Attempts = new();

        public ClientDestination ClientContext;
        public HashSet<I2PIdentHash> FailedPeers = new();
        public int? ParallelQueries;
        public ConcurrentDictionary<I2PIdentHash, byte> PendingRi = new();

        public int Retries;

        public SortedSet<I2PIdentHash> ToTry;
        public ConcurrentDictionary<I2PIdentHash, TickCounter> UnheardFrom = new();
        public bool UseDirectQueries;

        public IdentUpdateRequestInfo(
            I2PIdentHash id,
            DatabaseLookupMessage.LookupTypes lookuptype)
        {
            FloodfillResponses = new ConcurrentDictionary<I2PIdentHash, FloodfillResponse>();
            LookupIdent = id;
            LookupType = lookuptype;
            Retries = 0;

            ToTry = new SortedSet<I2PIdentHash>(new XORComparator(id.RoutingKey));

            switch (lookuptype)
            {
                case DatabaseLookupMessage.LookupTypes.RouterInfo:
                    DatabaseLookupWaitTime = WaitForRouterInfo;
                    break;

                case DatabaseLookupMessage.LookupTypes.Normal:
                case DatabaseLookupMessage.LookupTypes.LeaseSet:
                    DatabaseLookupWaitTime = WaitForLeaseSet;
                    break;
            }
        }

        public ConcurrentDictionary<I2PIdentHash, FloodfillResponse> FloodfillResponses { get; set; }

        public void StartLookup(
            IEnumerable<I2PIdentHash> floodfills,
            OutboundTunnel outtunnel = null,
            InboundTunnel intunnel = null)
        {
            lock (Attempts)
            {
                if (Attempts.Any())
                {
                    var last = Attempts.Last();
                    foreach (var resp in FloodfillResponses) last.FloodfillResponses[resp.Key] = resp.Value;
                }
            }

            FloodfillResponses = new ConcurrentDictionary<I2PIdentHash, FloodfillResponse>(
                floodfills.Select(ff => new KeyValuePair<I2PIdentHash, FloodfillResponse>(
                    ff,
                    new FloodfillResponse())));

            var attempt = new LookupAttempt
            {
                OutboundTunnelGateway = outtunnel?.Destination,
                OutboundTunnelId = outtunnel?.SendTunnelId is not null ? (uint)outtunnel.SendTunnelId : null,
                InboundTunnelGateway = intunnel?.Destination,
                InboundTunnelId = intunnel?.GatewayTunnelId is not null ? (uint)intunnel.GatewayTunnelId : null
            };
            foreach (var ff in floodfills) attempt.FloodfillResponses[ff] = new FloodfillResponse { Floodfill = ff };
            lock (Attempts)
            {
                Attempts.Add(attempt);
            }

            Start.SetNow();
        }

        public void RecordError(string error)
        {
            lock (Attempts)
            {
                Attempts.Add(new LookupAttempt
                {
                    Details = error
                });
            }
        }
    }
}