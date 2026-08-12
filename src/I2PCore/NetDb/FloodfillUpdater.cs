using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

using GarlicClove = I2PCore.TunnelLayer.I2NP.Data.GarlicClove;

namespace I2PCore;

public class FloodfillUpdater
{
    public static readonly TickSpan DatabaseStoreNonReplyTimeout = TickSpan.Seconds(20);
    private readonly PeriodicAction CheckForTimouts = new(TickSpan.Seconds(5));

    private readonly TimeWindowDictionary<I2PIdentHash, ILeaseSet> PendingLeaseSetUpdates = new(TickSpan.Minutes(10));
    private readonly PeriodicAction RetryPendingUpdates = new(TickSpan.Seconds(10));

    private readonly TimeWindowDictionary<uint, FfUpdateRequestInfo> OutstandingRequests = new(TickSpan.Seconds(80));

    private readonly PeriodicAction StartNewUpdateRouterInfo = new(NetDb.RouterInfoExpiryTime / 5, true);

    public FloodfillUpdater()
    {
        Router.DeliveryStatusReceived += InboundTunnel_DeliveryStatusReceived;
    }

    private void InboundTunnel_DeliveryStatusReceived(DeliveryStatusMessage msg, InboundTunnel from)
    {
        if (!OutstandingRequests.TryRemove(msg.StatusMessageId, out var info))
            /*
            Logging.LogDebug( $"FloodfillUpdater: Floodfill delivery status " +
                $"{msg.StatusMessageId,10} unknown. Dropped." );
                */
            return;

        var id = info?.LeaseSet is null
            ? info?.IdentToUpdate
            : info.LeaseSet.Destination.IdentHash;

        Logging.LogDebug($"FloodfillUpdater: Floodfill delivery status {info} " +
                         $"received in {info.Start.DeltaToNowMilliseconds} mseconds.");

        NetDb.Inst.Statistics.FloodfillUpdateSuccess(info.CurrentTargetFf);
    }

    public void Run()
    {
        StartNewUpdateRouterInfo.Do(StartNewUpdatesRouterInfo);
        CheckForTimouts.Do(CheckTimeouts);
        RetryPendingUpdates.Do(ProcessPendingUpdates);
    }

    private void ProcessPendingUpdates()
    {
        foreach (var ls in PendingLeaseSetUpdates.ToArray())
        {
            if (ls.Value.Expire < DateTime.UtcNow)
            {
                PendingLeaseSetUpdates.TryRemove(ls.Key, out _);
                continue;
            }

            if (StartNewUpdatesLeaseSetInternal(ls.Value))
            {
                PendingLeaseSetUpdates.TryRemove(ls.Key, out _);
            }
        }
    }

    public void TrigUpdateRouterInfo(string reason)
    {
        if (StartNewUpdateRouterInfo.Autotrigger || StartNewUpdateRouterInfo.LastAction.DeltaToNowSeconds > 15)
        {
            Logging.LogDebug($"FloodFillUpdater: New update triggered. Reason: {reason}");
            StartNewUpdateRouterInfo.TimeToAction = TickSpan.Seconds(5);
        }
        else
        {
            Logging.LogDebug($"FloodFillUpdater: New update request ignored. Reason: {reason}");
        }
    }

    public void TrigUpdateLeaseSet(ILeaseSet leaseset)
    {
        if (!StartNewUpdatesLeaseSetInternal(leaseset))
        {
            PendingLeaseSetUpdates[leaseset.Destination.IdentHash] = leaseset;
        }
    }

    private void StartNewUpdatesRouterInfo()
    {
        // Hidden mode: don't publish our RouterInfo to floodfills
        // Matches Java I2P FloodfillNetworkDatabaseFacade.publish()
        if (RouterContext.Inst.IsHidden)
        {
            Logging.LogDebug("FloodfillUpdater: Hidden mode - not publishing RouterInfo");
            return;
        }

        var myId = RouterContext.Inst.MyRouterIdentity.IdentHash;
        var list = GetNewFfList(
            myId,
            3, 5,
            null);

        // Java's NEXT_RKEY_RI_ADVANCE_TIME = 45 minutes
        var now = DateTime.UtcNow;
        var isNearMidnight = now.TimeOfDay > new TimeSpan(23, 15, 0);
        if (isNearMidnight)
        {
            var tomorrow = now.AddDays(1);
            var nextList = GetNewFfList(
                myId,
                tomorrow,
                2, 5,
                null);
            list = list.Concat(nextList).Distinct().ToList();
        }

        foreach (var ff in list)
            try
            {
                var token = BufUtils.RandomUint() | 1;

                Logging.Log(string.Format("FloodfillUpdater: {0}, RI, token: {1,10}, dist: {2}.",
                    ff.Id32Short, token,
                    ff ^ RouterContext.Inst.MyRouterIdentity.IdentHash.RoutingKey));

                OutstandingRequests[token] = new FfUpdateRequestInfo(
                    ff,
                    token,
                    RouterContext.Inst.MyRouterIdentity.IdentHash);

                SendUpdate(ff, token);
            }
            catch (Exception ex)
            {
                Logging.Log(ex);
            }
    }

    private bool StartNewUpdatesLeaseSetInternal(ILeaseSet ls)
    {
        // old lease sets are out of date
        while (OutstandingRequests.TryRemove(
                   OutstandingRequests.Where(r => r.Value?.LeaseSet?.Destination.IdentHash == ls.Destination.IdentHash)
                       .Select(r => r.Key)
                       .FirstOrDefault(),
                   out _))
        {
        }

        var destId = ls.Destination.IdentHash;
        var list = GetNewFfList(
            destId,
            2, 8,
            null);

        // Java's NEXT_RKEY_LS_ADVANCE_TIME = 10 minutes
        var now = DateTime.UtcNow;
        if (now.TimeOfDay > new TimeSpan(23, 50, 0))
        {
            var nextList = GetNewFfList(
                destId,
                now.AddDays(1),
                1, 5,
                null);
            list = list.Concat(nextList).Distinct().ToList();
        }

        var destinations = list
            .Select(i => NetDb.Inst[i])
            .Where(ri => ri != null);

        var successes = 0;
        foreach (var ff in destinations)
            try
            {
                var ffident = ff.Identity.IdentHash;
                var token = BufUtils.RandomUint() | 1;

                Logging.Log($"FloodfillUpdater: New LS update started for " +
                            $"{ls.Destination.IdentHash.Id32Short}, {ls.Leases.Count()} leases " +
                            $"update {ffident.Id32Short}, token {token,10}, " +
                            $"dist: {ffident ^ ls.Destination.IdentHash.RoutingKey}.");

                if (SendLeaseSetUpdate(ff, ls, token))
                {
                    OutstandingRequests[token] = new FfUpdateRequestInfo(ffident, token, ls, 0);
                    successes++;
                }
            }
            catch (Exception ex)
            {
                Logging.Log(ex);
            }

        return successes > 0;
    }

    /// <summary>
    ///     Garlic-wrap one message for a floodfill, choosing the encryption from the key type in
    ///     its RouterInfo: Noise N for an X25519 or ML-KEM hybrid identity, ElGamal only for an
    ///     identity that actually holds an ElGamal key.
    /// </summary>
    /// <remarks>
    ///     Batch 3-11 (docs/PRODUCTION-PLAN.md). Three of the four garlic sends in this file used
    ///     ElGamal unconditionally, so every RouterInfo publish and every LeaseSet *retry* went to
    ///     a modern floodfill in a form it cannot read. Only <c>GetECIESPublicKey</c> answers this
    ///     question correctly for a hybrid identity — the X25519 half is the *trailing* 32 bytes,
    ///     where the LeaseSet path used to hand Noise N the whole key.
    /// </remarks>
    internal static I2NpMessage WrapForFloodfill(I2NpMessage msg, I2PRouterInfo ffri)
    {
        var eciesKey = ffri.GetECIESPublicKey();

        Logging.LogInformation(
            $"FloodfillUpdater: publishing {msg.MessageType} to " +
            $"{(eciesKey is null ? "ElGamal" : "ECIES")} FF {ffri.Identity.IdentHash.Id32Short}");

        if (eciesKey != null) return Garlic.EciesEncryptGarlic(msg, eciesKey);

        return Garlic.EgEncryptGarlic(
            new Garlic(new GarlicClove(new GarlicCloveDeliveryLocal(msg))),
            ffri.Identity.PublicKey,
            new I2PSessionKey(),
            null);
    }

    private void SendUpdate(I2PIdentHash ff, uint token)
    {
        // If greater than zero, a DeliveryStatusMessage
        // is requested with the Message ID set to the value of the Reply Token.
        // A floodfill router is also expected to flood the data to the closest floodfill peers
        // if the token is greater than zero.
        // https://geti2p.net/spec/i2np#databasestore

        var ds = new DatabaseStoreMessage(
            RouterContext.Inst.MyRouterInfo,
            token,
            RouterContext.Inst.MyRouterInfo.Identity.IdentHash,
            0);

        var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.AllowExploratory);

        if (outtunnel != null)
        {
            var ffri = NetDb.Inst[ff];
            if (ffri != null)
            {
                outtunnel.Send(
                    new TunnelMessageRouter(
                        WrapForFloodfill(ds, ffri),
                        ff));
                return;
            }
        }

        TransportProvider.Send(ff, ds);
    }

    private bool SendLeaseSetUpdate(I2PRouterInfo ffri, ILeaseSet ls, uint token)
    {
        var client = Router.GetClientDestination(ls.Destination.IdentHash);
        var outtunnel = client?.GetEstablishedOutboundTunnel()
                        ?? TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.RequireExploratory);

        var replytunnel = ls.Leases.Random();

        if (outtunnel is null || replytunnel is null)
        {
            Logging.LogDebug($"SendLeaseSetUpdate: " +
                             $"client: {client?.Destination.IdentHash.Id32Short ?? "none"}, " +
                             $"outtunnel: {outtunnel}, replytunnel: {replytunnel}");
            return false;
        }

        var ds = new DatabaseStoreMessage(ls, token, replytunnel.TunnelGw, replytunnel.TunnelId);

        // As explained on the network database page, local LeaseSets are sent to floodfill
        // routers in a Database Store Message wrapped in a Garlic Message so it is not
        // visible to the tunnel's outbound gateway.

        outtunnel.Send(
            new TunnelMessageRouter(
                WrapForFloodfill(ds, ffri),
                ffri.Identity.IdentHash));
        return true;
    }

    private void CheckTimeouts()
    {
        KeyValuePair<uint, FfUpdateRequestInfo>[] timeout;

        timeout = OutstandingRequests
            .Where(r =>
                !r.Value.TimedOut
                && r.Value.Start.DeltaToNow > r.Value.Timeout)
            .ToArray();

        foreach (var one in timeout)
        {
            Logging.LogDebug($"FloodfillUpdater: Update {one.Key,10} failed with timeout.");
            NetDb.Inst.Statistics.FloodfillUpdateTimeout(one.Value.CurrentTargetFf);
        }

        TimeoutRegenerateRiUpdate(timeout
            .Where(t => t.Value?.LeaseSet is null)
            .Select(t => t.Value));

        TimeoutRegenerateLsUpdate(timeout
            .Where(t =>
                !(t.Value?.LeaseSet is null))
            .Select(t => t.Value));
    }

    private void TimeoutRegenerateRiUpdate(IEnumerable<FfUpdateRequestInfo> rinfos)
    {
        if (!rinfos.Any())
            return;

        var list = GetNewFfList(
            RouterContext.Inst.MyRouterIdentity.IdentHash,
            rinfos.Count(), 2 + rinfos.Sum(inf => inf.Retries) * 2,
            rinfos.SelectMany(inf => FfUpdateRequestInfo.Exclude?.Select(e => e.Key)).ToHashSet());

        foreach (var rinfo in rinfos)
        {
            if (OutstandingRequests.TryGetValue(rinfo.Token, out var old))
                old.TimedOut = true;

            var ff = list.Random();

            var token = BufUtils.RandomUint() | 1;

            Logging.LogDebug(string.Format("FloodfillUpdater: RI replacement update {0}, token {1,10}, dist: {2}.",
                ff.Id32Short, token,
                ff ^ RouterContext.Inst.MyRouterIdentity.IdentHash.RoutingKey));

            SendUpdate(ff, token);

            var newreq = new FfUpdateRequestInfo(
                ff,
                token,
                RouterContext.Inst.MyRouterIdentity.IdentHash);
            FfUpdateRequestInfo.Exclude[ff] = 1;

            OutstandingRequests[token] = newreq;
        }
    }

    private void TimeoutRegenerateLsUpdate(IEnumerable<FfUpdateRequestInfo> lsets)
    {
        if (!lsets.Any())
            return;

        foreach (var lsinfo in lsets)
        {
            if (OutstandingRequests.TryGetValue(lsinfo.Token, out var old))
                old.TimedOut = true;

            var token = BufUtils.RandomUint() | 1;

            var ls = lsinfo.LeaseSet;

            var list = GetNewFfList(
                ls.Destination.IdentHash,
                1, 2 + 5 * lsinfo.Retries,
                lsets.SelectMany(inf => FfUpdateRequestInfo.Exclude?.Select(e => e.Key)).ToHashSet());

            var ff = list.FirstOrDefault();
            if (ff is null) continue;

            var ffri = NetDb.Inst[ff];
            if (ffri is null) continue;

            Logging.Log($"FloodfillUpdater: LS {ls.Destination.IdentHash.Id32Short} " +
                        $"replacement update {ff.Id32Short}, token {token,10}, " +
                        $"dist: {ff ^ ls.Destination.IdentHash.RoutingKey}.");

            // Only a request we actually sent can time out. Registering one we did not would
            // charge this floodfill for a message it never received.
            if (!SendLeaseSetUpdate(ffri, ls, token)) continue;

            var newreq = new FfUpdateRequestInfo(
                ff,
                token,
                ls,
                lsinfo.Retries + 1);

            FfUpdateRequestInfo.Exclude[ff] = 1;

            OutstandingRequests[token] = newreq;
        }
    }

    private static IEnumerable<I2PIdentHash> GetNewFfList(I2PIdentHash id, int count, int samples,
        ICollection<I2PIdentHash> exclude)
    {
        return GetNewFfList(id, DateTime.UtcNow, count, samples, exclude);
    }

    private static IEnumerable<I2PIdentHash> GetNewFfList(I2PIdentHash id, DateTime targetDate, int count, int samples,
        ICollection<I2PIdentHash> exclude)
    {
        var list = NetDb.Inst
            .GetClosestFloodfill(
                id,
                targetDate,
                samples,
                exclude);

        if (!(list?.Any() ?? false)) list = NetDb.Inst.GetRandomFloodfillRouter(true, 20);

        var p = list.Select(i => new
        {
            Id = i,
            NetDb.Inst.Statistics[i].Score
        }).ToHashSet();

        // Batch 3-9: both sources can now legitimately come back empty, because a request for a
        // floodfill no longer answers with a router that is not one. RandomWeighted on an empty
        // set throws, and publishing nowhere is the honest outcome — the caller retries.
        if (p.Count == 0)
        {
            Logging.LogWarning(
                $"FloodfillUpdater: no floodfill to publish {id.Id32Short} to. " +
                $"Floodfills known: {NetDb.Inst.FloodfillCount}, routers known: {NetDb.Inst.RouterCount}");
            return Enumerable.Empty<I2PIdentHash>();
        }

        var result = new List<I2PIdentHash>();

        var i = 0;
        while (i++ < count * 2 && result.Count < count)
        {
            var r = p.RandomWeighted(wr => wr.Score, 20.0);

            if (!result.Contains(r.Id)) result.Add(r.Id);
        }

        return result;
    }

    private class FfUpdateRequestInfo
    {
        public static readonly TimeWindowDictionary<I2PIdentHash, object> Exclude = new(TickSpan.Minutes(5));
        public readonly I2PIdentHash IdentToUpdate;
        public readonly ILeaseSet LeaseSet;
        public readonly int Retries;
        public readonly TickCounter Start = new();

        public readonly uint Token;
        public bool TimedOut;

        public FfUpdateRequestInfo(I2PIdentHash ff, uint token, I2PIdentHash id)
        {
            CurrentTargetFf = ff;
            Token = token;
            IdentToUpdate = id;
        }

        public FfUpdateRequestInfo(I2PIdentHash ff, uint token, ILeaseSet ls, int retries)
        {
            CurrentTargetFf = ff;
            Token = token;
            LeaseSet = ls;
            Retries = retries;
        }

        public I2PIdentHash CurrentTargetFf { get; }

        public TickSpan Timeout => LeaseSet is null
            ? DatabaseStoreNonReplyTimeout
            : DatabaseStoreNonReplyTimeout * 2;

        public override string ToString()
        {
            return $"{(LeaseSet is null ? "RI" : "LS")} {Token,10} {CurrentTargetFf.Id32Short}";
        }
    }
}