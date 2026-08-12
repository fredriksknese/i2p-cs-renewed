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

    // internal for the 3-12 guard test: a request is registered here only when it was actually
    // sent, and charged as a timeout exactly once.
    internal readonly TimeWindowDictionary<uint, FfUpdateRequestInfo> OutstandingRequests = new(TickSpan.Seconds(80));

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

                // Only a publish we actually sent can time out. Registering one we did not would
                // charge this floodfill for a message it never received — batch 3-11 fixed the
                // same thing on the LeaseSet retry.
                if (SendUpdate(ff, token))
                    OutstandingRequests[token] = new FfUpdateRequestInfo(
                        ff,
                        token,
                        RouterContext.Inst.MyRouterIdentity.IdentHash);
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

    /// <summary>Publishes our RouterInfo to one floodfill. True only if the message was sent.</summary>
    private bool SendUpdate(I2PIdentHash ff, uint token)
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

        // NetDb.Start() runs before TunnelProvider.Start(), and this tick begins as soon as the
        // *transport* layer exists, so the tunnel layer can legitimately still be null here.
        var outtunnel = TunnelProvider.Inst?.GetEstablishedOutboundTunnel(TunnelPoolSelection.AllowExploratory);

        if (outtunnel != null)
        {
            var ffri = NetDb.Inst[ff];
            if (ffri != null)
            {
                outtunnel.Send(
                    new TunnelMessageRouter(
                        WrapForFloodfill(ds, ffri),
                        ff));
                return true;
            }
        }

        try
        {
            return TransportProvider.Send(ff, ds);
        }
        catch (Exception ex)
        {
            // TransportProvider.Send answers with a bool but rethrows anything it did not expect
            // (TransportProvider.cs, the general catch at the end of Send). Letting that escape
            // aborts the whole NetDb tick — the LeaseSet retries, the NetDb import and the ident
            // lookups all run after this one. Failing to publish is a false, not a crash.
            Logging.LogDebug($"FloodfillUpdater: RI publish to {ff.Id32Short} not sent: {ex.Message}");
            return false;
        }
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

    /// <summary>
    ///     Charges every outstanding request that has run out of time, once, and then tries to
    ///     re-send it to a different floodfill.
    /// </summary>
    /// <remarks>
    ///     Batch 3-12 (docs/PRODUCTION-PLAN.md). <c>TimedOut</c> is what stops a request being
    ///     charged again on the next pass, and it used to be set by the two regeneration methods —
    ///     so a request whose *replacement* could not be built stayed unmarked and was charged
    ///     afresh every 5 seconds until the 80-second window dropped it. One unanswered publish
    ///     could reach a dozen charges against a floodfill, where five (against two successes) is
    ///     enough for <c>RoutersStatistics</c> to call it inactive and sweep it out of the index.
    ///     The charge and the mark are one decision and now happen in one place; regenerating is a
    ///     separate, best-effort thing that may legitimately do nothing.
    /// </remarks>
    internal void CheckTimeouts()
    {
        var timeout = OutstandingRequests
            .Where(r =>
                !r.Value.TimedOut
                && r.Value.Start.DeltaToNow > r.Value.Timeout)
            .ToArray();

        foreach (var one in timeout)
        {
            Logging.LogDebug($"FloodfillUpdater: Update {one.Key,10} failed with timeout.");
            NetDb.Inst.Statistics.FloodfillUpdateTimeout(one.Value.CurrentTargetFf);
            one.Value.TimedOut = true;
        }

        TimeoutRegenerateRiUpdate(timeout
            .Where(t => t.Value?.LeaseSet is null)
            .Select(t => t.Value)
            .ToArray());

        TimeoutRegenerateLsUpdate(timeout
            .Where(t =>
                !(t.Value?.LeaseSet is null))
            .Select(t => t.Value)
            .ToArray());
    }

    private void TimeoutRegenerateRiUpdate(IReadOnlyCollection<FfUpdateRequestInfo> rinfos)
    {
        if (rinfos.Count == 0)
            return;

        // Retries is always 0 for a RouterInfo request — the replacement below builds one with
        // the constructor that has no retry count — so the sample widening this expresses does
        // not actually widen. Left as it stands: making it live changes floodfill selection, and
        // that belongs with a batch that can measure it.
        var list = GetNewFfList(
            RouterContext.Inst.MyRouterIdentity.IdentHash,
            rinfos.Count, 2 + rinfos.Sum(inf => inf.Retries) * 2,
            FfUpdateRequestInfo.Exclude.Select(e => e.Key).ToHashSet()).ToArray();

        // Batch 3-9 made "no floodfill to publish to" a legitimate answer, and this method still
        // dereferenced list.Random(). With the floodfill index empty — which is the state a run
        // of unanswered publishes produces — that NullReferenceException left the NetDb worker's
        // whole pass undone: the LeaseSet retries below, ProcessPendingUpdates, ImportNetDbFiles
        // (the one thing that could put a floodfill back) and the ident lookups.
        if (list.Length == 0)
            return;

        foreach (var rinfo in rinfos)
            try
            {
                var ff = list.Random();
                var token = BufUtils.RandomUint() | 1;

                Logging.LogDebug(string.Format("FloodfillUpdater: RI replacement update {0}, token {1,10}, dist: {2}.",
                    ff.Id32Short, token,
                    ff ^ RouterContext.Inst.MyRouterIdentity.IdentHash.RoutingKey));

                if (!SendUpdate(ff, token)) continue;

                FfUpdateRequestInfo.Exclude[ff] = 1;

                OutstandingRequests[token] = new FfUpdateRequestInfo(
                    ff,
                    token,
                    RouterContext.Inst.MyRouterIdentity.IdentHash);
            }
            catch (Exception ex)
            {
                // One replacement that cannot be built is not a reason to skip the others, nor to
                // abort the tick. The initial publish loop above has always worked this way.
                Logging.Log(ex);
            }
    }

    private void TimeoutRegenerateLsUpdate(IReadOnlyCollection<FfUpdateRequestInfo> lsets)
    {
        if (lsets.Count == 0)
            return;

        foreach (var lsinfo in lsets)
        {
            var token = BufUtils.RandomUint() | 1;

            var ls = lsinfo.LeaseSet;

            var list = GetNewFfList(
                ls.Destination.IdentHash,
                1, 2 + 5 * lsinfo.Retries,
                FfUpdateRequestInfo.Exclude.Select(e => e.Key).ToHashSet());

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

    internal class FfUpdateRequestInfo
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