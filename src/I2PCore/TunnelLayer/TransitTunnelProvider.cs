using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using CM = System.Configuration.ConfigurationManager;
using static I2PCore.Utils.BufUtils;

namespace I2PCore.TunnelLayer;

public class TransitTunnelProvider : ITunnelOwner
{
    private static readonly TickSpan BlockRecentTunnelsWindow = Tunnel.TunnelLifetime * 3;
    public const int BlockRecentTunnelsCount = 2;

    private readonly TunnelProvider TunnelMgr;

    private readonly ConcurrentDictionary<Tunnel, byte> RunningGatewayTunnels = new();

    private readonly ConcurrentDictionary<Tunnel, byte> RunningEndpointTunnels = new();

    private readonly ConcurrentDictionary<Tunnel, byte> RunningTransitTunnels = new();

    private readonly ItemFilterWindow<uint> AcceptedTunnelHashes =
        new(
            BlockRecentTunnelsWindow,
            BlockRecentTunnelsCount);

    /// <summary>
    ///     Per-next-hop build-request throttle, modelled on Java I2P's `ParticipatingThrottler`:
    ///     a counter per hop over a window of a third of a tunnel lifetime, with a limit that
    ///     rises with the number of tunnels we are already carrying.
    ///
    ///     **i2pd has no throttle of this kind at all** — `TransitTunnels::HandleShortTunnelBuildMsg`
    ///     accepts unless tunnels are disabled, connectivity is limited, or `GetCongestionLevel()`
    ///     (transit count against `DEFAULT_MAX_NUM_TRANSIT_TUNNELS = 5000`, and transport bandwidth)
    ///     is past 70, above which it rejects probabilistically. Java throttles per hop because a
    ///     router that will relay unlimited tunnels toward one peer is an amplifier pointed at that
    ///     peer; that reason still holds here, so the filter stays — with Java's shape rather than
    ///     the constant 2 per 5 minutes it had.
    ///
    ///     Batch 3-14: that constant, plus the window bug in `ItemFilterWindow.Update`, refused
    ///     **528 of 531** build requests in the CI run for 3-13 — every one of them
    ///     "Reject due same next destination" — because a test network has exactly one next hop we
    ///     can ever be asked for. Two tunnels were built out of 529 attempts.
    ///
    ///     Java counts the previous hop in the same counter as the next hop. We count only the next
    ///     hop: the amplification argument is about where traffic is aimed, and counting both would
    ///     halve the budget again in exactly the small networks this batch exists to unblock.
    /// </summary>
    private readonly ItemFilterWindow<I2PIdentHash> NextHopFilter = new(NextHopWindow, MinNextHopRequests);

    // Java I2P ParticipatingThrottler: CLEAN_TIME = 11 min / LIFETIME_PORTION(3),
    // MIN_LIMIT = 12/3, MAX_LIMIT = 66/3, PERCENT_LIMIT = 3/3 percent of participating tunnels.
    private static readonly TickSpan NextHopWindow = TickSpan.Seconds(11 * 60 / 3);
    private const int MinNextHopRequests = 12 / 3;
    private const int MaxNextHopRequests = 66 / 3;
    private const int NextHopPercentOfTransit = 3 / 3;

    /// <summary>Why we last answered a build request the way we did, counted since start.</summary>
    private readonly ConcurrentDictionary<string, long> BuildDecisions = new();

    private const string DecisionAccept = "Accept";
    private const string DecisionHidden = "RejectHidden";
    private const string DecisionNextHop = "RejectNextHopThrottle";
    private const string DecisionCapacity = "RejectCapacity";
    private const string DecisionUnhealthy = "RejectOwnTunnelsDown";
    private const string DecisionRecent = "RejectRecentDuplicate";

    private bool Decision(string reason)
    {
        BuildDecisions.AddOrUpdate(reason, 1, (_, v) => v + 1);
        return reason == DecisionAccept;
    }

    private class PendingRequest
    {
        public readonly TickCounter Created = new();
        public TunnelBuildRequestDecrypt Decrypt;
        public I2PIdentHash From;
        public Ii2NpHeader Msg;
    }

    private readonly ConcurrentDictionary<I2PIdentHash, ConcurrentQueue<PendingRequest>> PendingLookups = new();
    private readonly TickSpan PendingLookupTimeout = TickSpan.Seconds(20);

    internal TransitTunnelProvider(TunnelProvider tp)
    {
        TunnelMgr = tp;
        ReadAppConfig();

        tp.TunnelBuildRequestEvents += HandleTunnelBuildRecords;
        NetDb.Inst.RouterInfoUpdates += NetDb_RouterInfoUpdates;
    }

    private void NetDb_RouterInfoUpdates(I2PRouterInfo ri)
    {
        if (PendingLookups.TryRemove(ri.Identity.IdentHash, out var queue))
        {
            Logging.LogInformation(
                $"TransitTunnelProvider: RouterInfo for {ri.Identity.IdentHash.Id32Short} found. Resuming {queue.Count} pending build requests.");
            while (queue.TryDequeue(out var request))
                if (request.Created.DeltaToNow < PendingLookupTimeout)
                    HandleTunnelBuildRecords(request.Msg, request.Decrypt, request.From);
                else
                    Logging.LogDebug(
                        $"TransitTunnelProvider: Pending build request for {ri.Identity.IdentHash.Id32Short} expired.");
        }
    }

    private void CleanupPendingLookups()
    {
        foreach (var key in PendingLookups.Keys.ToArray())
            if (PendingLookups.TryGetValue(key, out var queue))
            {
                var allExpired = true;
                foreach (var req in queue)
                    if (req.Created.DeltaToNow < PendingLookupTimeout)
                    {
                        allExpired = false;
                        break;
                    }

                if (allExpired) PendingLookups.TryRemove(key, out _);
            }
    }

    private readonly PeriodicAction Maintenance = new(TickSpan.Minutes(15));

    // Batch 3-14: one period, not two. This was `#if DEBUG` 30 s `#else` 2 minutes — and the
    // Release branch declared a second, non-readonly field with the same name, so the two builds
    // disagreed about how often the router reports what it is carrying. Same class of defect as
    // the `#if DEBUG` diagnostics batch 3-10 removed from NetDb: a Release router that says less
    // about itself than a Debug one, in the subsystem being diagnosed.
    private readonly PeriodicAction LogStatus = new(TickSpan.Seconds(30));
    public void Execute()
    {
        LogStatus.Do(LogStatusReport);
        CleanupPendingLookups();
    }

    /// <summary>
    ///     Get transit tunnel statistics for web console display.
    /// </summary>
    internal (int gateway, int endpoint, int transit) GetTransitCounts()
    {
        return (RunningGatewayTunnels.Count, RunningEndpointTunnels.Count, RunningTransitTunnels.Count);
    }

    /// <summary>
    ///     Total number of running transit tunnels (all types)
    /// </summary>
    public int TransitTunnelCount =>
        RunningGatewayTunnels.Count + RunningEndpointTunnels.Count + RunningTransitTunnels.Count;

    public IEnumerable<Tunnel> GetTunnels()
    {
        return RunningGatewayTunnels.Keys
            .Concat(RunningEndpointTunnels.Keys)
            .Concat(RunningTransitTunnels.Keys);
    }

    internal void RegisterTransitTunnel(Tunnel tunnel)
    {
        if (tunnel is GatewayTunnel)
            RunningGatewayTunnels[tunnel] = 1;
        else if (tunnel is EndpointTunnel)
            RunningEndpointTunnels[tunnel] = 1;
        else if (tunnel is TransitTunnel) RunningTransitTunnels[tunnel] = 1;
    }

    private void LogStatusReport()
    {
        var gtc = RunningGatewayTunnels.Count;
        var gbrr = RunningGatewayTunnels.Sum(gt =>
            gt.Key.Bandwidth.ReceiveBandwidth.Bitrate) / 1024f;
        var gbrs = RunningGatewayTunnels.Sum(gt =>
            gt.Key.Bandwidth.SendBandwidth.Bitrate) / 1024f;

        var gbr = RunningGatewayTunnels.Sum(gt =>
            gt.Key.Bandwidth.ReceiveBandwidth.DataBytes);
        var gbs = RunningGatewayTunnels.Sum(gt =>
            gt.Key.Bandwidth.SendBandwidth.DataBytes);

        var etc = RunningEndpointTunnels.Count;
        var ebrr = RunningEndpointTunnels.Sum(gt =>
            gt.Key.Bandwidth.ReceiveBandwidth.Bitrate) / 1024f;
        var ebrs = RunningEndpointTunnels.Sum(gt =>
            gt.Key.Bandwidth.SendBandwidth.Bitrate) / 1024f;

        var ebr = RunningEndpointTunnels.Sum(gt =>
            gt.Key.Bandwidth.ReceiveBandwidth.DataBytes);
        var ebs = RunningEndpointTunnels.Sum(gt =>
            gt.Key.Bandwidth.SendBandwidth.DataBytes);

        var ttc = RunningTransitTunnels.Count;
        var tbrr = RunningTransitTunnels.Sum(gt =>
            gt.Key.Bandwidth.ReceiveBandwidth.Bitrate) / 1024f;
        var tbrs = RunningTransitTunnels.Sum(gt =>
            gt.Key.Bandwidth.SendBandwidth.Bitrate) / 1024f;

        var tbr = RunningTransitTunnels.Sum(gt =>
            gt.Key.Bandwidth.ReceiveBandwidth.DataBytes);
        var tbs = RunningTransitTunnels.Sum(gt =>
            gt.Key.Bandwidth.SendBandwidth.DataBytes);

        Logging.LogInformation(
            $"Established gateway tunnels   : {gtc,2}, Send / Receive: " +
            $"{gbrs,8:F1} kbps / {gbrr,8:F1} kbps   " +
            $"{BytesToReadable(gbs),10} / {BytesToReadable(gbr),10}");

        Logging.LogInformation(
            $"Established endpoint tunnels  : {etc,2}, Send / Receive: " +
            $"{ebrs,8:F1} kbps / {ebrr,8:F1} kbps   " +
            $"{BytesToReadable(ebs),10} / {BytesToReadable(ebr),10}");

        Logging.LogInformation(
            $"Established transit tunnels   : {ttc,2}, Send / Receive: " +
            $"{tbrs,8:F1} kbps / {tbrr,8:F1} kbps   " +
            $"{BytesToReadable(tbs),10} / {BytesToReadable(tbr),10}");

        LogBuildDecisions();
    }

    /// <summary>
    ///     What we answered the peers who asked us to carry a tunnel, and why. Batch 3-14: the
    ///     reasons were `LogDebug` only, so a Release router at the default level could refuse
    ///     every tunnel it was offered and say nothing about it — which is how 528 refusals in a
    ///     row survived until an i2pd log was read beside ours.
    /// </summary>
    private void LogBuildDecisions()
    {
        var report = FormatBuildDecisions(BuildDecisions);
        if (report != null) Logging.LogInformation(report);
    }

    /// <summary>Null when nothing has been asked of us yet — there is no report to make.</summary>
    internal static string FormatBuildDecisions(IEnumerable<KeyValuePair<string, long>> decisions)
    {
        var counts = decisions.ToArray();
        var total = counts.Sum(d => d.Value);
        if (total == 0) return null;

        var accepted = counts
            .Where(d => d.Key == DecisionAccept)
            .Sum(d => d.Value);

        var reasons = string.Join(", ", counts
            .Where(d => d.Key != DecisionAccept && d.Value > 0)
            .OrderByDescending(d => d.Value)
            .Select(d => $"{d.Key}: {d.Value} ({100f * d.Value / total:F1}%)"));

        return $"Transit build requests        : {total} answered, {accepted} accepted "
               + $"({100f * accepted / total:F1}%)"
               + (string.IsNullOrEmpty(reasons) ? "" : $". Refused: {reasons}");
    }

    public void ReadAppConfig()
    {
        if (!string.IsNullOrWhiteSpace(CM.AppSettings["MaxTransitTunnels"]))
            RouterContext.Inst.MaxTransitTunnels = int.Parse(CM.AppSettings["MaxTransitTunnels"]);
    }

    internal void HandleTunnelBuildRecords(
        Ii2NpHeader msg,
        TunnelBuildRequestDecrypt decrypt,
        I2PIdentHash from)
    {
        if (decrypt.Decrypted.ToAnyone)
        {
            // Im outbound endpoint
            Logging.LogInformation($"HandleTunnelBuildRecords: Outbound endpoint request from {from?.Id32Short}");
            HandleEndpointTunnelRequest(msg, decrypt, from);
            return;
        }

        if (decrypt.Decrypted.FromAnyone)
        {
            // Im inbound gateway
            Logging.LogInformation($"HandleTunnelBuildRecords: Inbound gateway request from {from?.Id32Short}");
            HandleGatewayTunnelRequest(msg, decrypt, from);
            return;
        }

        if (decrypt.Decrypted.NextIdent != RouterContext.Inst.MyRouterIdentity.IdentHash)
        {
            // Im transit tunnel
            Logging.LogDebug($"HandleTunnelBuildRecords: Transit tunnel request {decrypt}");
            HandleTransitTunnelRequest(msg, decrypt, from);
            return;
        }

        throw new NotSupportedException();
    }

    private void HandleGatewayTunnelRequest(
        Ii2NpHeader msg,
        TunnelBuildRequestDecrypt decrypt,
        I2PIdentHash from)
    {
        // Validate NextHop RouterInfo exists in our NetDb before accepting
        var nextHop = new I2PIdentHash(new I2PBufferCursor(decrypt.Decrypted.NextIdent.Hash.Clone()));
        if (!NetDb.Inst.Contains(nextHop))
        {
            Logging.LogInformation(
                $"HandleGatewayTunnelRequest: NextHop {nextHop.Id32Short} not in NetDb. Initiating lookup.");
            var queue = PendingLookups.GetOrAdd(nextHop, _ => new ConcurrentQueue<PendingRequest>());
            queue.Enqueue(new PendingRequest { Msg = msg, Decrypt = decrypt.Clone(), From = from });
            NetDb.Inst.IdentHashLookup.LookupRouterInfo(nextHop);
            return;
        }

        var config = new TunnelConfig(
            TunnelConfig.TunnelDirection.Inbound,
            TunnelConfig.TunnelPool.External,
            new TunnelInfo(new List<HopInfo>
                {
                    new(
                        RouterContext.Inst.MyRouterIdentity,
                        new I2PTunnelId())
                }
            ));

        var tunnel = new GatewayTunnel(this, config, decrypt.Decrypted);
        tunnel.EstablishedTime.SetNow();
        // Gateways accept from any peer, so ReceiveFrom stays null

        var doaccept = AcceptingTunnels(decrypt.Decrypted);

        if (!doaccept)
            Logging.LogInformation(
                $"HandleGatewayTunnelRequest: Rejecting Inbound Gateway tunnel {tunnel.ReceiveTunnelId} from {from?.Id32Short}");

        var response = doaccept
            ? BuildResponseRecord.RequestResponse.Accept
            : BuildResponseRecord.DefaultErrorReply;

        Logging.LogDebug($"HandleGatewayTunnelRequest {tunnel.TunnelDebugTrace}: " +
                         $"{tunnel.Destination.Id32Short} Gateway tunnel request: {response} " +
                         $"for tunnel id {tunnel.ReceiveTunnelId}.");

        var replymsg = CreateReplyMessage(msg, decrypt, response);

        if (response == BuildResponseRecord.RequestResponse.Accept)
        {
            Logging.LogInformation(
                $"HandleGatewayTunnelRequest: Accepting Inbound Gateway tunnel {tunnel.ReceiveTunnelId} from {from?.Id32Short}");
            RunningGatewayTunnels[tunnel] = 1;
            TunnelMgr.AddTunnel(tunnel);
        }

        TransportProvider.Send(tunnel.Destination, replymsg);
    }

    private void HandleEndpointTunnelRequest(
        Ii2NpHeader msg,
        TunnelBuildRequestDecrypt decrypt,
        I2PIdentHash from)
    {
        var config = new TunnelConfig(
            TunnelConfig.TunnelDirection.Inbound,
            TunnelConfig.TunnelPool.External,
            new TunnelInfo(new List<HopInfo>
                {
                    new(
                        RouterContext.Inst.MyRouterIdentity,
                        new I2PTunnelId())
                }
            ));

        var tunnel = new EndpointTunnel(this, config, decrypt.Decrypted);
        tunnel.EstablishedTime.SetNow();
        tunnel.ReceiveFrom = from;

        var doaccept = AcceptingTunnels(decrypt.Decrypted);

        var response = doaccept
            ? BuildResponseRecord.RequestResponse.Accept
            : BuildResponseRecord.DefaultErrorReply;

        Logging.LogDebug($"HandleEndpointTunnelRequest {tunnel.TunnelDebugTrace}: " +
                         $"{tunnel.Destination.Id32Short} Endpoint tunnel request: {response} " +
                         $"for tunnel id {tunnel.ReceiveTunnelId}.");

        var newrecords = decrypt.CreateTunnelBuildReplyRecords(response);

        var responsemessage = new VariableTunnelBuildReplyMessage(
            newrecords.Select(r => new BuildResponseRecord(r)),
            tunnel.ResponseMessageId);

        var buildreplymsg = new TunnelGatewayMessage(
            responsemessage,
            tunnel.ResponseTunnelId);

        if (response == BuildResponseRecord.RequestResponse.Accept)
        {
            Logging.LogInformation(
                $"HandleEndpointTunnelRequest: Accepting Outbound Endpoint tunnel {tunnel.ReceiveTunnelId} from {from?.Id32Short}");
            RunningEndpointTunnels[tunnel] = 1;
            TunnelMgr.AddTunnel(tunnel);
        }

        TransportProvider.Send(tunnel.Destination, buildreplymsg);
    }

    private void HandleTransitTunnelRequest(
        Ii2NpHeader msg,
        TunnelBuildRequestDecrypt decrypt,
        I2PIdentHash from)
    {
        // Validate NextHop RouterInfo exists in our NetDb before accepting
        var nextHop = new I2PIdentHash(new I2PBufferCursor(decrypt.Decrypted.NextIdent.Hash.Clone()));
        if (!NetDb.Inst.Contains(nextHop))
        {
            Logging.LogInformation(
                $"HandleTransitTunnelRequest: NextHop {nextHop.Id32Short} not in NetDb. Initiating lookup.");
            var queue = PendingLookups.GetOrAdd(nextHop, _ => new ConcurrentQueue<PendingRequest>());
            queue.Enqueue(new PendingRequest { Msg = msg, Decrypt = decrypt.Clone(), From = from });
            NetDb.Inst.IdentHashLookup.LookupRouterInfo(nextHop);
            return;
        }

        var config = new TunnelConfig(
            TunnelConfig.TunnelDirection.Inbound,
            TunnelConfig.TunnelPool.External,
            new TunnelInfo(new List<HopInfo>
                {
                    new(
                        RouterContext.Inst.MyRouterIdentity,
                        new I2PTunnelId())
                }
            ));

        var tunnel = new TransitTunnel(this, config, decrypt.Decrypted);
        tunnel.EstablishedTime.SetNow();
        tunnel.ReceiveFrom = from;

        var doaccept = AcceptingTunnels(decrypt.Decrypted);

        var response = doaccept
            ? BuildResponseRecord.RequestResponse.Accept
            : BuildResponseRecord.DefaultErrorReply;

        Logging.LogDebug($"HandleTransitTunnelRequest {tunnel.TunnelDebugTrace}: " +
                         $"{tunnel.Destination.Id32Short} Transit tunnel request: {response} " +
                         $"for tunnel id {tunnel.ReceiveTunnelId}.");

        var replymsg2 = CreateReplyMessage(msg, decrypt, response);

        if (response == BuildResponseRecord.RequestResponse.Accept)
        {
            RunningTransitTunnels[tunnel] = 1;
            TunnelMgr.AddTunnel(tunnel);
        }

        TransportProvider.Send(tunnel.Destination, replymsg2);
    }

    #region Request filter

    /// <summary>
    ///     How many build requests naming the same next hop we will answer inside
    ///     <see cref="NextHopWindow" />. Java I2P's rule: a floor, a ceiling, and a percentage of
    ///     the tunnels we are already carrying — so a busy router tolerates more from one peer
    ///     than an idle one, and an idle one still tolerates enough to bootstrap.
    /// </summary>
    internal static int NextHopRequestLimit(int transittunnelcount)
    {
        return Math.Max(MinNextHopRequests,
            Math.Min(MaxNextHopRequests, transittunnelcount * NextHopPercentOfTransit / 100));
    }

    internal bool AcceptingTunnels(I2PIdentHash nextIdent)
    {
        return Decision(EvaluateBuildRequest(nextIdent));
    }

    /// <summary>Decides, without recording — the two callers count exactly one decision each.</summary>
    private string EvaluateBuildRequest(I2PIdentHash nextIdent)
    {
        // Hidden mode: reject all transit tunnels
        if (RouterContext.Inst.IsHidden)
        {
            Logging.LogDebug("TransitProvider AcceptingTunnels: Reject - hidden mode.");
            return DecisionHidden;
        }

        var currenttunnelcount = TransitTunnelCount;
        RouterContext.Inst.CurrentTransitTunnelCount = currenttunnelcount;

        // Reject if we've seen the same next-hop destination too many times recently
        var nexthoplimit = NextHopRequestLimit(currenttunnelcount);
        if (nextIdent != null && !NextHopFilter.Update(nextIdent, nexthoplimit))
        {
            Logging.LogDebug($"TransitProvider AcceptingTunnels: Reject, {NextHopFilter.Count(nextIdent)} requests " +
                             $"for next hop {nextIdent.Id32Short} in {NextHopWindow}, limit {nexthoplimit}. " +
                             $"Running tunnels: {currenttunnelcount}.");
            return DecisionNextHop;
        }

        if (currenttunnelcount >= RouterContext.Inst.MaxTransitTunnels)
        {
            Logging.LogDebug($"TransitProvider AcceptingTunnels: Reject, {currenttunnelcount} running " +
                             $"of {RouterContext.Inst.MaxTransitTunnels} allowed.");
            return DecisionCapacity;
        }

        // Two causes with one name is what this batch exists to stop: being full is not the same
        // as declining to relay because our own tunnels are unhealthy behind a firewall.
        if (!TunnelMgr.AcceptTransitTunnels)
        {
            Logging.LogDebug("TransitProvider AcceptingTunnels: Reject, not relaying while our own " +
                             "client tunnels are down and we are firewalled.");
            return DecisionUnhealthy;
        }

        Logging.LogDebug($"TransitProvider AcceptingTunnels: Running tunnels: {currenttunnelcount}. Accept: true.");

        return DecisionAccept;
    }

    private bool AcceptingTunnels(BuildRequestRecord drec)
    {
        var decision = EvaluateBuildRequest(drec.NextIdent);

        // Reject duplicate/similar build requests (replay protection)
        if (decision == DecisionAccept && HaveSeenTunnelBuildRequest(drec))
        {
            Logging.LogDebug($"TransitProvider AcceptingTunnels: Reject due to similarity to recent tunnel. " +
                             $"Running tunnels: {TransitTunnelCount}. Accept: false.");
            decision = DecisionRecent;
        }

        if (!Decision(decision)) return false;

        AcceptedTunnelBuildRequest(drec);
        return true;
    }

    private void AcceptedTunnelBuildRequest(BuildRequestRecord drec)
    {
        AcceptedTunnelBuildRequest(drec.GetReducedHash());
    }

    private void AcceptedTunnelBuildRequest(uint hash)
    {
        AcceptedTunnelHashes.Update(hash);
    }

    private bool HaveSeenTunnelBuildRequest(BuildRequestRecord drec)
    {
        return !AcceptedTunnelHashes.Update(drec.GetReducedHash());
    }

    #endregion

    #region TunnelEvents

    public void TunnelEstablished(Tunnel tunnel)
    {
    }

    public void TunnelBuildFailed(Tunnel tunnel, bool timeout)
    {
    }

    public void TunnelExpired(Tunnel tunnel)
    {
        Logging.LogDebug($"TransitProvider: TunnelTimeout: {tunnel}");
        RunningGatewayTunnels.TryRemove(tunnel, out _);
        RunningEndpointTunnels.TryRemove(tunnel, out _);
        RunningTransitTunnels.TryRemove(tunnel, out _);
    }

    public void TunnelFailed(Tunnel tunnel)
    {
        TunnelExpired(tunnel);
    }

    #endregion

    private static I2NpMessage CreateReplyMessage(
        Ii2NpHeader msg,
        TunnelBuildRequestDecrypt decrypt,
        BuildResponseRecord.RequestResponse response)
    {
        var newrecords = decrypt.CreateTunnelBuildReplyRecords(response);

        if (msg.MessageType == I2NpMessage.MessageTypes.VariableTunnelBuild)
            return new VariableTunnelBuildMessage(newrecords);

        return new TunnelBuildMessage(newrecords);
    }

    public override string ToString()
    {
        return GetType().Name;
    }
}