using System;
using System.Collections.Concurrent;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer;

public class TunnelPoolManager
{
    /// <summary>
    ///     Grace period after startup before attempting multi-hop tunnel builds.
    ///     Allows time for NTCP2 connections to be established with peers.
    /// </summary>
    private static readonly TickSpan StartupGracePeriod = TickSpan.Seconds(15);

    private readonly ConcurrentDictionary<I2PIdentHash, TunnelPool> _clientInboundPools = new();
    private readonly ConcurrentDictionary<I2PIdentHash, TunnelPool> _clientOutboundPools = new();
    private readonly TickCounter _startTime = TickCounter.Now;

    private readonly TunnelProvider _tunnelMgr;
    private readonly PeriodicAction LogStatus = new(TickSpan.Seconds(30));

    private readonly PeriodicAction TunnelBuild = new(TickSpan.Seconds(1));

    public TunnelPoolManager(TunnelProvider tp)
    {
        _tunnelMgr = tp;

        // Read the configured values once, here, rather than having TunnelPoolSettings reach for
        // a singleton in its constructor (batch 2-6).
        var ctx = RouterContext.Inst;

        var ibExplSettings = new TunnelPoolSettings(
            true, ctx.ExploratoryTunnelQuantity, ctx.ExploratoryTunnelLength);
        InboundExploratory = new TunnelPool(tp, ibExplSettings);

        var obExplSettings = new TunnelPoolSettings(
            false, ctx.ExploratoryTunnelQuantity, ctx.ExploratoryTunnelLength);
        OutboundExploratory = new TunnelPool(tp, obExplSettings);
    }

    public TunnelPool InboundExploratory { get; }

    public TunnelPool OutboundExploratory { get; }

    public int EstablishedTunnels => InboundExploratory.EstablishedCount + OutboundExploratory.EstablishedCount;

    public void Execute()
    {
        if (InboundExploratory.EstablishedCount == 0 && TransportProvider.Inst.ConnectedRoutersCount > 0)
            InboundExploratory.CreateFallbackTunnel();
        if (OutboundExploratory.EstablishedCount == 0 && TransportProvider.Inst.ConnectedRoutersCount > 0)
            OutboundExploratory.CreateFallbackTunnel();

        // Wait for peer connections to be established before building multi-hop tunnels
        if (_startTime.DeltaToNow < StartupGracePeriod)
            return;

        TunnelBuild.Do(BuildNewTunnels);
        LogStatus.Do(LogStatusReport);
    }

    private void BuildNewTunnels()
    {
        if (RouterContext.Inst.FloodfillEnabled)
        {
            // Java-like: Increase exploratory tunnel quantity for floodfills
            InboundExploratory.Settings.Quantity = Math.Max(InboundExploratory.Settings.Quantity, 6);
            OutboundExploratory.Settings.Quantity = Math.Max(OutboundExploratory.Settings.Quantity, 6);
        }

        var inNeeded = InboundExploratory.CountHowManyToBuild();
        var outNeeded = OutboundExploratory.CountHowManyToBuild();

        var inProgress = InboundExploratory.InProgressCount;
        var outProgress = OutboundExploratory.InProgressCount;

        if (inNeeded <= 0 && outNeeded <= 0) return;

        // Use real (non-0-hop) counts to decide aggressiveness.
        // 0-hop fallback tunnels are useful but don't indicate healthy network participation.
        var realEstablished = InboundExploratory.RealEstablishedCount + OutboundExploratory.RealEstablishedCount;
        var connectedCount = TransportProvider.Inst.ConnectedRoutersCount;

        // Panic mode: no real tunnels. Fire even if some are in-progress — they
        // may all be timing out and we shouldn't wait for them.
        if (realEstablished == 0 && connectedCount > 0)
        {
            Logging.LogDebug(
                $"TunnelPoolManager: Panic mode — no real tunnels (in-progress: {inProgress + outProgress}). Building aggressively.");
            OutboundExploratory.CreateTunnels(5);
            InboundExploratory.CreateTunnels(5);
            return;
        }

        // Adjust frequency dynamically for bootstrapping
        TunnelBuild.Frequency = realEstablished < 2 || connectedCount < 10
            ? TickSpan.Milliseconds(500)
            : TickSpan.Seconds(1);

        // Proactive bootstrapping: build outbound first since inbound build
        // requests need to be sent via an outbound tunnel.
        if (connectedCount < 3 || OutboundExploratory.RealEstablishedCount == 0)
        {
            var targetBootstrap = connectedCount == 0 ? 5 : 2;
            OutboundExploratory.CreateTunnels(targetBootstrap);
            InboundExploratory.CreateTunnels(targetBootstrap);
        }

        // Max tunnels to build per cycle
        var maxTunnels = realEstablished < 2 || connectedCount < 10 ? 20 : 5;

        // Build both directions fairly — outbound first since inbound
        // build requests are sent through outbound tunnels.
        var toBuildTotal = Math.Min(inNeeded + outNeeded, maxTunnels);
        if (toBuildTotal > 0)
        {
            var outToBuild = inNeeded > 0 && outNeeded > 0 ? (toBuildTotal + 1) / 2 : outNeeded > 0 ? toBuildTotal : 0;
            var inToBuild = toBuildTotal - outToBuild;

            if (outToBuild > 0) OutboundExploratory.CreateTunnels(outToBuild);
            if (inToBuild > 0) InboundExploratory.CreateTunnels(inToBuild);
        }
    }

    private void LogStatusReport()
    {
        var ei = InboundExploratory.EstablishedCount;
        var pi = InboundExploratory.InProgressCount;
        var eo = OutboundExploratory.EstablishedCount;
        var po = OutboundExploratory.InProgressCount;

        var status = RouterContext.Inst.IsFirewalled ? "Firewalled" : "Reachable";
        Logging.LogInformation(
            $"Exploratory Tunnels: in {ei,2} ({pi,2}), out {eo,2} ({po,2}) IB:{InboundExploratory.BuildSuccessRatio} OB:{OutboundExploratory.BuildSuccessRatio} Status: {status} Conns: {TransportProvider.Inst.ConnectedRoutersCount}");
    }
}