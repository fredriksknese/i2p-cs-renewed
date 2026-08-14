using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer;

public class ClientTunnelProvider : ITunnelOwner
{
    /// <summary>
    ///     After this many consecutive outbound tunnel build failures per client,
    ///     force exploratory reply tunnels to break out of a bad paired-tunnel cycle.
    ///     Matches Java I2P's MAX_CONSECUTIVE_CLIENT_BUILD_FAILS = 6.
    /// </summary>
    private const int MaxConsecutiveClientBuildFails = 6;

    // Java I2P builds exactly the number needed, no multiplier
    public static double NewTunnelCreationFactor = 2;

    private readonly List<IClient> Clients = new();

    private readonly ConcurrentDictionary<IClient, int> ConsecutiveOutboundBuildFails = new();
    private readonly PeriodicAction DestinationExecute = new(TickSpan.Seconds(1));

    private readonly ConcurrentDictionary<Tunnel, IClient> Destinations = new();
    private readonly PeriodicAction LogStatus = new(TickSpan.Seconds(20));

    private readonly ConcurrentDictionary<Tunnel, IClient> PendingTunnels = new();

    private readonly PeriodicAction TunnelBuild = new(TickSpan.Seconds(1));
    public SuccessRatio ClientTunnelBuildSuccessRatio = new();
    private PeriodicAction ReplaceTunnels = new(TickSpan.Seconds(5));

    internal TunnelProvider TunnelMgr;

    internal ClientTunnelProvider(TunnelProvider tp)
    {
        TunnelMgr = tp;
    }

    public int ClientTunnelCount => Destinations.Count;

    public IClient GetClientForTunnel(Tunnel tunnel)
    {
        if (Destinations.TryGetValue(tunnel, out var client)) return client;
        if (PendingTunnels.TryGetValue(tunnel, out client)) return client;
        return null;
    }

    public IEnumerable<IClient> GetClients()
    {
        lock (Clients)
        {
            return Clients.ToArray();
        }
    }

    internal void AttachClient(IClient client)
    {
        lock (Clients)
        {
            Clients.Add(client);
        }
    }

    internal void DetachClient(IClient client)
    {
        lock (Clients)
        {
            Clients.Remove(client);
        }

        ConsecutiveOutboundBuildFails.TryRemove(client, out _);

        // Shutdown and remove all tunnels for this client
        foreach (var t in Destinations.Where(kvp => kvp.Value == client).Select(kvp => kvp.Key).ToArray())
        {
            t.Shutdown();
            Destinations.TryRemove(t, out _);
            TunnelMgr.RemoveTunnel(t);
        }
        foreach (var t in PendingTunnels.Where(kvp => kvp.Value == client).Select(kvp => kvp.Key).ToArray())
        {
            t.Shutdown();
            PendingTunnels.TryRemove(t, out _);
            TunnelMgr.RemoveTunnel(t);
        }
    }

    private OutboundTunnel CreateOutboundTunnel(IClient client, TunnelInfo prototype)
    {
        var config = new TunnelConfig(
            TunnelConfig.TunnelDirection.Outbound,
            TunnelConfig.TunnelPool.Client,
            prototype ?? Tunnel.CreateOutboundTunnelChain(client.OutboundTunnelHopCount, false));

        // Force exploratory reply tunnels after too many consecutive failures,
        // matching Java I2P's MAX_CONSECUTIVE_CLIENT_BUILD_FAILS fallback.
        TunnelPoolSelection? replyOverride = ShouldForceExploratoryReply(client)
            ? TunnelPoolSelection.RequireExploratory
            : null;

        var tunnel = (OutboundTunnel)TunnelMgr.CreateTunnel(this, config, replyOverride);
        if (tunnel != null)
        {
            TunnelMgr.AddTunnel(tunnel);
            client.AddOutboundPending(tunnel);
            PendingTunnels[tunnel] = client;
        }

        return tunnel;
    }

    private bool ShouldForceExploratoryReply(IClient client)
    {
        return ConsecutiveOutboundBuildFails.GetValueOrDefault(client, 0) >= MaxConsecutiveClientBuildFails;
    }

    private InboundTunnel CreateInboundTunnel(IClient client, TunnelInfo prototype)
    {
        var config = new TunnelConfig(
            TunnelConfig.TunnelDirection.Inbound,
            TunnelConfig.TunnelPool.Client,
            prototype ?? Tunnel.CreateInboundTunnelChain(client.InboundTunnelHopCount, false));

        var tunnel = (InboundTunnel)TunnelMgr.CreateTunnel(this, config);
        if (tunnel != null)
        {
            TunnelMgr.AddTunnel(tunnel);
            client.AddInboundPending(tunnel);
            PendingTunnels[tunnel] = client;
        }

        return tunnel;
    }

    public void Execute()
    {
        TunnelBuild.Do(() =>
        {
            try
            {
                BuildNewTunnels();
            }
            catch (Exception ex)
            {
                Logging.Log("ClientTunnelProvider Execute BuildNewTunnels", ex);
            }
        });

        DestinationExecute.Do(() =>
        {
            var dests = Destinations.Select(d => d.Value).ToArray();

            foreach (var onedest in dests)
                try
                {
                    onedest.Execute();
                }
                catch (Exception ex)
                {
                    Logging.Log("ClientTunnelProvider Execute DestExecute", ex);
                }

            LogStatus.Do(LogStatusReport);
        });
    }

    private void LogStatusReport()
    {
        var dti = Destinations.Where(t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Inbound);
        var pti = PendingTunnels.Where(t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Inbound);
        var dto = Destinations.Where(t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Outbound);
        var pto = PendingTunnels.Where(t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Outbound);

        var ei = dti.Count();
        var pi = pti.Count();
        var eo = dto.Count();
        var po = pto.Count();

        var post = "";
        var pist = "";

        if (Logging.IsTraceEnabled(TraceCategories.TunnelTransfer))
        {
            pist = string.Join(", ", pti.Select(t => t.Key.TunnelDebugTrace));
            post = string.Join(", ", pto.Select(t => t.Key.TunnelDebugTrace));
        }

        Logging.LogInformation(
            $"Established client tunnels in : {ei,2} ( {pi,2} {pist}), out: {eo,2} ( {po,2} {post}) {ClientTunnelBuildSuccessRatio}");
    }

    private void BuildNewTunnels()
    {
        TunnelsNeededInfo[] tocreateinbound;
        TunnelsNeededInfo[] tocreateoutbound;

        lock (Clients)
        {
            tocreateinbound = Clients.Where(c => c.InboundTunnelsNeeded > 0).Select(c => new TunnelsNeededInfo
                { Client = c, TunnelsNeeded = c.InboundTunnelsNeeded }).ToArray();

            tocreateoutbound = Clients.Where(c => c.OutboundTunnelsNeeded > 0).Select(c => new TunnelsNeededInfo
                { Client = c, TunnelsNeeded = c.OutboundTunnelsNeeded }).ToArray();
        }

        foreach (var create in tocreateinbound)
        {
            var needed = create.TunnelsNeeded * NewTunnelCreationFactor;
            for (var i = 0; i < needed; ++i)
            {
                Logging.LogInformation($"{this} building new inbound tunnel {i + 1}/{needed}");

                var t = CreateInboundTunnel(create.Client, null);
                if (t == null)
                {
                    // No outbound tunnels available
                    TunnelBuild.TimeToAction = TickSpan.Seconds(10);
                    break;
                }
            }
        }

        foreach (var create in tocreateoutbound)
        {
            var needed = create.TunnelsNeeded * NewTunnelCreationFactor;
            for (var i = 0; i < create.TunnelsNeeded * NewTunnelCreationFactor; ++i)
            {
                Logging.LogInformation($"{this} building new outbound tunnel {i + 1}/{needed}");
                CreateOutboundTunnel(create.Client, null);
            }
        }

        TunnelMgr.ClientTunnelsStatusOk = Clients.All(ct => ct.ClientTunnelsStatusOk);
    }

    public override string ToString()
    {
        return GetType().Name;
    }

    private class TunnelsNeededInfo
    {
        internal IClient Client;
        internal int TunnelsNeeded;
    }

    #region TunnelEvents

    public void TunnelEstablished(Tunnel tunnel)
    {
        ClientTunnelBuildSuccessRatio.Success();

        if (!PendingTunnels.TryRemove(tunnel, out var client))
        {
            Logging.LogDebug($"ClientTunnelProvider: WARNING. Unable to find client for established tunnel {tunnel}");
            return;
        }

        Destinations[tunnel] = client;

        if (tunnel is OutboundTunnel) ConsecutiveOutboundBuildFails[client] = 0;

        try
        {
            client.TunnelEstablished(tunnel);
        }
        catch (Exception ex)
        {
            Logging.Log(ex);
        }
    }

    public void TunnelBuildFailed(Tunnel tunnel, bool timeout)
    {
        ClientTunnelBuildSuccessRatio.Failure();

        if (!PendingTunnels.TryRemove(tunnel, out var client))
        {
            Logging.LogDebug($"ClientTunnelProvider: WARNING. Unable to find client TunnelBuildTimeout! {tunnel}");
            return;
        }

        if (tunnel is OutboundTunnel)
        {
            var fails = ConsecutiveOutboundBuildFails.AddOrUpdate(client, 1, (_, v) => v + 1);
            if (fails >= MaxConsecutiveClientBuildFails)
                Logging.LogWarning(
                    $"ClientTunnelProvider: {fails} consecutive outbound build failures, forcing exploratory reply tunnels.");
        }

        try
        {
            client.RemoveTunnel(tunnel, RemovalReason.BuildFailed);
        }
        catch (Exception ex)
        {
            Logging.Log(ex);
        }
    }

    public void TunnelFailed(Tunnel tunnel)
    {
        if (!Destinations.TryRemove(tunnel, out var client))
        {
            Logging.LogDebug($"ClientTunnelProvider: WARNING. Unable to find client for TunnelFailed {tunnel}");
            return;
        }

        client.RemoveTunnel(tunnel, RemovalReason.Failed);
    }

    public void TunnelExpired(Tunnel tunnel)
    {
        if (!Destinations.TryRemove(tunnel, out var client))
        {
            Logging.LogDebug($"ClientTunnelProvider: WARNING. Unable to find client for TunnelExpired {tunnel}");
            return;
        }

        client.RemoveTunnel(tunnel, RemovalReason.Expired);
    }

    #endregion
}