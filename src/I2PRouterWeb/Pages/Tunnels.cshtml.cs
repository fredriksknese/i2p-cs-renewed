using I2PCore.TunnelLayer;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class TunnelsModel : PageModel
{
    private readonly RouterService _routerService;

    public TunnelsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public List<TunnelDisplayInfo> OutboundTunnels { get; set; } = new();
    public List<TunnelDisplayInfo> InboundTunnels { get; set; } = new();
    public List<TunnelDisplayInfo> PendingOutboundTunnels { get; set; } = new();
    public List<TunnelDisplayInfo> PendingInboundTunnels { get; set; } = new();

    public int TotalTunnels => OutboundTunnels.Count + InboundTunnels.Count + PendingOutboundTunnels.Count +
                               PendingInboundTunnels.Count;

    public int OutboundCount => OutboundTunnels.Count + PendingOutboundTunnels.Count;
    public int InboundCount => InboundTunnels.Count + PendingInboundTunnels.Count;

    public int ExploratoryCount => OutboundTunnels.Count(t => t.IsExploratory) +
                                   InboundTunnels.Count(t => t.IsExploratory) +
                                   PendingOutboundTunnels.Count(t => t.IsExploratory) +
                                   PendingInboundTunnels.Count(t => t.IsExploratory);

    public void OnGet()
    {
        try
        {
            var tunnelProvider = TunnelProvider.Inst;
            if (tunnelProvider == null) return;

            var outbound = tunnelProvider.GetOutboundTunnels();
            if (outbound != null)
                OutboundTunnels = outbound
                    .Where(t => t.Config.Pool != TunnelConfig.TunnelPool.External)
                    .Select(t => BuildInfo(t, "Outbound"))
                    .ToList();

            var inbound = tunnelProvider.GetInboundTunnels();
            if (inbound != null)
                InboundTunnels = inbound
                    .Where(t => t.Config.Pool != TunnelConfig.TunnelPool.External)
                    .Select(t => BuildInfo(t, "Inbound"))
                    .ToList();

            var pendingOut = tunnelProvider.GetPendingOutboundTunnels();
            if (pendingOut != null)
                PendingOutboundTunnels = pendingOut
                    .Where(t => t.Config.Pool != TunnelConfig.TunnelPool.External)
                    .Select(t => BuildInfo(t, "Outbound (Pending)"))
                    .ToList();

            var pendingIn = tunnelProvider.GetPendingInboundTunnels();
            if (pendingIn != null)
                PendingInboundTunnels = pendingIn
                    .Where(t => t.Config.Pool != TunnelConfig.TunnelPool.External)
                    .Select(t => BuildInfo(t, "Inbound (Pending)"))
                    .ToList();

            _routerService.LogActivity("Tunnels", $"Viewed tunnels: {TotalTunnels} total");
        }
        catch (Exception ex)
        {
            _routerService.LogActivity("Error", $"Error loading tunnels: {ex.Message}");
        }
    }

    private TunnelDisplayInfo BuildInfo(Tunnel tunnel, string direction)
    {
        var hops = new List<string>();
        try
        {
            if (tunnel.Config?.Info?.Hops != null)
                foreach (var hop in tunnel.Config.Info.Hops)
                    hops.Add(hop.Peer.IdentHash.Id64Short);
        }
        catch
        {
        }

        if (hops.Count == 0) hops.Add("(zero-hop)");

        long bytesSent = 0, bytesRecv = 0;
        double sendRate = 0, recvRate = 0;
        try
        {
            bytesSent = tunnel.Bandwidth?.SendBandwidth?.DataBytes ?? 0;
            bytesRecv = tunnel.Bandwidth?.ReceiveBandwidth?.DataBytes ?? 0;
            sendRate = tunnel.Bandwidth?.SendBandwidth?.Bitrate ?? 0;
            recvRate = tunnel.Bandwidth?.ReceiveBandwidth?.Bitrate ?? 0;
        }
        catch
        {
        }

        var ageMs = tunnel.CreationTime.DeltaToNow.ToMilliseconds;
        var estMs = tunnel.EstablishedTime.DeltaToNow.ToMilliseconds;

        return new TunnelDisplayInfo
        {
            TunnelId = tunnel.TunnelDebugTrace,
            Direction = direction,
            Pool = tunnel.Config?.Pool.ToString() ?? "?",
            HopCount = tunnel.Config?.Info?.Hops?.Count ?? 0,
            Hops = hops,
            IsActive = tunnel.Active,
            IsEstablished = tunnel.Established,
            ReceiveTunnelId = tunnel.ReceiveTunnelId?.ToString() ?? "",
            AgeSeconds = ageMs / 1000,
            EstablishedAgoSeconds = estMs / 1000,
            BytesSent = bytesSent,
            BytesReceived = bytesRecv,
            SendBitrate = sendRate,
            ReceiveBitrate = recvRate,
            IsExploratory = tunnel.Config?.Pool == TunnelConfig.TunnelPool.Exploratory
        };
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }

    public static string FormatRate(double bitsPerSec)
    {
        if (bitsPerSec < 1000) return $"{bitsPerSec:F0} bps";
        if (bitsPerSec < 1000000) return $"{bitsPerSec / 1000:F1} Kbps";
        return $"{bitsPerSec / 1000000:F1} Mbps";
    }
}

public class TunnelDisplayInfo
{
    public string TunnelId { get; set; } = "";
    public string Direction { get; set; } = "";
    public string Pool { get; set; } = "";
    public int HopCount { get; set; }
    public List<string> Hops { get; set; } = new();
    public bool IsActive { get; set; }
    public bool IsEstablished { get; set; }
    public string ReceiveTunnelId { get; set; } = "";
    public int AgeSeconds { get; set; }
    public int EstablishedAgoSeconds { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public double SendBitrate { get; set; }
    public double ReceiveBitrate { get; set; }
    public bool IsExploratory { get; set; }
}