using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PRouterWeb.Services;
using I2PCore.SessionLayer;

namespace I2PRouterWeb.Pages;

public class TransportsModel : PageModel
{
    private readonly RouterService _routerService;

    public int Ntcp2Sessions { get; set; }
    public int Ntcp2Connecting { get; set; }
    public int Ssu2Sessions { get; set; }
    public int Ssu2Connecting { get; set; }
    public int Ntcp2BlockedIPs { get; set; }
    public int Ssu2BlockedIPs { get; set; }
    public bool Ntcp2PQEnabled { get; set; }
    public bool IsFirewalled { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }

    public string FormattedBytesSent => FormatBytes(BytesSent);
    public string FormattedBytesReceived => FormatBytes(BytesReceived);

    public TransportsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public void OnGet()
    {
        try
        {
            var ctx = RouterContext.Inst;
            if (ctx != null)
            {
                IsFirewalled = ctx.IsFirewalled;
            }

            var tp = I2PCore.TransportLayer.TransportProvider.Inst;
            if (tp != null)
            {
                Ntcp2Sessions = tp.Ntcp2SessionCount;
                Ntcp2Connecting = tp.Ntcp2ConnectingCount;
                Ssu2Sessions = tp.Ssu2SessionCount;
                Ssu2Connecting = tp.Ssu2ConnectingCount;
                Ntcp2BlockedIPs = tp.Ntcp2BlockedCount;
                Ssu2BlockedIPs = tp.Ssu2BlockedCount;
                Ntcp2PQEnabled = true; // ML-KEM-768 (pq=4) advertised
            }

            _routerService.LogActivity("Transports", "Viewed transport information");
        }
        catch (Exception ex)
        {
            _routerService.LogActivity("Error", $"Error loading transports: {ex.Message}");
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
    }
}
