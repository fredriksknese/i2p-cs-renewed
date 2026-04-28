using I2PCore.TransportLayer.Log;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;

namespace I2PRouterWeb.Pages;

public class ConnectionLogsModel : PageModel
{
    private readonly RouterService _routerService;

    public ConnectionLogsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public IEnumerable<TransportConnectionLogger.LogEntry> Logs { get; set; } =
        Array.Empty<TransportConnectionLogger.LogEntry>();

    public TransportConnectionLogger.ConnectionStats Stats { get; set; } = new();

    public IEnumerable<(string Reason, int Count, IEnumerable<(string ShortId, string FullId)> Routers)>
        Ntcp2InboundFailures { get; set; } =
        Array.Empty<(string, int, IEnumerable<(string, string)>)>();

    public IEnumerable<(string Reason, int Count, IEnumerable<(string ShortId, string FullId)> Routers)>
        Ntcp2OutboundFailures { get; set; } =
        Array.Empty<(string, int, IEnumerable<(string, string)>)>();

    public IEnumerable<(string Reason, int Count, IEnumerable<(string ShortId, string FullId)> Routers)>
        Ssu2InboundFailures { get; set; } =
        Array.Empty<(string, int, IEnumerable<(string, string)>)>();

    public IEnumerable<(string Reason, int Count, IEnumerable<(string ShortId, string FullId)> Routers)>
        Ssu2OutboundFailures { get; set; } =
        Array.Empty<(string, int, IEnumerable<(string, string)>)>();

    public IEnumerable<(string ShortId, string FullId, int Count, IEnumerable<(string Reason, int Count)> Reasons)>
        Ntcp2InboundFailedRouters { get; set; } =
        Array.Empty<(string, string, int, IEnumerable<(string, int)>)>();

    public IEnumerable<(string ShortId, string FullId, int Count, IEnumerable<(string Reason, int Count)> Reasons)>
        Ntcp2OutboundFailedRouters { get; set; } =
        Array.Empty<(string, string, int, IEnumerable<(string, int)>)>();

    public IEnumerable<(string ShortId, string FullId, int Count, IEnumerable<(string Reason, int Count)> Reasons)>
        Ssu2InboundFailedRouters { get; set; } =
        Array.Empty<(string, string, int, IEnumerable<(string, int)>)>();

    public IEnumerable<(string ShortId, string FullId, int Count, IEnumerable<(string Reason, int Count)> Reasons)>
        Ssu2OutboundFailedRouters { get; set; } =
        Array.Empty<(string, string, int, IEnumerable<(string, int)>)>();

    public void OnGet()
    {
        Logs = _routerService.GetTransportConnectionLogs();
        Stats = _routerService.GetConnectionStats();
        Ntcp2InboundFailures = _routerService.GetTopFailureReasons("NTCP2", "Inbound");
        Ntcp2OutboundFailures = _routerService.GetTopFailureReasons("NTCP2", "Outbound");
        Ssu2InboundFailures = _routerService.GetTopFailureReasons("SSU2", "Inbound");
        Ssu2OutboundFailures = _routerService.GetTopFailureReasons("SSU2", "Outbound");

        Ntcp2InboundFailedRouters = _routerService.GetTopFailedRouters("NTCP2", "Inbound");
        Ntcp2OutboundFailedRouters = _routerService.GetTopFailedRouters("NTCP2", "Outbound");
        Ssu2InboundFailedRouters = _routerService.GetTopFailedRouters("SSU2", "Inbound");
        Ssu2OutboundFailedRouters = _routerService.GetTopFailedRouters("SSU2", "Outbound");
    }

    public FileResult OnGetExportCsv(string transport, string direction, string reason)
    {
        var failures = _routerService.GetFailuresByReason(transport, direction, reason);
        var csv = new StringBuilder();
        csv.AppendLine("Reason,RemoteEndPoint,ShortId,FullId,PublishedDate,Addresses,Options");

        foreach (var failure in failures)
        {
            var addresses = failure.RouterInfo != null
                ? string.Join("; ", failure.RouterInfo.Addresses.Select(a => a.ToString().Replace("\r", "").Replace("\n", " ").Trim()))
                : "";
            var options = failure.RouterInfo != null
                ? string.Join("; ", failure.RouterInfo.Options.Select(kv => $"{kv.Key}={kv.Value}"))
                : "";
            var published = failure.RouterInfo?.PublishedDate.ToString() ?? "";
            var endPoint = failure.RemoteEndPoint?.ToString() ?? "";

            csv.AppendLine($"{EscapeCsv(failure.Reason)},{EscapeCsv(endPoint)},{EscapeCsv(failure.RouterId)},{EscapeCsv(failure.RouterFullId)},{EscapeCsv(published)},{EscapeCsv(addresses)},{EscapeCsv(options)}");
        }

        var bytes = Encoding.UTF8.GetBytes(csv.ToString());
        var fileName = $"failures_{transport}_{direction}_{reason.Replace(" ", "_")}_{DateTime.Now:yyyyMMddHHmmss}.csv";
        foreach (var c in Path.GetInvalidFileNameChars()) fileName = fileName.Replace(c, '_');

        return File(bytes, "text/csv", fileName);
    }

    private string EscapeCsv(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value.Contains(",") || value.Contains("\"") || value.Contains("\n") || value.Contains("\r"))
        {
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
