using I2PCore.TransportLayer.Log;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

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

    public void OnGet()
    {
        Logs = _routerService.GetTransportConnectionLogs();
    }
}