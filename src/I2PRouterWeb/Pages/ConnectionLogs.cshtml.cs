using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PRouterWeb.Services;
using I2PCore.TransportLayer.Log;

namespace I2PRouterWeb.Pages;

public class ConnectionLogsModel : PageModel
{
    private readonly RouterService _routerService;

    public IEnumerable<TransportConnectionLogger.LogEntry> Logs { get; set; } = Array.Empty<TransportConnectionLogger.LogEntry>();

    public ConnectionLogsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public void OnGet()
    {
        Logs = _routerService.GetTransportConnectionLogs();
    }
}
