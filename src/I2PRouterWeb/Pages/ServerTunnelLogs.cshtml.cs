using I2PCore.Utils;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class ServerTunnelLogsModel : PageModel
{
    private readonly RouterService _routerService;

    public ServerTunnelLogsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public IEnumerable<ServerTunnelLogger.LogEntry> Logs { get; set; } = [];

    public void OnGet()
    {
        Logs = _routerService.GetServerTunnelLogs();
    }
}
