using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PRouterWeb.Services;
using I2PCore.Utils;

namespace I2PRouterWeb.Pages;

public class HttpProxyLogsModel : PageModel
{
    private readonly RouterService _routerService;

    public HttpProxyLogsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public IEnumerable<HttpProxyLogger.LogEntry> Logs { get; set; } = [];

    public void OnGet()
    {
        Logs = _routerService.GetHttpProxyLogs();
    }
}
