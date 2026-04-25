using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class NetDbLogModel : PageModel
{
    private readonly NetDbLogService _netDbLogService;

    public NetDbLogModel(NetDbLogService netDbLogService)
    {
        _netDbLogService = netDbLogService;
    }

    public IEnumerable<NetDbLogEntry> Logs { get; private set; } = [];

    public void OnGet()
    {
        Logs = _netDbLogService.GetLogs();
    }
}