using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class NetDbStatsModel : PageModel
{
    private readonly RouterService _routerService;

    public NetDbStatsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public bool FloodfillEnabled => _routerService.FloodfillEnabled;

    public IEnumerable<(string B32Address, int Count)> TopLeaseSetLookups { get; set; } =
        Array.Empty<(string, int)>();

    public IEnumerable<(string RouterHash, string ShortId, int Count)> TopRouterInfoLookups { get; set; } =
        Array.Empty<(string, string, int)>();

    public void OnGet()
    {
        if (!FloodfillEnabled) return;

        TopLeaseSetLookups = _routerService.GetTopLeaseSetLookups();
        TopRouterInfoLookups = _routerService.GetTopRouterInfoLookups();
    }
}
