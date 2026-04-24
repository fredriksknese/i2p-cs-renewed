using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PRouterWeb.Services;

namespace I2PRouterWeb.Pages;

public class TransitModel : PageModel
{
    private readonly RouterService _routerService;

    public List<TransitTunnelInfo> TransitTunnels { get; set; } = new();
    public int TotalTransitTunnels => TransitTunnels.Count;
    public int EndpointCount => TransitTunnels.Count(t => t.IsEndpoint);
    public int TransitCount => TransitTunnels.Count(t => !t.IsEndpoint);

    public TransitModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public void OnGet()
    {
        try
        {
            TransitTunnels = _routerService.GetTransitTunnels().ToList();
            _routerService.LogActivity("Transit", $"Viewed {TransitTunnels.Count} transit tunnels");
        }
        catch (Exception ex)
        {
            _routerService.LogActivity("Error", $"Error loading transit tunnels: {ex.Message}");
        }
    }
}
