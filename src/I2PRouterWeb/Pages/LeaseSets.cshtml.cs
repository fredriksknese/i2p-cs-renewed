using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PRouterWeb.Services;

namespace I2PRouterWeb.Pages;

public class LeaseSetsModel : PageModel
{
    private readonly RouterService _routerService;

    public List<LeaseSetDisplayInfo> LeaseSets { get; set; } = new();
    public int TotalCount => LeaseSets.Count;

    public LeaseSetsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public void OnGet()
    {
        try
        {
            var netdb = I2PCore.NetDb.Inst;
            if (netdb != null)
            {
                // Get stored lease sets from NetDb
                var leaseSets = netdb.GetAllLeaseSets();
                if (leaseSets != null)
                {
                    foreach (var ls in leaseSets)
                    {
                        LeaseSets.Add(new LeaseSetDisplayInfo
                        {
                            DestHash = ls.Destination?.IdentHash?.Id32Short ?? "Unknown",
                            LeaseSetType = ls.GetType().Name,
                            LeaseCount = ls.Leases?.Count() ?? 0,
                            Expiration = ls.Expire.ToString("HH:mm:ss")
                        });
                    }
                }
            }

            _routerService.LogActivity("LeaseSets", "Viewed lease set information");
        }
        catch (Exception ex)
        {
            _routerService.LogActivity("Error", $"Error loading lease sets: {ex.Message}");
        }
    }
}

public class LeaseSetDisplayInfo
{
    public string DestHash { get; set; } = string.Empty;
    public string LeaseSetType { get; set; } = string.Empty;
    public int LeaseCount { get; set; }
    public string Expiration { get; set; } = string.Empty;
}
