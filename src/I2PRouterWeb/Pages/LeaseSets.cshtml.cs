using Microsoft.AspNetCore.Mvc.RazorPages;
using I2PCore.Data;
using I2PCore.Utils;
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
                var leaseSets = netdb.GetAllLeaseSets();
                if (leaseSets != null)
                {
                    foreach (var ls in leaseSets)
                    {
                        var dest = ls.Destination;
                        var identHash = dest?.IdentHash;

                        var info = new LeaseSetDisplayInfo
                        {
                            DestinationBase64 = dest != null
                                ? Convert.ToBase64String(dest.ToByteArray())
                                : "",
                            B32Address = identHash != null
                                ? $"{identHash.Id32}.b32.i2p"
                                : "",
                            DestHashShort = identHash?.Id32Short ?? "Unknown",
                            LeaseSetType = ls.MessageType.ToString(),
                            TypeClassName = ls.GetType().Name,
                            Expiration = ls.Expire,
                        };

                        // Public keys
                        if (ls.PublicKeys != null)
                        {
                            foreach (var pk in ls.PublicKeys)
                            {
                                info.PublicKeys.Add(new PublicKeyDisplayInfo
                                {
                                    KeyType = pk.Certificate?.PublicKeyType.ToString() ?? "Unknown",
                                    KeyLength = pk.Key.Length,
                                    KeyBase64 = Convert.ToBase64String(pk.Key.ToByteArray()),
                                });
                            }
                        }

                        // Leases
                        if (ls.Leases != null)
                        {
                            foreach (var lease in ls.Leases)
                            {
                                info.Leases.Add(new LeaseDisplayInfo
                                {
                                    TunnelGatewayHash = lease.TunnelGw?.Id32Short ?? "Unknown",
                                    TunnelGatewayB32 = lease.TunnelGw != null
                                        ? $"{lease.TunnelGw.Id32}.b32.i2p"
                                        : "",
                                    TunnelId = lease.TunnelId?.ToString() ?? "0",
                                    Expiration = lease.Expire,
                                });
                            }
                        }

                        LeaseSets.Add(info);
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
    public string DestinationBase64 { get; set; } = string.Empty;
    public string B32Address { get; set; } = string.Empty;
    public string DestHashShort { get; set; } = string.Empty;
    public string LeaseSetType { get; set; } = string.Empty;
    public string TypeClassName { get; set; } = string.Empty;
    public DateTime Expiration { get; set; }
    public List<PublicKeyDisplayInfo> PublicKeys { get; set; } = new();
    public List<LeaseDisplayInfo> Leases { get; set; } = new();
}

public class PublicKeyDisplayInfo
{
    public string KeyType { get; set; } = string.Empty;
    public int KeyLength { get; set; }
    public string KeyBase64 { get; set; } = string.Empty;
}

public class LeaseDisplayInfo
{
    public string TunnelGatewayHash { get; set; } = string.Empty;
    public string TunnelGatewayB32 { get; set; } = string.Empty;
    public string TunnelId { get; set; } = string.Empty;
    public DateTime Expiration { get; set; }
}
