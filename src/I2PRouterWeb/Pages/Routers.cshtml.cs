using I2PCore;
using I2PCore.Data;
using I2PCore.TransportLayer;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class RoutersModel : PageModel
{
    private readonly RouterService _routerService;

    public RoutersModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public List<RouterDisplayInfo> Routers { get; set; } = new();
    public int TotalRouters { get; set; }
    public int ConnectedCount { get; set; }
    public int Ntcp2Count { get; set; }
    public int Ssu2Count { get; set; }
    public int FloodfillCount { get; set; }
    public string SearchQuery { get; set; } = string.Empty;
    public bool ShowAll { get; set; }

    public void OnGet(string? search, bool? all)
    {
        try
        {
            SearchQuery = search ?? string.Empty;
            ShowAll = all ?? false;

            var netDb = NetDb.Inst;
            var transportProvider = TransportProvider.Inst;

            if (netDb == null) return;

            TotalRouters = netDb.RouterCount;
            FloodfillCount = netDb.FloodfillCount;

            if (transportProvider != null)
            {
                var protocolCounts = transportProvider.GetConnectionCountsByProtocol();
                Ntcp2Count = protocolCounts.GetValueOrDefault("NTCP2", 0);
                Ssu2Count = protocolCounts.GetValueOrDefault("SSU2", 0);
                ConnectedCount = protocolCounts.Values.Sum();
            }

            IEnumerable<I2PRouterInfo> filteredRouters;

            if (ShowAll || !string.IsNullOrEmpty(SearchQuery))
            {
                // Get ALL routers
                filteredRouters = netDb.FindRouterInfo((hash, info) => true);

                // Apply search filter if provided
                if (!string.IsNullOrEmpty(SearchQuery))
                    filteredRouters = filteredRouters.Where(r =>
                        r.Identity.IdentHash.Id32Short.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        r.Addresses.Any(a => a.Host?.ToString()?.Contains(SearchQuery) == true));
            }
            else
            {
                // Default: show only connected
                var connectedHashes = transportProvider?.GetConnectedRouterHashes() ?? Enumerable.Empty<I2PIdentHash>();
                filteredRouters = connectedHashes.Select(h => netDb[h]).Where(ri => ri != null)!;
            }

            Routers = filteredRouters.Select(ri =>
                {
                    var hash = ri.Identity.IdentHash;
                    var stats = netDb.Statistics[hash];

                    var isConnected = false;
                    var protocol = string.Empty;
                    var isPQ = false;

                    var activeTransport = transportProvider?.GetActiveTransport(hash);
                    if (activeTransport != null)
                    {
                        isConnected = true;
                        protocol = activeTransport.Protocol;
                        isPQ = activeTransport.IsPQ;
                    }

                    // Gather all transport types from addresses
                    var transports = ri.Addresses
                        .Select(a => a.TransportStyle?.ToString() ?? "?")
                        .Distinct()
                        .ToList();

                    var caps = ri.Options?["caps"]?.ToString() ?? "";
                    var version = ri.Options?["router.version"]?.ToString() ?? "";
                    var isFloodfill = caps.Contains('f');

                    // Get first IPv4 address
                    var addr = ri.Addresses.FirstOrDefault(a => a.Options.Contains("host"));
                    var host = addr?.Host?.ToString() ?? "";
                    var port = addr?.Port ?? 0;

                    return new RouterDisplayInfo
                    {
                        Hash = hash.Id32Short,
                        FullHash = hash.ToString(),
                        Host = host,
                        Port = port,
                        Caps = caps,
                        Version = version,
                        IsFloodfill = isFloodfill,
                        Transports = transports,
                        IsConnected = isConnected,
                        Protocol = protocol,
                        IsPQ = isPQ,
                        PublishedDate = (DateTime)ri.PublishedDate,
                        Score = stats?.Score ?? 0,
                        SuccessfulConnects = stats?.SuccessfulConnects ?? 0,
                        FailedConnects = stats?.FailedConnects ?? 0,
                        SuccessfulTunnelMember = stats?.SuccessfulTunnelMember ?? 0,
                        DeclinedTunnelMember = stats?.DeclinedTunnelMember ?? 0,
                        TunnelBuildTimeout = stats?.TunnelBuildTimeout ?? 0,
                        AddressCount = ri.Addresses?.Length ?? 0
                    };
                })
                .OrderByDescending(r => r.IsConnected)
                .ThenByDescending(r => r.Score)
                .ToList();

            _routerService.LogActivity("Routers", $"Viewed {Routers.Count} routers");
        }
        catch (Exception ex)
        {
            _routerService.LogActivity("Error", $"Error loading routers: {ex.Message}");
        }
    }
}

public class RouterDisplayInfo
{
    public string Hash { get; set; } = "";
    public string FullHash { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string Caps { get; set; } = "";
    public string Version { get; set; } = "";
    public bool IsFloodfill { get; set; }
    public List<string> Transports { get; set; } = new();
    public bool IsConnected { get; set; }
    public string Protocol { get; set; } = "";
    public bool IsPQ { get; set; }
    public DateTime PublishedDate { get; set; }
    public float Score { get; set; }
    public long SuccessfulConnects { get; set; }
    public long FailedConnects { get; set; }
    public long SuccessfulTunnelMember { get; set; }
    public long DeclinedTunnelMember { get; set; }
    public long TunnelBuildTimeout { get; set; }
    public int AddressCount { get; set; }
    public string RouterHash => Hash; // backward compat
}