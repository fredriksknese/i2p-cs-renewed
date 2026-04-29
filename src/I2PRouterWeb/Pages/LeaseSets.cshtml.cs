using I2PCore;
using I2PCore.Client;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class LeaseSetsModel : PageModel
{
    private readonly RouterService _routerService;

    public LeaseSetsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public List<LeaseSetDisplayInfo> LeaseSets { get; set; } = new();
    public int TotalCount => LeaseSets.Count;

    public void OnGet()
    {
        try
        {
            // Build a map of IdentHash → tunnel pool names that have a session for it
            var boundPools = BuildBoundPoolsMap();

            var netdb = NetDb.Inst;
            if (netdb != null)
            {
                var leaseSets = netdb.GetAllLeaseSets();
                if (leaseSets != null)
                    foreach (var ls in leaseSets)
                    {
                        var dest = ls.Destination;
                        var identHash = dest?.IdentHash;

                        var info = new LeaseSetDisplayInfo
                        {
                            DestinationBase64 = dest != null
                                ? FreenetBase64.Encode(new I2PByteBlock(dest.ToByteArray()))
                                : "",
                            B32Address = identHash != null
                                ? $"{identHash.Id32}.b32.i2p"
                                : "",
                            DestHashShort = identHash?.Id64 ?? "Unknown",
                            LeaseSetType = ls.MessageType.ToString(),
                            TypeClassName = ls.GetType().Name,
                            Expiration = ls.Expire
                        };

                        // Public keys
                        if (ls.PublicKeys != null)
                            foreach (var pk in ls.PublicKeys)
                                info.PublicKeys.Add(new PublicKeyDisplayInfo
                                {
                                    KeyType = pk.Certificate?.PublicKeyType.ToString() ?? "Unknown",
                                    KeyLength = pk.Key.Length,
                                    KeyBase64 = FreenetBase64.Encode(new I2PByteBlock(pk.Key.ToByteArray()))
                                });

                        // Leases
                        if (ls.Leases != null)
                            foreach (var lease in ls.Leases)
                                info.Leases.Add(new LeaseDisplayInfo
                                {
                                    TunnelGatewayHash = lease.TunnelGw?.Id64Short ?? "Unknown",
                                    TunnelGatewayB32 = lease.TunnelGw != null
                                        ? $"{lease.TunnelGw.Id32}.b32.i2p"
                                        : "",
                                    TunnelId = lease.TunnelId?.ToString() ?? "0",
                                    Expiration = lease.Expire
                                });

                        // Which tunnel pools have a session referencing this LeaseSet?
                        if (identHash != null && boundPools.TryGetValue(identHash, out var pools))
                            info.BoundTunnelPools = pools;

                        LeaseSets.Add(info);
                    }
            }

            _routerService.LogActivity("LeaseSets", "Viewed lease set information");
        }
        catch (Exception ex)
        {
            _routerService.LogActivity("Error", $"Error loading lease sets: {ex.Message}");
        }
    }

    /// <summary>
    ///     Build a map of remote IdentHash → list of tunnel pool names that have
    ///     a session (and therefore a cached LeaseSet) for that destination.
    /// </summary>
    private static Dictionary<I2PIdentHash, List<string>> BuildBoundPoolsMap()
    {
        var result = new Dictionary<I2PIdentHash, List<string>>();

        try
        {
            // Check the shared HTTP proxy destination
            var proxyDest = ClientContext.Inst?.SharedProxyDestination;
            if (proxyDest != null)
                foreach (var kvp in proxyDest.MySessions.Sessions)
                    if (kvp.Value.RemoteLeaseSet != null)
                    {
                        if (!result.TryGetValue(kvp.Key, out var list))
                        {
                            list = new List<string>();
                            result[kvp.Key] = list;
                        }

                        list.Add("HTTP Proxy");
                    }

            // Check all named tunnels
            if (ClientContext.Inst != null)
                foreach (var name in ClientContext.Inst.TunnelNames)
                {
                    var tunnel = ClientContext.Inst.GetTunnel(name);
                    if (tunnel?.MyDestination == null) continue;

                    foreach (var kvp in tunnel.MyDestination.MySessions.Sessions)
                        if (kvp.Value.RemoteLeaseSet != null)
                        {
                            if (!result.TryGetValue(kvp.Key, out var list))
                            {
                                list = new List<string>();
                                result[kvp.Key] = list;
                            }

                            list.Add(name);
                        }
                }
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"LeaseSets: Error building bound pools map: {ex.Message}");
        }

        return result;
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
        public List<string> BoundTunnelPools { get; set; } = new();
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
}