using I2PCore;
using I2PCore.TransportLayer;
using I2PCore.TransportLayer.Log;
using I2PCore.TunnelLayer;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class RouterDetailModel : PageModel
{
    private readonly RouterService _routerService;

    public RouterDetailModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    public bool Found { get; set; }
    public string Hash { get; set; } = "";
    public string FullIdentHash { get; set; } = "";
    public string FullIdentHash64 { get; set; } = "";
    public DateTime PublishedDate { get; set; }
    public string Caps { get; set; } = "";
    public string Version { get; set; } = "";
    public string NetId { get; set; } = "";
    public bool IsFloodfill { get; set; }
    public string SignatureType { get; set; } = "";
    public string CryptoType { get; set; } = "";

    // Connection
    public bool IsConnected { get; set; }
    public string Protocol { get; set; } = "";
    public bool IsPQ { get; set; }
    public bool IsOutgoing { get; set; }

    // Addresses
    public List<AddressDetail> Addresses { get; set; } = new();

    // All router options
    public Dictionary<string, string> Options { get; set; } = new();

    // Statistics
    public float Score { get; set; }
    public float ConnectScore { get; set; }
    public float TunnelMemberScore { get; set; }
    public float FloodfillScore { get; set; }
    public float TunnelTestScore { get; set; }
    public float IdentResolveScore { get; set; }
    public float FirewallPenalty { get; set; }
    public float BandwidthBonus { get; set; }
    public float BuildTimePenalty { get; set; }
    public float InfoFaultyPenalty { get; set; }

    public long SuccessfulConnects { get; set; }
    public long FailedConnects { get; set; }
    public long SuccessfulTunnelMember { get; set; }
    public long DeclinedTunnelMember { get; set; }
    public long SuccessfulTunnelTest { get; set; }
    public long FailedTunnelTest { get; set; }
    public long TunnelBuildTimeout { get; set; }
    public long TunnelBuildTimeMsPerHop { get; set; }
    public long FloodfillUpdateSuccess { get; set; }
    public long FloodfillUpdateTimeout { get; set; }
    public long InformationFaulty { get; set; }
    public long SlowHandshakeConnect { get; set; }
    public float MaxBandwidthSeen { get; set; }
    public bool StatsIsFirewalled { get; set; }
    public string LastSeen { get; set; } = "";

    // Tunnels this router participates in
    public List<TunnelParticipation> Tunnels { get; set; } = new();

    public void OnGet(string? hash)
    {
        if (string.IsNullOrEmpty(hash)) return;

        Hash = hash;
        var netDb = NetDb.Inst;
        if (netDb == null) return;

        var routers = netDb.FindRouterInfo((h, r) =>
            h.Id64.Equals(hash, StringComparison.OrdinalIgnoreCase) ||
            h.Id64Short.Equals(hash, StringComparison.OrdinalIgnoreCase) ||
            h.Id32.Equals(hash, StringComparison.OrdinalIgnoreCase) ||
            h.Id32Short.Equals(hash, StringComparison.OrdinalIgnoreCase));
 
        var ri = routers.FirstOrDefault();
        if (ri == null)
        {
            ri = TransportConnectionLogger.Inst.GetRouterInfo(hash);
        }

        if (ri == null) return;

        Found = true;
        var identHash = ri.Identity.IdentHash;
        FullIdentHash = identHash.ToString();
        FullIdentHash64 = identHash.Id64;
        PublishedDate = (DateTime)ri.PublishedDate;
        SignatureType = ri.Identity.Certificate.SignatureType.ToString();
        CryptoType = ri.Identity.Certificate.PublicKeyType.ToString();

        // Options
        if (ri.Options != null)
        {
            Caps = ri.Options["caps"] ?? "";
            Version = ri.Options["router.version"] ?? "";
            NetId = ri.Options["netId"] ?? "";
            IsFloodfill = Caps.Contains('f');

            try
            {
                foreach (var pair in ri.Options) Options[pair.Key?.ToString() ?? "?"] = pair.Value?.ToString() ?? "";
            }
            catch
            {
            }
        }

        // Connection status
        var transportProvider = TransportProvider.Inst;
        var activeTransport = transportProvider?.GetActiveTransport(identHash);
        if (activeTransport != null)
        {
            IsConnected = true;
            Protocol = activeTransport.Protocol;
            IsPQ = activeTransport.IsPQ;
            IsOutgoing = activeTransport.IsOutgoing;
        }

        // Addresses
        if (ri.Addresses != null)
            foreach (var addr in ri.Addresses)
            {
                var detail = new AddressDetail
                {
                    Transport = addr.TransportStyle?.ToString() ?? "?",
                    Host = addr.Host?.ToString() ?? "",
                    Port = addr.Port,
                    Cost = addr.Cost
                };

                try
                {
                    if (addr.Options != null)
                        foreach (var opt in addr.Options)
                            detail.Options[opt.Key?.ToString() ?? "?"] = opt.Value?.ToString() ?? "";
                }
                catch
                {
                }

                Addresses.Add(detail);
            }

        // Statistics
        var stats = netDb.Statistics[identHash];
        if (stats != null)
        {
            Score = stats.Score;
            ConnectScore = stats.ConnectScore;
            TunnelMemberScore = stats.TunnelMemberScore;
            FloodfillScore = stats.FloodfillScore;
            TunnelTestScore = stats.TunnelTestScore;
            IdentResolveScore = stats.IdentResolveScore;
            FirewallPenalty = stats.FirewallPenalty;
            BandwidthBonus = stats.BandwidthBonus;
            BuildTimePenalty = stats.BuildTimePenalty;
            InfoFaultyPenalty = stats.InfoFaultyPenalty;

            SuccessfulConnects = stats.SuccessfulConnects;
            FailedConnects = stats.FailedConnects;
            SuccessfulTunnelMember = stats.SuccessfulTunnelMember;
            DeclinedTunnelMember = stats.DeclinedTunnelMember;
            SuccessfulTunnelTest = stats.SuccessfulTunnelTest;
            FailedTunnelTest = stats.FailedTunnelTest;
            TunnelBuildTimeout = stats.TunnelBuildTimeout;
            TunnelBuildTimeMsPerHop = stats.TunnelBuildTimeMsPerHop;
            FloodfillUpdateSuccess = stats.FloodfillUpdateSuccess;
            FloodfillUpdateTimeout = stats.FloodfillUpdateTimeout;
            InformationFaulty = stats.InformationFaulty;
            SlowHandshakeConnect = stats.SlowHandshakeConnect;
            MaxBandwidthSeen = stats.MaxBandwidthSeen;
            StatsIsFirewalled = stats.IsFirewalled;
            LastSeen = stats.LastSeen?.ToString() ?? "Never";
        }

        // Find tunnels this router participates in
        var tp = TunnelProvider.Inst;
        if (tp != null)
        {
            foreach (var t in tp.GetOutboundTunnels())
                if (t.TunnelMembers?.Any(m => m.IdentHash == identHash) == true)
                    Tunnels.Add(new TunnelParticipation
                    {
                        TunnelId = t.TunnelDebugTrace,
                        Direction = "Outbound",
                        Pool = t.Config?.Pool.ToString() ?? "?",
                        IsActive = t.Active
                    });

            foreach (var t in tp.GetInboundTunnels())
                if (t.TunnelMembers?.Any(m => m.IdentHash == identHash) == true)
                    Tunnels.Add(new TunnelParticipation
                    {
                        TunnelId = t.TunnelDebugTrace,
                        Direction = "Inbound",
                        Pool = t.Config?.Pool.ToString() ?? "?",
                        IsActive = t.Active
                    });
        }
    }
}

public class AddressDetail
{
    public string Transport { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public int Cost { get; set; }
    public Dictionary<string, string> Options { get; set; } = new();
}

public class TunnelParticipation
{
    public string TunnelId { get; set; } = "";
    public string Direction { get; set; } = "";
    public string Pool { get; set; } = "";
    public bool IsActive { get; set; }
}