using System.Collections.Generic;
using System.Linq;
using I2PCore;
using I2PCore.SessionLayer;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class ManageTunnelsModel : PageModel
{
    private readonly RouterService _routerService;

    public ManageTunnelsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    [BindProperty] public int HttpProxyPort { get; set; }
    [BindProperty] public RouterContext.HttpProxyEncryptionType ProxyEncryption { get; set; }
    [BindProperty] public bool HttpProxyEnabled { get; set; }

    [BindProperty] public string NewTunnelName { get; set; } = "";
    [BindProperty] public string NewTunnelType { get; set; } = "client";
    [BindProperty] public string NewTunnelHost { get; set; } = "127.0.0.1";
    [BindProperty] public int NewTunnelPort { get; set; }
    [BindProperty] public string NewTunnelDestination { get; set; } = "";
    [BindProperty] public int NewTunnelHops { get; set; } = 3;
    [BindProperty] public int NewTunnelQuantity { get; set; } = 3;
    [BindProperty] public string NewTunnelSigningKeyType { get; set; } = "EdDsaSha512Ed25519";
    [BindProperty] public List<string> NewTunnelCryptoKeyTypes { get; set; } = new() { "X25519" };
    [BindProperty] public bool NewTunnelStartOnLaunch { get; set; }

    public List<TunnelConfigInfo> GenericTunnels { get; set; } = new();
    public bool HttpProxyRunning { get; set; }
    public string? SuccessMessage { get; set; }
    public string? ErrorMessage { get; set; }

    public void OnGet()
    {
        LoadData();
    }

    public IActionResult OnPostUpdateHttpProxy()
    {
        _routerService.HttpProxyPort = HttpProxyPort;
        _routerService.ProxyEncryption = ProxyEncryption;
        
        // We need to apply these settings. Since I removed them from ApplySettings parameters 
        // (well, I kept them but the UI doesn't send them), I'll just use the ones from _routerService.
        _routerService.ApplySettings(
            _routerService.ExternalAddress, 
            _routerService.TcpPort, 
            _routerService.UdpPort, 
            _routerService.IsFirewalled, 
            _routerService.UseIPv6, 
            _routerService.EnableSSU2, 
            _routerService.FloodfillEnabled,
            ProxyEncryption,
            _routerService.MaxTransitTunnels,
            _routerService.TransitSharePercent,
            _routerService.MaxNtcp2InboundConnections,
            _routerService.MaxNtcp2OutboundConnections);

        SuccessMessage = "HTTP Proxy settings updated.";
        LoadData();
        return Page();
    }

    public IActionResult OnPostCreateTunnel()
    {
        if (string.IsNullOrWhiteSpace(NewTunnelName))
        {
            ErrorMessage = "Tunnel name is required.";
            LoadData();
            return Page();
        }

        // Ensure MLKEM variants come before plain X25519 so remote routers
        // prefer the stronger post-quantum option (first listed = preferred).
        var orderedCryptoKeys = NewTunnelCryptoKeyTypes
            .OrderByDescending(k => k.Contains("MLKEM", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var cryptoTypes = string.Join(",", orderedCryptoKeys);
        var options = new Dictionary<string, string>
        {
            { "type", NewTunnelType },
            { "port", NewTunnelPort.ToString() },
            { "inbound.length", NewTunnelHops.ToString() },
            { "outbound.length", NewTunnelHops.ToString() },
            { "inbound.quantity", NewTunnelQuantity.ToString() },
            { "outbound.quantity", NewTunnelQuantity.ToString() },
            { "signaturetype", NewTunnelSigningKeyType },
            { "cryptotype", orderedCryptoKeys.FirstOrDefault() ?? "X25519" },
            { "i2cp.leaseSetEncType", cryptoTypes },
            { "startOnLaunch", NewTunnelStartOnLaunch.ToString().ToLowerInvariant() }
        };

        if (NewTunnelType == "client" || NewTunnelType == "httpclient")
        {
            options["destination"] = NewTunnelDestination;
        }
        else
        {
            options["host"] = NewTunnelHost;
            // Persist keys for server tunnels
            options["keys"] = $"tunnel-{NewTunnelName.Replace(" ", "_")}.dat";
        }

        _routerService.SaveTunnelConfig(NewTunnelName, options);
        // Requirement 1: Don't start automatically
        // _routerService.StartTunnel(NewTunnelName);

        SuccessMessage = $"Tunnel '{NewTunnelName}' created. You must start it manually.";
        LoadData();
        return Page();
    }

    public IActionResult OnPostAction(string name, string action)
    {
        if (action == "start") _routerService.StartTunnel(name);
        else if (action == "stop") _routerService.StopTunnel(name);
        else if (action == "toggle_autostart") _routerService.ToggleTunnelAutostart(name);
        else if (action == "remove")
        {
            _routerService.StopTunnel(name);
            _routerService.RemoveTunnelConfig(name);
        }

        LoadData();
        return Page();
    }

    private void LoadData()
    {
        HttpProxyPort = _routerService.HttpProxyPort;
        ProxyEncryption = _routerService.ProxyEncryption;
        HttpProxyRunning = _routerService.IsHttpProxyRunning;

        GenericTunnels.Clear();
        foreach (var config in _routerService.GetTunnelsConfig())
        {
            GenericTunnels.Add(new TunnelConfigInfo
            {
                Name = config.Key,
                Type = config.Value.GetValueOrDefault("type", "unknown"),
                Port = int.Parse(config.Value.GetValueOrDefault("port", "0")),
                IsRunning = _routerService.IsTunnelRunning(config.Key),
                StartOnLaunch = config.Value.GetValueOrDefault("startOnLaunch", "false").ToLowerInvariant() == "true",
                Base32Address = _routerService.GetTunnelB32Address(config.Key)
            });
        }
    }

    public class TunnelConfigInfo
    {
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public int Port { get; set; }
        public bool IsRunning { get; set; }
        public bool StartOnLaunch { get; set; }
        public string? Base32Address { get; set; }
    }
}
