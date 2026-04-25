using System.Net;
using I2PCore.SessionLayer;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class SettingsModel : PageModel
{
    private readonly RouterService _routerService;

    public SettingsModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    [BindProperty] public string? ExternalAddress { get; set; }

    [BindProperty] public int TcpPort { get; set; }

    [BindProperty] public int UdpPort { get; set; }

    [BindProperty] public bool IsFirewalled { get; set; }

    [BindProperty] public bool UseIPv6 { get; set; }

    [BindProperty] public bool EnableSSU2 { get; set; }

    [BindProperty] public bool FloodfillEnabled { get; set; }

    [BindProperty] public int MaxTransitTunnels { get; set; }

    [BindProperty] public int MaxNtcp2InboundConnections { get; set; }

    [BindProperty] public int MaxNtcp2OutboundConnections { get; set; }

    [BindProperty] public int TransitSharePercent { get; set; }

    [BindProperty] public RouterContext.HttpProxyEncryptionType ProxyEncryption { get; set; }

    [BindProperty] public int HttpProxyPort { get; set; }

    public string? CurrentExternalAddress { get; set; }
    public string? DetectedExternalAddress { get; set; }
    public int CurrentTcpPort { get; set; }
    public int CurrentUdpPort { get; set; }
    public bool CurrentIsFirewalled { get; set; }
    public bool CurrentUseIPv6 { get; set; }
    public bool CurrentEnableSSU2 { get; set; }
    public bool CurrentFloodfillEnabled { get; set; }
    public int CurrentMaxTransitTunnels { get; set; }
    public int CurrentMaxNtcp2InboundConnections { get; set; }
    public int CurrentMaxNtcp2OutboundConnections { get; set; }
    public int CurrentTransitSharePercent { get; set; }
    public RouterContext.HttpProxyEncryptionType CurrentProxyEncryption { get; set; }
    public int CurrentHttpProxyPort { get; set; }
    public bool CurrentHttpProxyRunning { get; set; }
    public string? SuccessMessage { get; set; }

    public void OnGet()
    {
        LoadCurrentSettings();

        // Pre-fill form with current settings
        ExternalAddress = _routerService.ExternalAddress?.ToString();
        TcpPort = _routerService.TcpPort;
        UdpPort = _routerService.UdpPort;
        IsFirewalled = _routerService.IsFirewalled;
        UseIPv6 = _routerService.UseIPv6;
        EnableSSU2 = _routerService.EnableSSU2;
        FloodfillEnabled = _routerService.FloodfillEnabled;
        MaxTransitTunnels = _routerService.MaxTransitTunnels;
        MaxNtcp2InboundConnections = _routerService.MaxNtcp2InboundConnections;
        MaxNtcp2OutboundConnections = _routerService.MaxNtcp2OutboundConnections;
        TransitSharePercent = _routerService.TransitSharePercent;
        ProxyEncryption = _routerService.ProxyEncryption;
        HttpProxyPort = _routerService.HttpProxyPort;
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
        {
            LoadCurrentSettings();
            return Page();
        }

        IPAddress? ipAddress = null;
        if (!string.IsNullOrWhiteSpace(ExternalAddress))
            if (!IPAddress.TryParse(ExternalAddress, out ipAddress))
            {
                ModelState.AddModelError(nameof(ExternalAddress), "Invalid IP address format");
                LoadCurrentSettings();
                return Page();
            }

        _routerService.HttpProxyPort = HttpProxyPort;
        _routerService.ApplySettings(ipAddress, TcpPort, UdpPort, IsFirewalled, UseIPv6, EnableSSU2, FloodfillEnabled,
            ProxyEncryption, MaxTransitTunnels, TransitSharePercent, MaxNtcp2InboundConnections,
            MaxNtcp2OutboundConnections);

        LoadCurrentSettings();
        SuccessMessage = "Settings applied successfully!";

        return Page();
    }

    private void LoadCurrentSettings()
    {
        CurrentExternalAddress = _routerService.ExternalAddress?.ToString();
        DetectedExternalAddress = _routerService.DetectedExternalAddress?.ToString();
        CurrentTcpPort = _routerService.TcpPort;
        CurrentUdpPort = _routerService.UdpPort;
        CurrentIsFirewalled = _routerService.IsFirewalled;
        CurrentUseIPv6 = _routerService.UseIPv6;
        CurrentEnableSSU2 = _routerService.EnableSSU2;
        CurrentFloodfillEnabled = _routerService.FloodfillEnabled;
        CurrentMaxTransitTunnels = _routerService.MaxTransitTunnels;
        CurrentMaxNtcp2InboundConnections = _routerService.MaxNtcp2InboundConnections;
        CurrentMaxNtcp2OutboundConnections = _routerService.MaxNtcp2OutboundConnections;
        CurrentTransitSharePercent = _routerService.TransitSharePercent;
        CurrentProxyEncryption = _routerService.ProxyEncryption;
        CurrentHttpProxyPort = _routerService.HttpProxyPort;
        CurrentHttpProxyRunning = _routerService.IsHttpProxyRunning;
    }
}