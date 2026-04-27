using System.Net;
using I2PCore.SessionLayer;

namespace I2PRouterWeb.Services;

public class WebRouterSettings
{
    public string? ExternalAddress { get; set; }
    public int TcpPort { get; set; } = 12345;
    public int UdpPort { get; set; } = 12345;
    public bool IsFirewalled { get; set; } = true;
    public bool UseIPv6 { get; set; }
    public bool EnableSSU2 { get; set; } = true;
    public bool FloodfillEnabled { get; set; }
    public int MaxTransitTunnels { get; set; } = 10000;
    public int MaxNtcp2InboundConnections { get; set; } = 2500;
    public int MaxNtcp2OutboundConnections { get; set; } = 2500;
    public int TransitSharePercent { get; set; } = 80;
    public RouterContext.HttpProxyEncryptionType ProxyEncryption { get; set; } = RouterContext.HttpProxyEncryptionType.Hybrid;
    public int HttpProxyPort { get; set; } = 4445;
}
