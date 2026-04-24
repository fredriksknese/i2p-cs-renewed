using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using System.Collections.Concurrent;
using System.Net;

namespace I2PRouterWeb.Services;

public class RouterService
{
    private readonly NetDbLogService _netDbLogService;
    private readonly ConcurrentQueue<ActivityLogEntry> _activityLog = new();

    public RouterService(NetDbLogService netDbLogService)
    {
        _netDbLogService = netDbLogService;
    }
    private const int MaxActivityLogEntries = 1000;
    private bool _isRunning = false;
    private DateTime? _startTime = null;

    public IPAddress? ExternalAddress { get; set; }
    public int TcpPort { get; set; } = 12345;
    public int UdpPort { get; set; } = 12345;
    public bool IsFirewalled { get; set; } = true;
    public bool UseIPv6 { get; set; } = false;
    public bool EnableSSU2 { get; set; } = true;
    public bool FloodfillEnabled { get; set; } = false;
    public RouterContext.HttpProxyEncryptionType ProxyEncryption { get; set; } = RouterContext.HttpProxyEncryptionType.Hybrid;
    public int HttpProxyPort { get; set; } = 4445;

    public bool IsRunning => _isRunning;
    public bool IsHttpProxyRunning => I2PCore.Client.ClientContext.Inst?.HTTPProxy?.IsRunning ?? false;
    
    /// <summary>
    /// Get the detected external IPv4 address (from peer reports or manual config)
    /// </summary>
    public IPAddress? DetectedExternalAddress => RouterContext.Inst?.ExtIpv4Address;
    public async Task ReseedAsync()
    {
        LogActivity("Network", "Triggering manual reseed from servers...");
        await I2PCore.Bootstrap.NetworkBootstrap();
    }

    public async Task<int> ReseedFromFileAsync(byte[] data)
    {
        LogActivity("Network", $"Manual reseed from uploaded file ({data.Length} bytes)...");
        var count = I2PCore.Bootstrap.ImportReseedFile(new BufLen(data));
        LogActivity("Network", $"Manual reseed imported {count} routers.");
        return count;
    }

    public IEnumerable<I2PCore.Utils.HttpProxyLogger.LogEntry> GetHttpProxyLogs()
    {
        return I2PCore.Utils.HttpProxyLogger.Inst.GetLogs().Reverse();
    }

    public IEnumerable<ActivityLogEntry> GetActivityLog() => _activityLog.ToArray().Reverse();

    public IEnumerable<I2PCore.TransportLayer.Log.TransportConnectionLogger.LogEntry> GetTransportConnectionLogs()
    {
        return I2PCore.TransportLayer.Log.TransportConnectionLogger.Inst.GetEntries();
    }

    public void StartRouter()
    {
        if (_isRunning)
        {
            LogActivity("Router", "Router already running");
            return;
        }

        RouterContext.RouterSettingsFile = "I2PRouterWeb.bin";

        if (ExternalAddress != null)
        {
            RouterContext.Inst.DefaultExtAddress = ExternalAddress;
        }

        RouterContext.Inst.DefaultTcpPort = TcpPort;
        RouterContext.Inst.DefaultUdpPort = UdpPort;
        RouterContext.Inst.IsFirewalled = IsFirewalled;
        RouterContext.UseIpV6 = UseIPv6;
        RouterContext.Inst.EnableSSU2 = EnableSSU2;
        RouterContext.Inst.FloodfillEnabled = FloodfillEnabled;
        RouterContext.Inst.ProxyEncryption = ProxyEncryption;

        RouterContext.Inst.ApplyNewSettings();

        Router.Start();
        _netDbLogService.Initialize();

        _isRunning = true;
        _startTime = DateTime.UtcNow;

        LogActivity("Router", "I2P Router started");
        Logging.LogInformation("I2P Router started");
    }

    public void StopRouter()
    {
        if (!_isRunning)
        {
            LogActivity("Router", "Router not running");
            return;
        }

        Router.Stop();

        _isRunning = false;
        _startTime = null;

        LogActivity("Router", "I2P Router stopped");
        Logging.LogInformation("I2P Router stopped");
    }

    public void StartHttpProxy()
    {
        if (!_isRunning)
        {
            LogActivity("HTTP Proxy", "Cannot start HTTP proxy - router not running");
            return;
        }

        if (IsHttpProxyRunning)
        {
            LogActivity("HTTP Proxy", "HTTP proxy already running");
            return;
        }

        var ctx = I2PCore.Client.ClientContext.Inst;
        ctx.SetConfig(I2PCore.Client.ClientContext.CfgHttpProxyPort, HttpProxyPort.ToString());
        ctx.SetConfig(I2PCore.Client.ClientContext.CfgHttpProxyEnabled, "true");
        ctx.SetConfig(I2PCore.Client.ClientContext.CfgSamEnabled, "false");
        ctx.SetConfig(I2PCore.Client.ClientContext.CfgSocksProxyEnabled, "false");
        ctx.Start();

        LogActivity("HTTP Proxy", $"HTTP proxy started on 127.0.0.1:{HttpProxyPort}");
        Logging.LogInformation($"HTTP proxy started on 127.0.0.1:{HttpProxyPort}");
    }

    public void StopHttpProxy()
    {
        if (!IsHttpProxyRunning)
        {
            LogActivity("HTTP Proxy", "HTTP proxy not running");
            return;
        }

        I2PCore.Client.ClientContext.Inst?.Stop();

        LogActivity("HTTP Proxy", "HTTP proxy stopped");
        Logging.LogInformation("HTTP proxy stopped");
    }

    public void ApplySettings(IPAddress? externalAddress, int tcpPort, int udpPort, bool isFirewalled, bool useIPv6, bool enableSSU2, bool floodfillEnabled, RouterContext.HttpProxyEncryptionType proxyEncryption)
    {
        ExternalAddress = externalAddress;
        TcpPort = tcpPort;
        UdpPort = udpPort;
        IsFirewalled = isFirewalled;
        UseIPv6 = useIPv6;
        EnableSSU2 = enableSSU2;
        FloodfillEnabled = floodfillEnabled;
        ProxyEncryption = proxyEncryption;

        var proxyEncryptionChanged = RouterContext.Inst.ProxyEncryption != ProxyEncryption;
        var proxyRunning = IsHttpProxyRunning;

        if ( proxyEncryptionChanged && proxyRunning )
        {
            StopHttpProxy();
        }

        if (ExternalAddress != null)
        {
            RouterContext.Inst.DefaultExtAddress = ExternalAddress;
        }

        RouterContext.Inst.DefaultTcpPort = TcpPort;
        RouterContext.Inst.DefaultUdpPort = UdpPort;
        RouterContext.Inst.IsFirewalled = IsFirewalled;
        RouterContext.UseIpV6 = UseIPv6;
        RouterContext.Inst.EnableSSU2 = EnableSSU2;
        RouterContext.Inst.FloodfillEnabled = FloodfillEnabled;
        RouterContext.Inst.ProxyEncryption = ProxyEncryption;

        RouterContext.Inst.ApplyNewSettings();

        if ( proxyEncryptionChanged && proxyRunning )
        {
            StartHttpProxy();
        }

        LogActivity("Settings", $"Applied new settings: Port {TcpPort}, Firewalled: {IsFirewalled}, SSU2: {EnableSSU2}, Floodfill: {FloodfillEnabled}, Encryption: {ProxyEncryption}");
    }

    public void LogActivity(string category, string message)
    {
        _activityLog.Enqueue(new ActivityLogEntry
        {
            Timestamp = DateTime.UtcNow,
            Category = category,
            Message = message
        });

        while (_activityLog.Count > MaxActivityLogEntries)
        {
            _activityLog.TryDequeue(out _);
        }
    }

    public RouterStatistics GetStatistics()
    {
        var uptime = _startTime.HasValue ? DateTime.UtcNow - _startTime.Value : TimeSpan.Zero;

        var stats = new RouterStatistics
        {
            RouterHash = RouterContext.Inst.MyRouterIdentity.IdentHash.Id32Short,
            Version = I2PConstants.ProtocolVersion,
            Uptime = uptime,
            PublicKey = Convert.ToBase64String(RouterContext.Inst.MyRouterIdentity.PublicKey.ToByteArray()),
            KeyType = RouterContext.Inst.MyRouterIdentity.PublicKey.Certificate.PublicKeyType.ToString(),
            IsRunning = _isRunning,
            BandwidthClass = RouterContext.Inst.GetBandwidthCapChar().ToString()
        };

        // NetDb and Transport stats
        try
        {
            stats.KnownRouters = I2PCore.NetDb.Inst.RouterCount;
            stats.KnownFloodfills = I2PCore.NetDb.Inst.FloodfillCount;
            stats.NTCP2SessionCount = TransportProvider.Inst?.Ntcp2SessionCount ?? 0;
            stats.SSU2SessionCount = TransportProvider.Inst?.Ssu2SessionCount ?? 0;
            
            stats.InboundTunnels = TunnelProvider.Inst?.InboundTunnelCount ?? 0;
            stats.OutboundTunnels = TunnelProvider.Inst?.OutboundTunnelCount ?? 0;
            stats.ExploratoryTunnels = (TunnelProvider.Inst?.GetInboundTunnels()?.Count(t => t.Config?.Pool == TunnelConfig.TunnelPool.Exploratory) ?? 0) +
                                       (TunnelProvider.Inst?.GetOutboundTunnels()?.Count(t => t.Config?.Pool == TunnelConfig.TunnelPool.Exploratory) ?? 0);
            stats.TransitTunnels = Router.TransitTunnelMgr?.TransitTunnelCount ?? 0;

            stats.HTTPProxyRunning = IsHttpProxyRunning;
            stats.HTTPProxyPort = HttpProxyPort;
        }
        catch { }

        return stats;
    }

    public IEnumerable<TransitTunnelInfo> GetTransitTunnels()
    {
        var result = new List<TransitTunnelInfo>();
        if (Router.TransitTunnelMgr == null) return result;

        foreach (var tunnel in Router.TransitTunnelMgr.GetTunnels())
        {
            result.Add(new TransitTunnelInfo
            {
                TunnelId = tunnel.ReceiveTunnelId.ToString(),
                FromRouter = "Unknown",
                ToRouter = tunnel.Destination?.Id32Short ?? "Endpoint",
                IsEndpoint = tunnel is EndpointTunnel,
                MessageCount = 0, // Not tracked per-tunnel yet
                LastActivity = DateTime.UtcNow - TimeSpan.FromMilliseconds( tunnel.EstablishedTime.DeltaToNowMilliseconds )
            });
        }

        return result;
    }
}

public class TransitTunnelInfo
{
    public string TunnelId { get; set; } = string.Empty;
    public string FromRouter { get; set; } = string.Empty;
    public string ToRouter { get; set; } = string.Empty;
    public bool IsEndpoint { get; set; }
    public int MessageCount { get; set; }
    public DateTime LastActivity { get; set; }
}

public class ActivityLogEntry
{
    public DateTime Timestamp { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class RouterStatistics
{
    public string RouterHash { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public TimeSpan Uptime { get; set; }
    public string PublicKey { get; set; } = string.Empty;
    public string KeyType { get; set; } = string.Empty;
    public bool IsRunning { get; set; }

    // Transport statistics
    public int NTCP2SessionCount { get; set; }
    public int SSU2SessionCount { get; set; }

    // NetDb statistics
    public int KnownRouters { get; set; }
    public int KnownFloodfills { get; set; }
    public int KnownLeaseSets { get; set; }

    // Tunnel statistics
    public int InboundTunnels { get; set; }
    public int OutboundTunnels { get; set; }
    public int ExploratoryTunnels { get; set; }
    public int TransitTunnels { get; set; }

    // Bandwidth
    public string InboundBandwidth { get; set; } = "0 Bps";
    public string OutboundBandwidth { get; set; } = "0 Bps";
    public string BandwidthClass { get; set; } = "O";

    // Client services
    public bool SAMEnabled { get; set; }
    public int SAMSessions { get; set; }
    public bool I2CPEnabled { get; set; }
    public bool HTTPProxyEnabled { get; set; }
    public bool SOCKSProxyEnabled { get; set; }
    public bool HTTPProxyRunning { get; set; }
    public int HTTPProxyPort { get; set; }
}
