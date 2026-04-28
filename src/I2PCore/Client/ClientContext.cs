using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.Streaming;
using I2PCore.Utils;

namespace I2PCore.Client;

/// <summary>
///     Singleton service lifecycle manager for all client-facing services.
///     Holds references to SAMBridge, HTTP proxy, SOCKS proxy, I2P tunnels,
///     and the address book. Supports configuration-driven start/stop.
/// </summary>
public class ClientContext
{
    // --- Default configuration keys and values (matching i2pd defaults) ---

    public const string CfgSamEnabled = "sam.enabled";
    public const string CfgSamPort = "sam.port";
    public const string CfgHttpProxyEnabled = "httpproxy.enabled";
    public const string CfgHttpProxyPort = "httpproxy.port";
    public const string CfgHttpProxyAddress = "httpproxy.address";
    public const string CfgHttpProxyOutproxy = "httpproxy.outproxy";
    public const string CfgSocksProxyEnabled = "socksproxy.enabled";
    public const string CfgSocksProxyPort = "socksproxy.port";
    public const string CfgSocksProxyAddress = "socksproxy.address";
    public const string CfgAddressBookEnabled = "addressbook.enabled";
    public const string CfgAddressBookPath = "addressbook.path";
    public const string CfgAddressBookSubscriptions = "addressbook.subscriptions";
    private static readonly object InstLock = new();
    private static ClientContext _inst;

    private static readonly Dictionary<string, string> DefaultConfig = new()
    {
        { CfgSamEnabled, "true" },
        { CfgSamPort, "7656" },
        { CfgHttpProxyEnabled, "true" },
        { CfgHttpProxyPort, "4444" },
        { CfgHttpProxyAddress, "127.0.0.1" },
        { CfgHttpProxyOutproxy, "" },
        { CfgSocksProxyEnabled, "true" },
        { CfgSocksProxyPort, "4447" },
        { CfgSocksProxyAddress, "127.0.0.1" },
        { CfgAddressBookEnabled, "true" },
        { CfgAddressBookPath, "hosts.txt" },
        { CfgAddressBookSubscriptions, "http://identiguy.i2p/hosts.txt" }
    };

    // --- Configuration ---

    private readonly ConcurrentDictionary<string, string> Config = new(
        StringComparer.OrdinalIgnoreCase);

    private readonly object LifecycleLock = new();

    private readonly ConcurrentDictionary<string, object> Tunnels = new();

    // Shared client destination for HTTP and SOCKS proxies
    private ClientDestination _sharedProxyDestination;
    private StreamingDestination _sharedStreamingDestination;

    private volatile bool IsRunning;

    private ClientContext()
    {
        // Seed with defaults
        foreach (var kvp in DefaultConfig) Config[kvp.Key] = kvp.Value;
    }

    public static ClientContext Inst
    {
        get
        {
            if (_inst is null)
                lock (InstLock)
                {
                    _inst ??= new ClientContext();
                }

            return _inst;
        }
    }

    // --- Service references ---

    public AddressBook AddressBook { get; private set; }
    public SAMBridge SAMBridge { get; private set; }
    public HTTPProxy HTTPProxy { get; private set; }
    public SOCKSProxy SOCKSProxy { get; private set; }

    public IEnumerable<string> TunnelNames => Tunnels.Keys;

    /// <summary>
    ///     Load configuration from an external dictionary, merging into current config.
    ///     Existing keys are overwritten; keys not present in the source are kept.
    /// </summary>
    public void LoadConfig(IDictionary<string, string> settings)
    {
        if (settings is null) return;

        foreach (var kvp in settings) Config[kvp.Key] = kvp.Value;
    }

    /// <summary>
    ///     Retrieve a configuration value, falling back to the default if not set.
    /// </summary>
    public string GetConfig(string key, string fallback = null)
    {
        if (Config.TryGetValue(key, out var val)) return val;
        return fallback;
    }

    public void SetConfig(string key, string value)
    {
        Config[key] = value;
    }

    private bool GetConfigBool(string key)
    {
        return string.Equals(
            GetConfig(key, "false"), "true",
            StringComparison.OrdinalIgnoreCase);
    }

    private int GetConfigInt(string key, int fallback)
    {
        var val = GetConfig(key);
        return int.TryParse(val, out var result) ? result : fallback;
    }

    // --- Lifecycle ---

    /// <summary>
    ///     Start all enabled services based on current configuration.
    /// </summary>
    public void Start()
    {
        lock (LifecycleLock)
        {
            if (IsRunning)
            {
                Logging.LogWarning("ClientContext: Already running.");
                return;
            }

            Logging.LogInformation("ClientContext: Starting services...");

            StartAddressBook();
            StartSAMBridge();
            StartHTTPProxy();
            StartSOCKSProxy();
            LoadTunnelsConfig();

            IsRunning = true;
            Logging.LogInformation("ClientContext: All enabled services started.");
        }
    }

    /// <summary>
    ///     Stop all running services and release resources.
    /// </summary>
    public void Stop()
    {
        lock (LifecycleLock)
        {
            if (!IsRunning) return;

            Logging.LogInformation("ClientContext: Stopping services...");

            StopSAMBridge();
            StopHTTPProxy();
            StopSOCKSProxy();
            StopTunnels();
            StopSharedProxyDestination();
            StopAddressBook();

            IsRunning = false;
            Logging.LogInformation("ClientContext: All services stopped.");
        }
    }

    /// <summary>
    ///     Reload configuration and restart services.
    /// </summary>
    public void Reload()
    {
        lock (LifecycleLock)
        {
            Logging.LogInformation("ClientContext: Reloading...");

            if (IsRunning) Stop();

            Start();
        }
    }

    /// <summary>
    ///     Reload from an updated settings dictionary and restart.
    /// </summary>
    public void Reload(IDictionary<string, string> settings)
    {
        LoadConfig(settings);
        Reload();
    }

    // --- Tunnel management ---

    /// <summary>
    ///     Register a named I2P tunnel instance (client or server tunnel).
    /// </summary>
    public void AddTunnel(string name, object tunnel)
    {
        if (string.IsNullOrWhiteSpace(name) || tunnel is null) return;
        Tunnels[name] = tunnel;
    }

    /// <summary>
    ///     Remove a named tunnel. Returns the removed instance, or null.
    /// </summary>
    public object RemoveTunnel(string name)
    {
        Tunnels.TryRemove(name, out var removed);
        return removed;
    }

    /// <summary>
    ///     Retrieve a registered tunnel by name.
    /// </summary>
    public II2PTunnel GetTunnel(string name)
    {
        if (Tunnels.TryGetValue(name, out var tunnel) && tunnel is II2PTunnel i2pTunnel) return i2pTunnel;
        return null;
    }

    public static string GetTunnelsConfigPath()
    {
        var searchPaths = new[]
        {
            Path.Combine(RouterContext.RouterPath, "tunnels.conf"),
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tunnels.conf"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".i2pd", "tunnels.conf"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".i2p-cs", "tunnels.conf")
        };

        foreach (var path in searchPaths)
            if (File.Exists(path))
                return path;

        return Path.Combine(RouterContext.RouterPath, "tunnels.conf");
    }

    /// <summary>
    ///     Load tunnels.conf and auto-create client/server tunnels.
    ///     Searches for tunnels.conf in the router data directory and standard locations.
    ///     Compatible with i2pd tunnels.conf format.
    /// </summary>
    public void LoadTunnelsConfig()
    {
        var searchPaths = new[]
        {
            Path.Combine(RouterContext.RouterPath, "tunnels.conf"),
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tunnels.conf"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".i2pd", "tunnels.conf"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".i2p-cs", "tunnels.conf")
        };

        foreach (var path in searchPaths)
        {
            if (!File.Exists(path)) continue;

            try
            {
                var config = new I2PConfig();
                config.ParseTunnelsConfig(path);

                var sections = config.GetSections();
                var tunnelCount = 0;

                foreach (var section in sections)
                {
                    var sectionConfig = config.GetSection(section);
                    if (sectionConfig == null || sectionConfig.Count == 0) continue;

                    var tunnelType = sectionConfig.GetValueOrDefault("type", "").ToLowerInvariant();
                    var autostart = sectionConfig.GetValueOrDefault("startOnLaunch", "false").ToLowerInvariant();

                    try
                    {
                        if (autostart != "true")
                        {
                            AddTunnel(section, sectionConfig);
                            Logging.LogDebug($"ClientContext: Tunnel '{section}' registered (autostart=false)");
                            continue;
                        }

                        StartGenericTunnel(section, sectionConfig);
                        tunnelCount++;
                        Logging.LogDebug($"ClientContext: Tunnel '{section}' started (type={tunnelType})");
                    }
                    catch (Exception ex)
                    {
                        Logging.LogWarning($"ClientContext: Failed to start tunnel '{section}': {ex.Message}");
                        // Still register the config so it can be managed
                        AddTunnel(section, sectionConfig);
                    }
                }

                if (tunnelCount > 0)
                    Logging.LogInformation($"ClientContext: Loaded {tunnelCount} tunnel(s) from '{path}'.");

                return; // Use first found config file
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"ClientContext: Error loading tunnels.conf from '{path}': {ex.Message}");
            }
        }
    }

    // --- Private service start/stop helpers ---

    public void StartAddressBook()
    {
        if (AddressBook != null) return;
        if (!GetConfigBool(CfgAddressBookEnabled)) return;

        var path = GetConfig(CfgAddressBookPath, "hosts.txt");
        AddressBook = new AddressBook(path);

        var subscriptions = GetConfig(CfgAddressBookSubscriptions, "");
        if (!string.IsNullOrWhiteSpace(subscriptions))
            foreach (var url in subscriptions.Split(',', ';'))
            {
                var trimmed = url.Trim();
                if (!string.IsNullOrEmpty(trimmed)) AddressBook.AddSubscription(trimmed);
            }

        AddressBook.Start();
        Logging.LogInformation("ClientContext: AddressBook started.");
    }

    public void StopAddressBook()
    {
        AddressBook?.Stop();
        AddressBook = null;
    }

    private void EnsureSharedProxyDestination()
    {
        if (_sharedProxyDestination != null) return;

        if (!Router.Started)
        {
            Logging.LogWarning("ClientContext: Router not started, cannot create proxy destination.");
            return;
        }

        // Create a transient destination for shared proxy use
        // MLKEM768-X25519 hybrid support
        var destInfo = new I2PDestinationInfo(
            I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519,
            I2PKeyType.KeyTypes.X25519);
        _sharedProxyDestination = Router.CreateDestination(destInfo, false, out _);
        _sharedProxyDestination.Name = "HTTP Proxy";
        _sharedProxyDestination.GenerateTemporaryKeys();

        var destBytes = destInfo.Destination.ToByteArray();
        _sharedStreamingDestination = new StreamingDestination(
            destInfo.Destination, destInfo.PrivateSigningKey, destBytes);
        _sharedStreamingDestination.SetSendCallback((dest, data) =>
        {
            var result = _sharedProxyDestination.Send(dest, data);
            if (result != ClientDestination.ClientStates.Established)
                Logging.LogWarning($"ClientContext: Streaming send to {dest.IdentHash.Id32Short} failed: {result}");
        });

        _sharedStreamingDestination.SetLookupCallback(dest =>
        {
            if (dest != null)
            {
                Logging.LogInformation($"ClientContext: Triggering LeaseSet lookup for {dest.IdentHash.Id32Short}");
                _sharedProxyDestination.LookupDestination(dest.IdentHash, (hash, ls, tag) =>
                {
                    Logging.LogInformation($"ClientContext: Lookup finished for {hash.Id32Short}. Success: {ls != null}");
                }, null);
            }
        });

        _sharedProxyDestination.DataReceived += (dest, data, sender) =>
        {
            _sharedStreamingDestination.HandleDataMessagePayload(data.ToByteArray(), sender);
        };

        // DatagramDestination for SOCKS UDP support can be wired later
        // when datagram send-by-IdentHash routing is fully integrated.
    }

    private void StopSharedProxyDestination()
    {
        _sharedStreamingDestination?.Dispose();
        _sharedStreamingDestination = null;

        if (_sharedProxyDestination != null)
        {
            _sharedProxyDestination.Shutdown();
            _sharedProxyDestination = null;
        }
    }

    public void StartSAMBridge()
    {
        if (SAMBridge != null) return;
        if (!GetConfigBool(CfgSamEnabled)) return;

        StartAddressBook();
        var port = GetConfigInt(CfgSamPort, 7656);

        try
        {
            SAMBridge = new SAMBridge(listenPort: port, addressBook: AddressBook);
            SAMBridge.Start();
            Logging.LogInformation($"ClientContext: SAM bridge started on port {port}.");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"ClientContext: Failed to start SAM bridge: {ex.Message}");
        }
    }

    public void StopSAMBridge()
    {
        SAMBridge?.Dispose();
        SAMBridge = null;
    }

    public void StartHTTPProxy()
    {
        if (HTTPProxy != null) return;
        if (!GetConfigBool(CfgHttpProxyEnabled)) return;

        var port = GetConfigInt(CfgHttpProxyPort, 4444);
        var address = GetConfig(CfgHttpProxyAddress, "127.0.0.1");

        StartAddressBook();
        EnsureSharedProxyDestination();
        if (_sharedProxyDestination == null || _sharedStreamingDestination == null)
        {
            Logging.LogWarning("ClientContext: Cannot start HTTP proxy - no proxy destination.");
            return;
        }

        try
        {
            HTTPProxy = new HTTPProxy(
                _sharedProxyDestination,
                _sharedStreamingDestination,
                port);

            var outproxy = GetConfig(CfgHttpProxyOutproxy, "");
            if (!string.IsNullOrWhiteSpace(outproxy)) HTTPProxy.OutproxyUrl = outproxy;

            HTTPProxy.Start();
            Logging.LogInformation($"ClientContext: HTTP proxy started on {address}:{port}.");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"ClientContext: Failed to start HTTP proxy: {ex.Message}");
        }
    }

    public void StopHTTPProxy()
    {
        HTTPProxy?.Dispose();
        HTTPProxy = null;
    }

    public void StartSOCKSProxy()
    {
        if (SOCKSProxy != null) return;
        if (!GetConfigBool(CfgSocksProxyEnabled)) return;

        var port = GetConfigInt(CfgSocksProxyPort, 4447);
        var address = GetConfig(CfgSocksProxyAddress, "127.0.0.1");

        StartAddressBook();
        EnsureSharedProxyDestination();
        if (_sharedProxyDestination == null || _sharedStreamingDestination == null)
        {
            Logging.LogWarning("ClientContext: Cannot start SOCKS proxy - no proxy destination.");
            return;
        }

        try
        {
            SOCKSProxy = new SOCKSProxy(
                _sharedProxyDestination,
                _sharedStreamingDestination,
                port);

            // Wire hostname resolution through the address book
            SOCKSProxy.ResolveHostname = hostname => { return AddressBook?.Lookup(hostname); };

            SOCKSProxy.Start();
            Logging.LogInformation($"ClientContext: SOCKS proxy started on {address}:{port}.");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"ClientContext: Failed to start SOCKS proxy: {ex.Message}");
        }
    }

    public void StopSOCKSProxy()
    {
        SOCKSProxy?.Dispose();
        SOCKSProxy = null;
    }

    public void StopTunnel(string name)
    {
        if (Tunnels.TryRemove(name, out var tunnel))
        {
            if (tunnel is IDisposable disposable)
            {
                try
                {
                    disposable.Dispose();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"ClientContext: Error stopping tunnel '{name}': {ex.Message}");
                }
            }
        }
    }

    private void StopTunnels()
    {
        foreach (var kvp in Tunnels)
            if (kvp.Value is IDisposable disposable)
                try
                {
                    disposable.Dispose();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"ClientContext: Error stopping tunnel '{kvp.Key}': {ex.Message}");
                }

        Tunnels.Clear();
    }

    public void StartGenericTunnel(string name, Dictionary<string, string> config)
    {
        var type = config.GetValueOrDefault("type", "").ToLowerInvariant();
        if (string.IsNullOrEmpty(type)) return;

        // Isolate: each tunnel gets its own destination
        var keysFile = config.GetValueOrDefault("keys", "");
        I2PDestinationInfo destInfo = null;

        var sigTypeStr = config.GetValueOrDefault("signaturetype", "");
        var cryptoTypeStr = config.GetValueOrDefault("cryptotype", "");

        var sigType = Enum.TryParse<I2PSigningKey.SigningKeyTypes>(sigTypeStr, true, out var st) 
            ? st : I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519;
        var cryptoType = I2PKeyType.Parse(cryptoTypeStr);
        if (cryptoType == I2PKeyType.KeyTypes.Invalid) cryptoType = I2PKeyType.KeyTypes.X25519;

        if (!string.IsNullOrEmpty(keysFile))
        {
            var path = Path.IsPathRooted(keysFile) ? keysFile : Path.Combine(RouterContext.RouterPath, keysFile);
            if (File.Exists(path))
            {
                destInfo = new I2PDestinationInfo(File.ReadAllText(path));
            }
            else
            {
                destInfo = new I2PDestinationInfo(sigType, cryptoType);
                File.WriteAllText(path, destInfo.ToBase64());
            }
        }
        else
        {
            destInfo = new I2PDestinationInfo(sigType, cryptoType);
        }

        var publish = type == "server" || type == "httpserver";
        var dest = Router.CreateDestination(destInfo, publish, out _);
        dest.Name = name;

        // Apply I2CP options
        foreach (var kvp in config)
            if (kvp.Key.StartsWith("i2cp.", StringComparison.OrdinalIgnoreCase))
                dest.Options[kvp.Key.ToLowerInvariant()] = kvp.Value;

        dest.GenerateTemporaryKeys();

        // Configure hops/quantities
        if (config.TryGetValue("inbound.length", out var val) && int.TryParse(val, out var hops)) dest.InboundTunnelHopCount = hops;
        if (config.TryGetValue("outbound.length", out val) && int.TryParse(val, out hops)) dest.OutboundTunnelHopCount = hops;
        if (config.TryGetValue("inbound.quantity", out val) && int.TryParse(val, out var quant)) dest.TargetInboundTunnelCount = quant;
        if (config.TryGetValue("outbound.quantity", out val) && int.TryParse(val, out quant)) dest.TargetOutboundTunnelCount = quant;

        var streaming = new StreamingDestination(dest.Destination, destInfo.PrivateSigningKey, destInfo.Destination.ToByteArray());
        streaming.SetSendCallback((target, data) =>
        {
            var result = dest.Send(target, data);
            if (result != ClientDestination.ClientStates.Established)
                Logging.LogWarning($"ClientContext: Tunnel '{name}' send to {target.IdentHash.Id32Short} failed: {result}");
        });
        streaming.SetLookupCallback(target =>
        {
            if (target != null) dest.LookupDestination(target.IdentHash, (hash, ls, tag) => { }, null);
        });

        dest.DataReceived += (d, data, sender) =>
        {
            streaming.HandleDataMessagePayload(data.ToByteArray(), sender);
        };

        if (type == "client" || type == "httpclient")
        {
            var port = int.Parse(config.GetValueOrDefault("port", "0"));
            var remoteStr = config.GetValueOrDefault("destination", "");
            if (string.IsNullOrEmpty(remoteStr)) throw new Exception("Client tunnel missing 'destination'");

            var remote = new I2PDestination(new I2PBufferCursor(FreenetBase64.Decode(remoteStr)));
            var tunnel = new I2PTunnelClient(dest, streaming, remote, port);
            tunnel.Start();
            AddTunnel(name, tunnel);
        }
        else if (type == "server" || type == "httpserver")
        {
            var host = config.GetValueOrDefault("host", "127.0.0.1");
            var port = int.Parse(config.GetValueOrDefault("port", "0"));
            var tunnel = new I2PTunnelServer(dest, streaming, host, port);
            tunnel.Start();
            AddTunnel(name, tunnel);
        }
        else
        {
            // Just register the config if type is unknown
            AddTunnel(name, config);
        }
    }
}