using System.Buffers;
using System.Net;
using I2PCore;
using I2PCore.Client;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer;
using I2PCore.Utils;

namespace I2PRouterCli;

internal class Program
{
    private static bool _isRunning;

    private static void Main(string[] args)
    {
        // Configure logging - no web interface, just console and file
        Logging.ReadAppConfig();
        Logging.SetLogLevel(Logging.LogLevels.Information);
        Logging.LogToDebug = false;
        Logging.LogToConsole = true;

        // Clear existing log file on startup for clean logs
        var logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "logs.txt");
        if (File.Exists(logFilePath)) File.Delete(logFilePath);
        Logging.LogToFile(logFilePath);
        Logging.LogInformation($"Logging to file: {logFilePath}");

        // Default settings
        IPAddress? externalAddress = null;
        var tcpPort = 12345;
        var udpPort = 12345;
        var isFirewalled = true;
        var useIPv6 = false;
        var disableIPv6 = false; // inverse of useIPv6 for CLI flag
        var enableSSU2 = false;
        var enablePqTransport = false;
        var floodfill = false;
        var testEepsite = false;
        var httpProxyPort = 4445; // Default to 4445 (4444 might be in use)

        var hiddenMode = false;
        string dataDir = null;
        var netId = 0; // 0 = use default (2)
        var disableReseed = false;
        var insecureReseed = false;
        var samPort = 0; // 0 = use default
        var exploratoryLength = 2;
        var exploratoryQuantity = 3;

        // Parse command line arguments
        for (var i = 0; i < args.Length; ++i)
            switch (args[i])
            {
                case "--hidden":
                    hiddenMode = true;
                    Console.WriteLine("Hidden mode enabled");
                    break;

                case "--test-example-eepsite":
                    testEepsite = true;
                    Console.WriteLine("Will test example eepsite after router is ready");
                    break;

                case "--http-proxy-port":
                    if (args.Length > i + 1)
                    {
                        httpProxyPort = int.Parse(args[++i]);
                        Console.WriteLine($"HTTP proxy port set to {httpProxyPort}");
                    }

                    break;

                case "--proxy-encryption":
                    if (args.Length > i + 1)
                    {
                        var mode = args[++i].ToLowerInvariant();
                        switch (mode)
                        {
                            case "ecies":
                                RouterContext.Inst.ProxyEncryption = RouterContext.HttpProxyEncryptionType.Ecies;
                                break;
                            case "mlkem":
                                RouterContext.Inst.ProxyEncryption = RouterContext.HttpProxyEncryptionType.Mlkem;
                                break;
                            case "hybrid":
                                RouterContext.Inst.ProxyEncryption = RouterContext.HttpProxyEncryptionType.Hybrid;
                                break;
                            default:
                                Console.WriteLine($"Unknown proxy encryption mode: {mode}. Using hybrid.");
                                break;
                        }

                        Console.WriteLine($"Proxy encryption: {RouterContext.Inst.ProxyEncryption}");
                    }

                    break;

                case "--external-ip":
                    if (args.Length > i + 1)
                    {
                        externalAddress = IPAddress.Parse(args[++i]);
                        Console.WriteLine($"External IP set to {externalAddress}");
                    }
                    else
                    {
                        Console.WriteLine("--external-ip requires an IP address");
                        return;
                    }

                    break;

                case "--ntcp2-port":
                    if (args.Length > i + 1)
                    {
                        tcpPort = int.Parse(args[++i]);
                        udpPort = tcpPort; // keep them synchronized by default
                        Console.WriteLine($"NTCP2 port set to {tcpPort}");
                    }
                    else
                    {
                        Console.WriteLine("--ntcp2-port requires a port number");
                        return;
                    }

                    break;

                case "--ssu2-port":
                    if (args.Length > i + 1)
                    {
                        udpPort = int.Parse(args[++i]);
                        enableSSU2 = true; // Auto-enable SSU2 if port is specified
                        Console.WriteLine($"SSU2 port set to {udpPort}");
                    }
                    else
                    {
                        Console.WriteLine("--ssu2-port requires a port number");
                        return;
                    }

                    break;

                case "--enable-ssu2":
                    enableSSU2 = true;
                    Console.WriteLine("SSU2: enabled");
                    break;

                case "--self-test":
                    TunnelProvider.SelfTestEnabled = true;
                    Console.WriteLine("Noise N self-test: enabled");
                    break;

                case "--experimental-pq":
                    enablePqTransport = true;
                    Console.WriteLine(
                        "Post-quantum NTCP2: enabled (experimental - handshake tests are quarantined, see batch 9-3)");
                    break;

                case "--is-firewalled":
                    isFirewalled = true;
                    Console.WriteLine($"Firewalled mode: {isFirewalled}");
                    break;

                case "--not-firewalled":
                    isFirewalled = false;
                    Console.WriteLine($"Firewalled mode: {isFirewalled}");
                    break;

                case "--disable-ipv6":
                    disableIPv6 = true;
                    useIPv6 = false;
                    Console.WriteLine("IPv6 disabled");
                    break;

                case "--enable-ipv6":
                    disableIPv6 = false;
                    useIPv6 = true;
                    Console.WriteLine("IPv6 enabled");
                    break;

                case "--disable-ssu2":
                    enableSSU2 = false;
                    Console.WriteLine("SSU2 disabled");
                    break;

                case "--floodfill":
                    floodfill = true;
                    Console.WriteLine("Floodfill mode: enabled");
                    break;

                case "--data-dir":
                    if (args.Length > i + 1)
                    {
                        dataDir = args[++i];
                        Console.WriteLine($"Data directory set to {dataDir}");
                    }

                    break;

                case "--netid":
                    if (args.Length > i + 1)
                    {
                        netId = int.Parse(args[++i]);
                        Console.WriteLine($"Network ID set to {netId}");
                    }

                    break;

                case "--disable-reseed":
                    disableReseed = true;
                    Console.WriteLine("Reseed disabled");
                    break;

                case "--insecure-reseed":
                    insecureReseed = true;
                    Console.WriteLine("WARNING: reseed TLS certificate validation disabled");
                    break;

                case "--log-level":
                    if (args.Length > i + 1)
                    {
                        var levelName = args[++i];

                        if (!Enum.TryParse<Logging.LogLevels>(levelName, true, out var level))
                        {
                            Console.Error.WriteLine(
                                $"Invalid --log-level '{levelName}'. Valid values: " +
                                string.Join(", ", Enum.GetNames<Logging.LogLevels>()));
                            Environment.Exit(2);
                        }

                        Logging.SetLogLevel(level);
                        Console.WriteLine($"Log level set to {level}");
                    }
                    else
                    {
                        Console.Error.WriteLine("--log-level requires a value");
                        Environment.Exit(2);
                    }

                    break;

                // Batch 6-1 (docs/PRODUCTION-PLAN.md). These categories used to be #if symbols
                // in I2PCore.csproj; selecting one meant a rebuild. An unknown name exits 2
                // rather than enabling nothing, and asking for a category the level will
                // swallow says so — both are silent-no-output traps otherwise.
                case "--log-trace":
                    if (args.Length > i + 1)
                    {
                        var traceNames = args[++i];

                        if (!TraceCategoryNames.TryParse(traceNames, out var categories, out var unknown))
                        {
                            Console.Error.WriteLine(
                                $"Invalid --log-trace category '{unknown}'. Valid values: " +
                                string.Join(", ", TraceCategoryNames.All));
                            Environment.Exit(2);
                        }

                        Logging.EnabledTraces = categories;
                        Console.WriteLine($"Trace categories set to {TraceCategoryNames.Format(categories)}");

                        if (categories != TraceCategories.None
                            && !Logging.IsEnabled(Logging.LogLevels.Debug))
                            Console.WriteLine(
                                $"WARNING: traces are Debug level and the log level is {Logging.LogLevel}, " +
                                "so nothing will be emitted. Add --log-level debug.");
                    }
                    else
                    {
                        Console.Error.WriteLine("--log-trace requires a value");
                        Environment.Exit(2);
                    }

                    break;

                case "--sam-port":
                    if (args.Length > i + 1)
                    {
                        samPort = int.Parse(args[++i]);
                        Console.WriteLine($"SAM port set to {samPort}");
                    }

                    break;

                case "--exploratory-length":
                    if (args.Length > i + 1)
                    {
                        exploratoryLength = int.Parse(args[++i]);
                        Console.WriteLine($"Exploratory length set to {exploratoryLength}");
                    }

                    break;

                case "--exploratory-quantity":
                    if (args.Length > i + 1)
                    {
                        exploratoryQuantity = int.Parse(args[++i]);
                        Console.WriteLine($"Exploratory quantity set to {exploratoryQuantity}");
                    }

                    break;

                case "--help":
                case "-h":
                    PrintHelp();
                    return;

                default:
                    Console.WriteLine($"Unknown argument: {args[i]}");
                    PrintHelp();
                    return;
            }

        // Apply pre-init settings (must be set BEFORE RouterContext.Inst is accessed)
        if (!string.IsNullOrEmpty(dataDir))
        {
            Directory.CreateDirectory(dataDir);
            StreamUtils.AppPathOverride = dataDir;
        }

        if (netId > 0) I2PConstants.I2PNetworkId = netId;

        if (disableReseed) Bootstrap.Disabled = true;

        // Logs at Critical from the property setter, so the operator sees it at any log level.
        if (insecureReseed) Bootstrap.InsecureReseed = true;

        // Apply configuration to router context
        RouterContext.RouterSettingsFile = "I2PRouterCli.bin";

        if (externalAddress != null) RouterContext.Inst.DefaultExtAddress = externalAddress;

        RouterContext.Inst.DefaultTcpPort = tcpPort;
        RouterContext.Inst.DefaultUdpPort = udpPort;
        RouterContext.Inst.IsFirewalled = isFirewalled;
        RouterContext.UseIpV6 = useIPv6 && !disableIPv6;
        RouterContext.Inst.EnableSSU2 = enableSSU2;
        // Must be set before Router.Start(): NTCP2Host reads it when it publishes its address.
        RouterContext.Inst.EnablePqTransport = enablePqTransport;
        RouterContext.Inst.FloodfillEnabled = floodfill;

        RouterContext.Inst.ExploratoryTunnelLength = exploratoryLength;
        RouterContext.Inst.ExploratoryTunnelQuantity = exploratoryQuantity;

        // Auto-enable hidden mode when firewalled (matches Java I2P behavior)
        if (isFirewalled || hiddenMode)
        {
            RouterContext.Inst.IsHidden = true;
            Console.WriteLine("Hidden mode: enabled (firewalled router)");
        }

        // Apply the new settings
        RouterContext.Inst.ApplyNewSettings();

        // Batch 4-0e: client-service configuration must be set before Router.Start(), which
        // starts ClientContext itself. It used to be set afterwards, so --sam-port and
        // --http-proxy-port were applied to services already listening on their defaults
        // (7656/4444/4447) and were silently ignored — including --sam-port 0, which is meant
        // to disable SAM and did not.
        ClientContext.Inst.SetConfig(
            ClientContext.CfgHttpProxyPort, httpProxyPort.ToString());
        ClientContext.Inst.SetConfig(
            ClientContext.CfgHttpProxyEnabled, "true");

        if (samPort > 0)
        {
            ClientContext.Inst.SetConfig(
                ClientContext.CfgSamEnabled, "true");
            ClientContext.Inst.SetConfig(
                ClientContext.CfgSamPort, samPort.ToString());
        }
        else
        {
            ClientContext.Inst.SetConfig(
                ClientContext.CfgSamEnabled, "false");
        }

        // Disable SOCKS to avoid port conflicts
        ClientContext.Inst.SetConfig(
            ClientContext.CfgSocksProxyEnabled, "false");

        // Start the router
        Router.Start();

        _isRunning = true;
        Logging.LogInformation("I2P Router CLI started");

        Console.WriteLine("I2P Router CLI is running. Press Ctrl+C to stop.");
        Console.WriteLine("Router ID: {0:x8}", RouterContext.Inst.MyRouterIdentity.IdentHash.Id32Short);
        Console.WriteLine($"Listening on TCP:{tcpPort}, UDP:{udpPort}");
        Console.WriteLine(
            $"Firewalled: {isFirewalled}, IPv6: {useIPv6 && !disableIPv6}, SSU2: {enableSSU2}, Floodfill: {floodfill}");

        // Export RouterInfo as router.info for integration test peer discovery
        try
        {
            var ri = RouterContext.Inst.MyRouterInfo;
            var brs = new ArrayBufferWriter<byte>();
            ri.Write(brs);
            var riPath = Path.Combine(
                dataDir ?? Directory.GetCurrentDirectory(), "router.info");
            File.WriteAllBytes(riPath, brs.WrittenSpan.ToArray());
            Logging.LogInformation($"RouterInfo exported to {riPath}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to export RouterInfo: {ex.Message}");
        }

        // Start client services. Configuration was applied before Router.Start() above;
        // this call is what brings up anything Router.Start() did not.
        try
        {
            ClientContext.Inst.Start();

            // Batch 4-0e: report what is listening, not what was requested. These lines used to
            // print the requested ports unconditionally, after a Start() that had discarded
            // them — so the CLI announced a SAM bridge on --sam-port while one was running on
            // 7656, and announced an HTTP proxy that was on 4444.
            Console.WriteLine(ClientContext.Inst.SAMBridge is null
                ? "SAM bridge: not running"
                : $"SAM bridge listening on 127.0.0.1:{samPort}");
            Console.WriteLine(ClientContext.Inst.HTTPProxy is null
                ? "HTTP proxy: not running"
                : $"HTTP proxy listening on 127.0.0.1:{httpProxyPort}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to start client services: {ex.Message}");
            Logging.Log(ex);
        }

        // Start eepsite test in background if requested
        if (testEepsite)
        {
            var proxyPort = httpProxyPort;
            Task.Run(async () => { await TestEepsite(proxyPort); });
        }

        // Batch 2-3 (docs/PRODUCTION-PLAN.md): make "Press Ctrl+C to stop" true.
        //
        // This used to be a bare `while (_isRunning) Thread.Sleep(1000)`. Nothing handled SIGINT,
        // so the runtime terminated the process outright: the finally below never ran, Router.Stop()
        // never ran, and peer profiles were never written. DaemonHelper had all of this implemented
        // and no caller. It sets e.Cancel = true so the process survives the signal, which is what
        // lets the shutdown sequence actually execute.
        using var daemon = new DaemonHelper();

        daemon.OnReload(Router.ReloadConfig);
        daemon.RegisterSignalHandlers();

        try
        {
            daemon.WaitForShutdown();
            Console.WriteLine("Shutdown requested, stopping router...");
        }
        catch (Exception ex)
        {
            Logging.Log(ex);
        }
        finally
        {
            StopRouter();
        }
    }

    private static void StopRouter()
    {
        if (_isRunning)
        {
            Router.Stop();
            _isRunning = false;
            Logging.LogInformation("I2P Router CLI stopped");
            Console.WriteLine("I2P Router CLI stopped.");
        }
    }

    private static async Task TestEepsite(int proxyPort)
    {
        const string testUrl = "http://nytzrhrjjfsutowojvxi7hphesskpqqr65wpistz6wa7cpajhp7a.b32.i2p/";
        const int minRouters = 100;
        const int maxWaitMinutes = 10;

        Logging.LogInformation("TestEepsite: Waiting for router to be ready...");

        // Wait for enough routers and established tunnels
        var startTime = DateTime.UtcNow;
        while (_isRunning)
        {
            var elapsed = DateTime.UtcNow - startTime;
            if (elapsed.TotalMinutes > maxWaitMinutes)
            {
                Logging.LogWarning($"TestEepsite: Timeout after {maxWaitMinutes} minutes. " +
                                   $"Router count: {NetDb.Inst.RouterCount}");
                break;
            }

            var routerCount = NetDb.Inst.RouterCount;
            var hasOutbound = TunnelProvider.Inst.OutboundTunnelCount > 0;
            var hasInbound = TunnelProvider.Inst.InboundTunnelCount > 0;

            // Need at least 2 outbound and 2 inbound tunnels for reliable operation
            var outCount = TunnelProvider.Inst.OutboundTunnelCount;
            var inCount = TunnelProvider.Inst.InboundTunnelCount;

            if (routerCount >= minRouters && outCount >= 2 && inCount >= 2)
            {
                Logging.LogInformation($"TestEepsite: Router ready. {routerCount} routers, " +
                                       $"tunnels out={outCount}, in={inCount}.");
                break;
            }

            Logging.LogInformation($"TestEepsite: Waiting... {routerCount} routers, " +
                                   $"out={outCount}, in={inCount}");
            await Task.Delay(15000);
        }

        if (!_isRunning) return;

        // Wait for tunnel pool and client destination tunnels to stabilize.
        // Client inbound tunnels can take 60-120 seconds to build.
        Logging.LogInformation("TestEepsite: Waiting 90s for tunnel pool to stabilize...");
        await Task.Delay(90000);

        Logging.LogInformation($"TestEepsite: Fetching {testUrl} via HTTP proxy...");

        try
        {
            var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}"),
                UseProxy = true
            };

            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromMinutes(3);

            var response = await client.GetAsync(testUrl);
            var content = await response.Content.ReadAsStringAsync();

            Console.WriteLine("=== EEPSITE TEST RESULT ===");
            Console.WriteLine($"Status: {response.StatusCode}");
            Console.WriteLine($"Content length: {content.Length}");
            if (content.Length > 2000)
                Console.WriteLine(content.Substring(0, 2000) + "...");
            else
                Console.WriteLine(content);
            Console.WriteLine("=== END EEPSITE TEST ===");

            Logging.LogInformation($"TestEepsite: SUCCESS! Status={response.StatusCode}, " +
                                   $"Length={content.Length}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("=== EEPSITE TEST FAILED ===");
            Console.WriteLine($"Error: {ex.Message}");
            if (ex.InnerException != null)
                Console.WriteLine($"Inner: {ex.InnerException.Message}");
            Console.WriteLine("=== END EEPSITE TEST ===");

            Logging.LogWarning($"TestEepsite: FAILED: {ex.Message}");
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("I2PRouterCli - CLI-only I2P Router");
        Console.WriteLine("");
        Console.WriteLine("Usage:");
        Console.WriteLine("  I2PRouterCli [options]");
        Console.WriteLine("");
        Console.WriteLine("Options:");
        Console.WriteLine("  --external-ip <IP>      Set external IP address");
        Console.WriteLine("  --ntcp2-port <PORT>     Set NTCP2 port (default: 12345)");
        Console.WriteLine("  --ssu2-port <PORT>      Set SSU2 port (default: 12345)");
        Console.WriteLine("  --is-firewalled         Run in firewalled mode (default)");
        Console.WriteLine("  --not-firewalled        Run in non-firewalled mode");
        Console.WriteLine("  --disable-ipv6          Disable IPv6 support");
        Console.WriteLine("  --enable-ipv6           Enable IPv6 support");
        Console.WriteLine("  --enable-ssu2           Enable SSU2 transport (off by default: no ACK/");
        Console.WriteLine("                          retransmit or Retry handling yet)");
        Console.WriteLine("  --disable-ssu2          Disable SSU2 transport (default)");
        Console.WriteLine("  --experimental-pq       Advertise post-quantum NTCP2 (off by default:");
        Console.WriteLine("                          hybrid handshake tests are quarantined)");
        Console.WriteLine("  --self-test             Run the Noise N tunnel-build self-check at");
        Console.WriteLine("                          startup and log the result");
        Console.WriteLine("  --floodfill             Enable floodfill mode");
        Console.WriteLine("  --proxy-encryption <mode> Set HTTP proxy encryption (ecies, mlkem, hybrid)");
        Console.WriteLine("  --data-dir <path>       Set custom data directory");
        Console.WriteLine("  --netid <N>             Set network ID (default: 2)");
        Console.WriteLine("  --disable-reseed        Disable network bootstrap/reseed");
        Console.WriteLine("  --insecure-reseed       Skip TLS certificate validation when reseeding.");
        Console.WriteLine("                          Lets anyone on the path choose every router this");
        Console.WriteLine("                          instance learns about. Do not use casually.");
        Console.WriteLine("  --log-level <LEVEL>     Set log verbosity: Everything, DebugData,");
        Console.WriteLine("                          Transport, Debug, Information (default),");
        Console.WriteLine("                          Warning, Error, Critical, Nothing");
        Console.WriteLine("  --log-trace <LIST>      Comma separated verbose trace categories:");
        Console.WriteLine("                          tunnel-transfer, lease-mgmt, ident-lookups,");
        Console.WriteLine("                          transport, tunnel-selection, upnp, all, none");
        Console.WriteLine("                          (default none). These are Debug level, so");
        Console.WriteLine("                          pair with --log-level debug.");
        Console.WriteLine("  --sam-port <PORT>       Enable SAM bridge on specified port");
        Console.WriteLine("  --help, -h              Show this help message");
        Console.WriteLine("");
        Console.WriteLine("Examples:");
        Console.WriteLine("  I2PRouterCli --external-ip 1.2.3.4 --ntcp2-port 9090 --ssu2-port 9091");
        Console.WriteLine("  I2PRouterCli --not-firewalled --disable-ipv6");
    }
}