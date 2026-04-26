using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PTests.IntegrationTests.Infrastructure;

/// <summary>
///     Manages a second C# I2P router as an external process.
///     Required because RouterContext/NetDb/TunnelProvider are singletons,
///     so only one C# router can run in-process.
/// </summary>
public class CSharpProcessManager : IDisposable
{
    private readonly StringBuilder _stderr = new();
    private readonly StringBuilder _stdout = new();
    private bool _disposed;
    private Process _process;

    public CSharpProcessManager(
        int ntcp2Port = PortAllocator.WellKnown.CSharpBNtcp2,
        int ssu2Port = PortAllocator.WellKnown.CSharpBSsu2,
        int samPort = PortAllocator.WellKnown.CSharpBSam,
        int httpProxyPort = PortAllocator.WellKnown.CSharpBHttpProxy)
    {
        Ntcp2Port = ntcp2Port;
        Ssu2Port = ssu2Port;
        SamPort = samPort;
        HttpProxyPort = httpProxyPort;
    }

    public string DataDir { get; private set; }
    public int Ntcp2Port { get; }
    public int Ssu2Port { get; }
    public int SamPort { get; }
    public int HttpProxyPort { get; }
    public bool Floodfill { get; set; }
    public bool EnableSsu2 { get; set; } = true;
    public string ExternalIp { get; set; } = "127.0.0.1";
    public int ExploratoryLength { get; set; } = 2;
    public int ExploratoryQuantity { get; set; } = 3;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Stop();
        _process?.Dispose();

        try
        {
            if (Directory.Exists(DataDir))
                Directory.Delete(DataDir, true);
        }
        catch
        {
        }
    }

    /// <summary>
    ///     Find the I2PRouterCli binary. Builds it if necessary.
    /// </summary>
    public static string FindOrBuildCli()
    {
        var solutionRoot = FindSolutionRoot();
        var projectPath = Path.Combine(solutionRoot, "src", "I2PRouterCli");
        var binaryPath = Path.Combine(projectPath, "bin", "Debug", "net10.0", "I2PRouterCli");

        if (!File.Exists(binaryPath))
        {
            Logging.LogInformation("Building I2PRouterCli...");
            var buildProc = Process.Start(new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"build \"{Path.Combine(projectPath, "I2PRouterCli.csproj")}\" -c Debug",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            buildProc?.WaitForExit(120000);
            if (buildProc?.ExitCode != 0)
            {
                var err = buildProc?.StandardError.ReadToEnd();
                throw new InvalidOperationException($"Failed to build I2PRouterCli: {err}");
            }
        }

        if (!File.Exists(binaryPath))
            throw new FileNotFoundException($"I2PRouterCli binary not found at {binaryPath}");

        return binaryPath;
    }

    /// <summary>
    ///     Start the C# router process with test network configuration.
    /// </summary>
    public async Task Start()
    {
        var binary = FindOrBuildCli();
        DataDir = Path.Combine(Path.GetTempPath(), $"i2p_cs_b_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(DataDir);

        var args = new StringBuilder();
        args.Append($"--data-dir \"{DataDir}\"");
        args.Append($" --netid {I2pdConfigGenerator.TestNetworkId}");
        args.Append(" --disable-reseed");
        args.Append($" --external-ip {ExternalIp}");
        args.Append($" --ntcp2-port {Ntcp2Port}");
        if (EnableSsu2)
        {
            args.Append($" --ssu2-port {Ssu2Port}");
            args.Append(" --enable-ssu2");
        }
        else
        {
            args.Append(" --disable-ssu2");
        }
        args.Append(" --not-firewalled");
        args.Append($" --sam-port {SamPort}");
        args.Append($" --http-proxy-port {HttpProxyPort}");
        if (Floodfill)
            args.Append(" --floodfill");

        args.Append($" --exploratory-length {ExploratoryLength}");
        args.Append($" --exploratory-quantity {ExploratoryQuantity}");

        Logging.LogInformation($"Starting C# Router B: dotnet {binary} {args}");

        _process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = binary,
                Arguments = args.ToString(),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = DataDir
            },
            EnableRaisingEvents = true
        };

        _process.OutputDataReceived += (s, e) =>
        {
            if (e.Data != null)
            {
                _stdout.AppendLine(e.Data);
                Logging.LogDebug($"[C# B stdout] {e.Data}");
            }
        };

        _process.ErrorDataReceived += (s, e) =>
        {
            if (e.Data != null)
            {
                _stderr.AppendLine(e.Data);
                Logging.LogDebug($"[C# B stderr] {e.Data}");
            }
        };

        if (!_process.Start())
            throw new InvalidOperationException("Failed to start C# Router B");

        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        Logging.LogInformation($"C# Router B started with PID {_process.Id}");
    }

    /// <summary>
    ///     Wait for the router to be ready (NTCP2 port listening).
    /// </summary>
    public async Task WaitForReady(int timeoutMs = 60000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (_process?.HasExited == true)
                throw new InvalidOperationException(
                    $"C# Router B exited prematurely with code {_process.ExitCode}.\n" +
                    $"stdout: {_stdout}\nstderr: {_stderr}");

            if (IsPortListening(Ntcp2Port))
            {
                Logging.LogInformation(
                    $"C# Router B ready (port {Ntcp2Port}) after {sw.ElapsedMilliseconds}ms");
                return;
            }

            await Task.Delay(500);
        }

        throw new TimeoutException(
            $"C# Router B not ready within {timeoutMs}ms.\nstdout: {_stdout}\nstderr: {_stderr}");
    }

    /// <summary>
    ///     Get the RouterInfo file path from the data directory.
    ///     The router stores its identity and netdb there.
    /// </summary>
    public async Task<I2PRouterInfo> WaitForRouterInfo(int timeoutMs = 30000)
    {
        // The router stores RouterInfos in {DataDir}/NetDb/
        return await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(
            DataDir, timeoutMs);
    }

    /// <summary>
    ///     Place a RouterInfo file in Router B's netDb so it discovers the peer.
    ///     Must be called before starting the router, or the router will pick it up
    ///     on its next netDb scan.
    /// </summary>
    public void InjectPeerRouterInfo(I2PRouterInfo ri)
    {
        var netDbDir = Path.Combine(DataDir, "NetDb");
        RouterInfoExchanger.ExportRouterInfo(ri, netDbDir);
    }

    public int GetKnownRouterCount()
    {
        var netDbDir = Path.Combine(DataDir, "NetDb");
        if (!Directory.Exists(netDbDir)) return 0;

        // I2P-CS stores in NetDb/rX/routerInfo-YYY.dat
        return Directory.GetFiles(netDbDir, "routerInfo-*.dat", SearchOption.AllDirectories).Length;
    }

    /// <summary>
    ///     Stop the router process.
    /// </summary>
    public void Stop()
    {
        if (_process == null || _process.HasExited)
            return;

        try
        {
            Logging.LogInformation("Stopping C# Router B...");
            _process.Kill(false);

            if (!_process.WaitForExit(10000))
            {
                _process.Kill(true);
                _process.WaitForExit(5000);
            }

            Logging.LogInformation($"C# Router B stopped (exit code {_process.ExitCode})");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Error stopping C# Router B: {ex.Message}");
        }
    }

    public string GetStdout()
    {
        return _stdout.ToString();
    }

    public string GetStderr()
    {
        return _stderr.ToString();
    }

    private static bool IsPortListening(int port)
    {
        try
        {
            using var client = new TcpClient();
            var result = client.BeginConnect("127.0.0.1", port, null, null);
            var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(200));
            if (success)
            {
                client.EndConnect(result);
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static string FindSolutionRoot()
    {
        var dir = AppDomain.CurrentDomain.BaseDirectory;
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir, "i2p.sln")))
                return dir;
            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new FileNotFoundException("Could not find i2p.sln solution root");
    }
}