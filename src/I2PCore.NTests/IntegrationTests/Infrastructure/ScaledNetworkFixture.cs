using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using I2PTests.IntegrationTests;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;

namespace I2PTests.ScaledNetwork;

/// <summary>
///     NUnit SetUpFixture for a 10-router test network (1 C# + 9 i2pd).
///     Provides enough peers for real multi-hop tunnel building, LeaseSet
///     publishing through floodfill routers, and SAM-based data transfer.
///     Network:
///     C# 0 (in-process, FF) — i2pd 0..8 (processes)
///     Floodfills: C# 0, i2pd 0, i2pd 1
/// </summary>
[SetUpFixture]
[Category("ScaledNetwork")]
public class ScaledNetworkFixture
{
    private static readonly List<string> _i2pdDataDirs = new();

    private bool _ownsCSharp0;
    public static CSharpRouterHarness CSharp0 { get; private set; }

    // Actual SAM port for C# Router 0
    public static int Cs0SamPort { get; private set; }

    // i2pd processes
    public static RouterProcessManager I2pd0 { get; private set; }
    public static RouterProcessManager I2pd1 { get; private set; }
    public static RouterProcessManager I2pd2 { get; private set; }
    public static RouterProcessManager I2pd3 { get; private set; }
    public static RouterProcessManager I2pd4 { get; private set; }
    public static RouterProcessManager I2pd5 { get; private set; }
    public static RouterProcessManager I2pd6 { get; private set; }
    public static RouterProcessManager I2pd7 { get; private set; }
    public static RouterProcessManager I2pd8 { get; private set; }

    // RouterInfos
    public static I2PRouterInfo Cs0Info { get; private set; }
    public static I2PRouterInfo I2pd0Info { get; private set; }
    public static I2PRouterInfo I2pd1Info { get; private set; }
    public static I2PRouterInfo I2pd2Info { get; private set; }
    public static I2PRouterInfo I2pd3Info { get; private set; }
    public static I2PRouterInfo I2pd4Info { get; private set; }
    public static I2PRouterInfo I2pd5Info { get; private set; }
    public static I2PRouterInfo I2pd6Info { get; private set; }
    public static I2PRouterInfo I2pd7Info { get; private set; }
    public static I2PRouterInfo I2pd8Info { get; private set; }

    // i2pd data directories
    public static string I2pd0DataDir { get; private set; }
    public static string I2pd1DataDir { get; private set; }

    public static bool IsReady { get; private set; }

    [OneTimeSetUp]
    public async Task SetUp()
    {
        if (IsReady) return;

        Logging.LogToConsole = true;
        Logging.LogToDebug = true;
        Logging.SetLogLevel(Logging.LogLevels.Information);
        Logging.LogToFile("/tmp/i2p_scaled_test.log");

        if (RouterProcessManager.FindI2pdBinary() == null)
        {
            Logging.LogWarning("i2pd not found — scaled network tests will be skipped.");
            return;
        }

        try
        {
            CSharpProcessManager.FindOrBuildCli();
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Cannot build I2PRouterCli: {ex.Message}");
            return;
        }

        try
        {
            await StartScaledNetwork();
            IsReady = true;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to start 10-router network: {ex}");
            Cleanup();
            throw;
        }
    }

    private async Task StartScaledNetwork()
    {
        var sw = Stopwatch.StartNew();
        Logging.LogInformation("=== Starting 10-router scaled test network (1 C# + 9 i2pd) ===");

        // Phase 1: Kill stale processes from previous runs
        RouterProcessManager.KillStaleProcessesOnPorts(
            Enumerable.Range(29000, 300).ToArray());

        // Phase 2: Start C# Router 0 in-process with floodfill
        //
        // Batch 4-0c: this asked `TestNetworkFixture.CSharpRouter != null`, which is true
        // for a disposed harness too — TestNetworkFixture's OneTimeTearDown runs before
        // this namespace's fixtures, so in a full suite run the router was already gone
        // and every test here died with a NullReferenceException from NetDb.Inst. Ask
        // whether the router is running, not whether the object exists.
        if (TestNetworkFixture.CSharpRouter?.IsRunning == true)
        {
            CSharp0 = TestNetworkFixture.CSharpRouter;
            Cs0SamPort = CSharp0.SamPort;
            _ownsCSharp0 = false;

            RouterContext.Inst.FloodfillEnabled = true;
            RouterContext.Inst.ConfiguredBandwidth = RouterContext.BandwidthClass.X;
            RouterContext.Inst.ApplyNewSettings();

            Logging.LogInformation(
                $"C# 0: reusing TestNetworkFixture router {CSharp0.GetMyIdentHash().Id32Short:x8}");
        }
        else
        {
            CSharp0 = new CSharpRouterHarness(
                PortAllocator.Scaled.Cs0Ntcp2,
                PortAllocator.Scaled.Cs0Ssu2,
                PortAllocator.Scaled.Cs0Sam,
                PortAllocator.Scaled.Cs0I2cp,
                true);
            CSharp0.Start();
            Cs0SamPort = PortAllocator.Scaled.Cs0Sam;
            _ownsCSharp0 = true;
        }

        Cs0Info = CSharp0.GetMyRouterInfo();
        Logging.LogInformation(
            $"C# 0 (in-process, FF): {Cs0Info.Identity.IdentHash.Id32Short:x8}");

        // Phase 3: Start i2pd floodfills (0, 1)
        var i2pd0Config = CreateI2pdConfig(0, true, new[] { Cs0Info });
        I2pd0DataDir = i2pd0Config.dataDir;
        var i2pd1Config = CreateI2pdConfig(1, true, new[] { Cs0Info });
        I2pd1DataDir = i2pd1Config.dataDir;

        I2pd0 = new RouterProcessManager();
        I2pd1 = new RouterProcessManager();

        Logging.LogInformation("Starting i2pd floodfills (wave 1)...");
        await Task.WhenAll(
            I2pd0.StartI2pd(i2pd0Config.configPath, i2pd0Config.dataDir),
            I2pd1.StartI2pd(i2pd1Config.configPath, i2pd1Config.dataDir));
        await Task.WhenAll(
            I2pd0.WaitForReady(PortAllocator.Scaled.I2pd0Ntcp2, 90000),
            I2pd1.WaitForReady(PortAllocator.Scaled.I2pd1Ntcp2, 90000));

        I2pd0Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pd0Config.dataDir, 60000);
        I2pd1Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pd1Config.dataDir, 60000);
        LogRouterInfo("i2pd 0 (FF)", I2pd0Info);
        LogRouterInfo("i2pd 1 (FF)", I2pd1Info);

        if (I2pd0Info != null) CSharp0.InjectPeerRouterInfo(I2pd0Info);
        if (I2pd1Info != null) CSharp0.InjectPeerRouterInfo(I2pd1Info);

        // Phase 4: Start remaining i2pd instances (2-8)
        var allKnownInfos = new[] { Cs0Info, I2pd0Info, I2pd1Info }.Where(ri => ri != null).ToArray();

        var i2pdConfigs = new List<(string dataDir, string configPath)>();
        for (var i = 2; i <= 8; i++) i2pdConfigs.Add(CreateI2pdConfig(i, false, allKnownInfos));

        I2pd2 = new RouterProcessManager();
        I2pd3 = new RouterProcessManager();
        I2pd4 = new RouterProcessManager();
        I2pd5 = new RouterProcessManager();
        I2pd6 = new RouterProcessManager();
        I2pd7 = new RouterProcessManager();
        I2pd8 = new RouterProcessManager();

        Logging.LogInformation("Starting i2pd instances 2-8 (wave 2)...");
        await Task.WhenAll(
            I2pd2.StartI2pd(i2pdConfigs[0].configPath, i2pdConfigs[0].dataDir),
            I2pd3.StartI2pd(i2pdConfigs[1].configPath, i2pdConfigs[1].dataDir),
            I2pd4.StartI2pd(i2pdConfigs[2].configPath, i2pdConfigs[2].dataDir),
            I2pd5.StartI2pd(i2pdConfigs[3].configPath, i2pdConfigs[3].dataDir),
            I2pd6.StartI2pd(i2pdConfigs[4].configPath, i2pdConfigs[4].dataDir),
            I2pd7.StartI2pd(i2pdConfigs[5].configPath, i2pdConfigs[5].dataDir),
            I2pd8.StartI2pd(i2pdConfigs[6].configPath, i2pdConfigs[6].dataDir)
        );

        await Task.WhenAll(
            I2pd2.WaitForReady(PortAllocator.Scaled.I2pd2Ntcp2, 90000),
            I2pd3.WaitForReady(PortAllocator.Scaled.I2pd3Ntcp2, 90000),
            I2pd4.WaitForReady(PortAllocator.Scaled.I2pd4Ntcp2, 90000),
            I2pd5.WaitForReady(29200, 90000),
            I2pd6.WaitForReady(29210, 90000),
            I2pd7.WaitForReady(29220, 90000),
            I2pd8.WaitForReady(29230, 90000)
        );

        I2pd2Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pdConfigs[0].dataDir, 60000);
        I2pd3Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pdConfigs[1].dataDir, 60000);
        I2pd4Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pdConfigs[2].dataDir, 60000);
        I2pd5Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pdConfigs[3].dataDir, 60000);
        I2pd6Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pdConfigs[4].dataDir, 60000);
        I2pd7Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pdConfigs[5].dataDir, 60000);
        I2pd8Info = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(i2pdConfigs[6].dataDir, 60000);

        // Phase 5: Final full-mesh injection into C# 0
        var allInfos = new[]
            {
                Cs0Info, I2pd0Info, I2pd1Info, I2pd2Info, I2pd3Info, I2pd4Info, I2pd5Info, I2pd6Info, I2pd7Info,
                I2pd8Info
            }
            .Where(ri => ri != null).ToArray();

        foreach (var ri in allInfos.Where(r => r != Cs0Info))
            CSharp0.InjectPeerRouterInfo(ri);

        // Cross-inject into all i2pd routers
        var allI2pdConfigs = new[] { i2pd0Config, i2pd1Config }.Concat(i2pdConfigs).ToArray();
        for (var i = 0; i < allI2pdConfigs.Length; i++)
            foreach (var ri in allInfos)
                RouterInfoExchanger.PlaceRouterInfoForI2pd(ri, allI2pdConfigs[i].dataDir);

        Logging.LogInformation("Triggering connections to i2pd peers...");
        if (I2pd0Info != null) CSharp0.ConnectToPeer(I2pd0Info);
        if (I2pd1Info != null) CSharp0.ConnectToPeer(I2pd1Info);

        await WaitForTunnelEstablishment(180000);

        Logging.LogInformation($"=== 10-router network ready in {sw.Elapsed.TotalSeconds:F1}s ===");
    }

    public static (string dataDir, string configPath) CreateI2pdConfig(
        int index, bool floodfill, I2PRouterInfo[] peerInfos)
    {
        (int, int, int, int, int) ports;

        if (index >= 0 && index <= 4)
        {
            ports = index switch
            {
                0 => (PortAllocator.Scaled.I2pd0Ntcp2,
                    PortAllocator.Scaled.I2pd0Ssu2,
                    PortAllocator.Scaled.I2pd0Sam,
                    PortAllocator.Scaled.I2pd0I2cp,
                    PortAllocator.Scaled.I2pd0Http),
                1 => (PortAllocator.Scaled.I2pd1Ntcp2,
                    PortAllocator.Scaled.I2pd1Ssu2,
                    PortAllocator.Scaled.I2pd1Sam,
                    PortAllocator.Scaled.I2pd1I2cp,
                    PortAllocator.Scaled.I2pd1Http),
                2 => (PortAllocator.Scaled.I2pd2Ntcp2,
                    PortAllocator.Scaled.I2pd2Ssu2,
                    PortAllocator.Scaled.I2pd2Sam,
                    PortAllocator.Scaled.I2pd2I2cp,
                    PortAllocator.Scaled.I2pd2Http),
                3 => (PortAllocator.Scaled.I2pd3Ntcp2,
                    PortAllocator.Scaled.I2pd3Ssu2,
                    PortAllocator.Scaled.I2pd3Sam,
                    PortAllocator.Scaled.I2pd3I2cp,
                    PortAllocator.Scaled.I2pd3Http),
                4 => (PortAllocator.Scaled.I2pd4Ntcp2,
                    PortAllocator.Scaled.I2pd4Ssu2,
                    PortAllocator.Scaled.I2pd4Sam,
                    PortAllocator.Scaled.I2pd4I2cp,
                    PortAllocator.Scaled.I2pd4Http),
                _ => throw new ArgumentOutOfRangeException(nameof(index))
            };
        }
        else
        {
            // Dynamic ports for index 5+
            var basePort = 29200 + (index - 5) * 10;
            ports = (basePort, basePort + 1, basePort + 2, basePort + 3, basePort + 4);
        }

        var dataDir = Path.Combine(Path.GetTempPath(),
            $"i2pd_scaled_{index}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dataDir);
        _i2pdDataDirs.Add(dataDir);

        // Pre-inject all known peer RouterInfos
        foreach (var ri in peerInfos)
            RouterInfoExchanger.PlaceRouterInfoForI2pd(ri, dataDir);

        var configContent = I2pdConfigGenerator.GenerateConfig(
            dataDir,
            ports.Item1,
            ports.Item2,
            ports.Item3,
            ports.Item4,
            ports.Item5,
            floodfill,
            logFile: $"/tmp/i2pd_scaled_{index}.log",
            ntcpSoft: 15,
            ntcpHard: 25);

        var configPath = I2pdConfigGenerator.WriteConfig(
            dataDir, configContent);

        return (dataDir, configPath);
    }

    private static async Task WaitForTunnelEstablishment(int timeoutMs)
    {
        var sw = Stopwatch.StartNew();

        // Initial settling time for routers to discover each other
        await Task.Delay(90000);

        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            var outCount =
                TunnelProvider.Inst?.OutboundTunnelCount ?? 0;
            var inCount =
                TunnelProvider.Inst?.InboundTunnelCount ?? 0;

            if (outCount >= 2 && inCount >= 2)
            {
                Logging.LogInformation(
                    $"Tunnels ready after {sw.Elapsed.TotalSeconds:F1}s: " +
                    $"out={outCount}, in={inCount}");
                return;
            }

            Logging.LogDebug(
                $"Waiting for tunnels: out={outCount}, in={inCount}");
            await Task.Delay(5000);
        }

        Logging.LogWarning(
            $"Tunnel wait timed out after {sw.Elapsed.TotalSeconds:F1}s. " +
            $"Out={TunnelProvider.Inst?.OutboundTunnelCount ?? 0}, " +
            $"In={TunnelProvider.Inst?.InboundTunnelCount ?? 0}");
    }

    private static void LogRouterInfo(string label, I2PRouterInfo ri)
    {
        if (ri != null)
            Logging.LogInformation(
                $"{label}: {ri.Identity.IdentHash.Id32Short:x8}");
        else
            Logging.LogWarning($"{label}: RouterInfo is NULL");
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        Cleanup();
    }

    private void Cleanup()
    {
        try
        {
            I2pd8?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd7?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd6?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd5?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd4?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd3?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd2?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd1?.Dispose();
        }
        catch
        {
        }

        try
        {
            I2pd0?.Dispose();
        }
        catch
        {
        }

        if (_ownsCSharp0)
            try
            {
                CSharp0?.Dispose();
            }
            catch
            {
            }

        foreach (var dir in _i2pdDataDirs)
            try
            {
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                    Directory.Delete(dir, true);
            }
            catch
            {
            }
    }

    /// <summary>
    ///     Require the full 10-router network. Skips test if not available.
    /// </summary>
    public static void Require()
    {
        if (RouterProcessManager.FindI2pdBinary() == null) Assert.Ignore("i2pd not available");
        if (!IsReady) Assert.Ignore("10-router network not ready");
    }
}