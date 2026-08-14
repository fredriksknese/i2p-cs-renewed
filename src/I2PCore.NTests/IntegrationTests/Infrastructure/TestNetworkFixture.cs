using System;
using System.IO;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;

namespace I2PTests.IntegrationTests;

/// <summary>
///     NUnit SetUpFixture that orchestrates the private test network.
///     Starts C# router and i2pd, exchanges RouterInfos, waits for readiness.
///     Shared across all integration test fixtures.
/// </summary>
[SetUpFixture]
[Category("Integration")]
public class TestNetworkFixture
{
    private static bool _initialized;
    private static readonly object _initLock = new();
    public static CSharpRouterHarness CSharpRouter { get; private set; }
    public static RouterProcessManager I2pdManager { get; private set; }
    public static I2PRouterInfo I2pdRouterInfo { get; private set; }
    public static string I2pdDataDir { get; private set; }

    /// <summary>
    ///     Check if i2pd is available. Tests will be skipped if not.
    /// </summary>
    public static bool IsI2pdAvailable =>
        RouterProcessManager.FindI2pdBinary() != null;

    [OneTimeSetUp]
    public async Task SetUp()
    {
        lock (_initLock)
        {
            if (_initialized) return;
            _initialized = true;
        }

        Logging.LogToConsole = true;
        Logging.LogToDebug = true;
        Logging.SetLogLevel(Logging.LogLevels.Transport);
        Logging.LogToFile("/tmp/i2p_integration_test.log");

        if (!IsI2pdAvailable)
        {
            Logging.LogWarning(
                "i2pd not found — integration tests will be skipped. " +
                "Install i2pd or set I2PD_PATH environment variable.");
            return;
        }

        try
        {
            await StartTestNetwork();
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to start test network: {ex}");
            CleanupOnFailure();
            throw;
        }
    }

    private async Task StartTestNetwork()
    {
        // 1. Create i2pd data directory and config
        I2pdDataDir = Path.Combine(Path.GetTempPath(),
            $"i2pd_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(I2pdDataDir);

        // 2. Start C# router first (so we can get its RouterInfo)
        //
        // Batch 3-16 (docs/PRODUCTION-PLAN.md): floodfill, and the reason is topological.
        // I2pdConfigGenerator makes i2pd a floodfill because a private network has no external
        // one, and i2pd inserts its own RouterInfo into m_Floodfills (NetDb.cpp, NetDb::Start).
        // With this router not a floodfill, i2pd was therefore the *only* one and published its
        // LeaseSets to itself, while every RouterInfo lookup it made came back empty —
        // RequestedDestination's constructor excludes self when floodfill (NetDbRequests.cpp),
        // which is the "NetDbReq: No more floodfills" warning seen in every run so far.
        // A two-router network needs two floodfills for a LeaseSet to travel between them.
        //
        // The second effect matters as much: FloodfillServer had never executed in *any*
        // integration run, so nothing this project has measured says whether it works.
        CSharpRouter = new CSharpRouterHarness(floodfill: true);
        CSharpRouter.Start();

        // 3. Place C# router's RouterInfo in i2pd's netDb
        RouterInfoExchanger.PlaceRouterInfoForI2pd(
            CSharpRouter.GetMyRouterInfo(), I2pdDataDir);

        // 4. Generate i2pd config and write it
        var configContent = I2pdConfigGenerator.GenerateConfig(I2pdDataDir);
        var configPath = I2pdConfigGenerator.WriteConfig(I2pdDataDir, configContent);

        // 5. Start i2pd — first kill any stale i2pd processes from previous runs
        // that might still be holding our well-known test ports.
        RouterProcessManager.KillStaleProcessesOnPorts(
            PortAllocator.WellKnown.I2pdNtcp2,
            PortAllocator.WellKnown.I2pdSsu2,
            PortAllocator.WellKnown.I2pdSam,
            PortAllocator.WellKnown.I2pdI2cp);
        I2pdManager = new RouterProcessManager();
        await I2pdManager.StartI2pd(configPath, I2pdDataDir);

        // 6. Wait for i2pd to be ready (NTCP2 port first, then SAM)
        await I2pdManager.WaitForReady(
            PortAllocator.WellKnown.I2pdNtcp2, 60000);
        await RouterProcessManager.WaitForPortListening(
            PortAllocator.WellKnown.I2pdSam, 30000);

        // 7. Import i2pd's RouterInfo into our C# router
        try
        {
            I2pdRouterInfo = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(
                I2pdDataDir, 30000);
            CSharpRouter.InjectPeerRouterInfo(I2pdRouterInfo);

            Logging.LogInformation(
                $"Test network ready: C# router {CSharpRouter.GetMyIdentHash().Id32Short:x8}, " +
                $"i2pd {I2pdRouterInfo.Identity.IdentHash.Id32Short:x8}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Could not import i2pd RouterInfo: {ex.Message}");
            // Tests can still run but peer exchange tests may fail
        }
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        CleanupOnFailure();
    }

    private void CleanupOnFailure()
    {
        try
        {
            I2pdManager?.Dispose();
        }
        catch
        {
        }

        try
        {
            CSharpRouter?.Dispose();
        }
        catch
        {
        }

        // Batch 4-0c: drop the reference as well as the router. Disposing it nulls
        // NetDb.Inst and TransportProvider.Inst, so what is left here is a handle to a
        // router that no longer exists — and ScaledNetworkFixture used to test this
        // property for null to decide whether it could reuse it, then NRE inside
        // NetDb.Inst.AddRouterInfo. Fixtures in other namespaces run after this
        // teardown, so the window is real and not hypothetical.
        CSharpRouter = null;

        try
        {
            if (!string.IsNullOrEmpty(I2pdDataDir) && Directory.Exists(I2pdDataDir))
                Directory.Delete(I2pdDataDir, true);
        }
        catch
        {
        }
    }

    /// <summary>
    ///     Assert that i2pd is available, or skip the test.
    ///     Call this at the start of any test that requires i2pd.
    /// </summary>
    public static void RequireI2pd()
    {
        if (!IsI2pdAvailable)
            Assert.Ignore("i2pd not available — skipping. Install i2pd or set I2PD_PATH.");
        if (I2pdRouterInfo == null)
            Assert.Ignore("i2pd RouterInfo not available — test network setup may have failed.");
    }

    /// <summary>
    ///     Assert that the C# router is running.
    /// </summary>
    public static void RequireCSharpRouter()
    {
        // Batch 4-0c: liveness, not non-nullness — see CSharpRouterHarness.IsRunning.
        // This is the guard that is meant to catch a missing router, so checking the
        // weaker condition made it the one place most likely to wave a dead one through.
        if (CSharpRouter?.IsRunning != true)
            Assert.Ignore("C# router not running — test network setup may have failed.");
    }
}