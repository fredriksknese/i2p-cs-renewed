using System;
using System.IO;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;

namespace I2PTests.IntegrationTests.MultiHop;

/// <summary>
///     NUnit SetUpFixture for the 4-router multi-hop test network.
///     Manages 2 C# routers and 2 i2pd routers, all on netid=99.
///     Enables real 2-hop tunnel construction for data transfer tests.
///     Network:
///     C# Router A (in-process) — i2pd A — C# Router B (process) — i2pd B
/// </summary>
[SetUpFixture]
[Category("MultiHop")]
public class MultiHopTestFixture
{
    private static bool _initialized;
    private bool _ownsCSharpA;

    // Tracks whether this fixture owns (started) the i2pd A instance.
    // If TestNetworkFixture already started i2pd A, we must not stop it on teardown.
    private bool _ownsI2pdA;

    // Router A (in-process C#)
    public static CSharpRouterHarness CSharpA { get; private set; }

    // Router B (external C# process)
    public static CSharpProcessManager CSharpB { get; private set; }

    // i2pd A
    public static RouterProcessManager I2pdAManager { get; private set; }
    public static I2PRouterInfo I2pdAInfo { get; private set; }
    public static string I2pdADataDir { get; private set; }

    // i2pd B
    public static RouterProcessManager I2pdBManager { get; private set; }
    public static I2PRouterInfo I2pdBInfo { get; private set; }
    public static string I2pdBDataDir { get; private set; }

    // C# Router B info (imported after it starts)
    public static I2PRouterInfo CSharpBInfo { get; private set; }

    public static bool IsReady => _initialized
                                  && CSharpA != null
                                  && I2pdAInfo != null
                                  && CSharpBInfo != null
                                  && I2pdBInfo != null;

    [OneTimeSetUp]
    public async Task SetUp()
    {
        if (_initialized) return;

        Logging.LogToDebug = true;
        Logging.SetLogLevel(Logging.LogLevels.Information);

        if (RouterProcessManager.FindI2pdBinary() == null)
        {
            Logging.LogWarning("i2pd not found — multi-hop tests will be skipped.");
            return;
        }

        try
        {
            await StartFourRouterNetwork();
            _initialized = true;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to start 4-router network: {ex}");
            Cleanup();
            throw;
        }
    }

    private async Task StartFourRouterNetwork()
    {
        Logging.LogInformation("=== Starting 4-router multi-hop test network ===");

        // 1. Create data directory for i2pd B only (i2pd A is reused from TestNetworkFixture)
        I2pdBDataDir = Path.Combine(Path.GetTempPath(), $"i2pd_b_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(I2pdBDataDir);

        // 2. Reuse C# Router A from TestNetworkFixture if already running;
        //    otherwise start a fresh in-process router.
        if (TestNetworkFixture.CSharpRouter != null)
        {
            CSharpA = TestNetworkFixture.CSharpRouter;
            _ownsCSharpA = false;
            Logging.LogInformation(
                $"C# Router A: reusing TestNetworkFixture router {CSharpA.GetMyIdentHash().Id32Short:x8}");
        }
        else
        {
            CSharpA = new CSharpRouterHarness();
            CSharpA.Start();
            _ownsCSharpA = true;
            Logging.LogInformation(
                $"C# Router A: {CSharpA.GetMyIdentHash().Id32Short:x8}");
        }

        var csAInfo = CSharpA.GetMyRouterInfo();

        // 3. Reuse i2pd A from TestNetworkFixture if already running;
        //    otherwise start a fresh i2pd A. Sharing is safe because both fixtures
        //    use the same well-known port block (29010-29014).
        if (TestNetworkFixture.I2pdManager != null &&
            TestNetworkFixture.I2pdRouterInfo != null)
        {
            I2pdAManager = TestNetworkFixture.I2pdManager;
            I2pdAInfo = TestNetworkFixture.I2pdRouterInfo;
            I2pdADataDir = TestNetworkFixture.I2pdDataDir;
            _ownsI2pdA = false;
            Logging.LogInformation(
                $"i2pd A: reusing TestNetworkFixture i2pd {I2pdAInfo.Identity.IdentHash.Id32Short:x8}");
        }
        else
        {
            I2pdADataDir = Path.Combine(Path.GetTempPath(), $"i2pd_a_test_{Guid.NewGuid():N}");
            Directory.CreateDirectory(I2pdADataDir);
            RouterInfoExchanger.PlaceRouterInfoForI2pd(csAInfo, I2pdADataDir);

            var i2pdAConfig = I2pdConfigGenerator.GenerateConfig(
                I2pdADataDir);
            var i2pdAConfigPath = I2pdConfigGenerator.WriteConfig(I2pdADataDir, i2pdAConfig);

            RouterProcessManager.KillStaleProcessesOnPorts(
                PortAllocator.WellKnown.I2pdNtcp2,
                PortAllocator.WellKnown.I2pdSsu2,
                PortAllocator.WellKnown.I2pdSam,
                PortAllocator.WellKnown.I2pdI2cp);
            I2pdAManager = new RouterProcessManager();
            await I2pdAManager.StartI2pd(i2pdAConfigPath, I2pdADataDir);
            await I2pdAManager.WaitForReady(PortAllocator.WellKnown.I2pdNtcp2);

            try
            {
                I2pdAInfo = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(
                    I2pdADataDir);
                Logging.LogInformation(
                    $"i2pd A: {I2pdAInfo.Identity.IdentHash.Id32Short:x8}");
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"Could not get i2pd A RouterInfo: {ex.Message}");
            }

            _ownsI2pdA = true;
        }

        // Place C# A's RouterInfo in i2pd B data dir
        RouterInfoExchanger.PlaceRouterInfoForI2pd(csAInfo, I2pdBDataDir);

        // 4. Start C# Router B (external process)
        CSharpB = new CSharpProcessManager();
        // Pre-inject C# A's RouterInfo into B's data dir
        Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(), "i2p_cs_b_test_pre"));
        await CSharpB.Start();
        await CSharpB.WaitForReady();

        // Get C# B's RouterInfo
        try
        {
            CSharpBInfo = await CSharpB.WaitForRouterInfo();
            Logging.LogInformation(
                $"C# Router B: {CSharpBInfo.Identity.IdentHash.Id32Short:x8}");

            // Place C# B's info in i2pd data dirs
            RouterInfoExchanger.PlaceRouterInfoForI2pd(CSharpBInfo, I2pdADataDir);
            RouterInfoExchanger.PlaceRouterInfoForI2pd(CSharpBInfo, I2pdBDataDir);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Could not get C# Router B RouterInfo: {ex.Message}");
        }

        // 5. (i2pd A is now set above — either reused or freshly started)

        // 6. Start i2pd B
        var i2pdBConfig = I2pdConfigGenerator.GenerateConfig(
            I2pdBDataDir,
            PortAllocator.WellKnown.I2pdBNtcp2,
            PortAllocator.WellKnown.I2pdBSsu2,
            PortAllocator.WellKnown.I2pdBSam,
            PortAllocator.WellKnown.I2pdBI2cp,
            PortAllocator.WellKnown.I2pdBHttp);
        var i2pdBConfigPath = I2pdConfigGenerator.WriteConfig(I2pdBDataDir, i2pdBConfig);

        I2pdBManager = new RouterProcessManager();
        await I2pdBManager.StartI2pd(i2pdBConfigPath, I2pdBDataDir);
        await I2pdBManager.WaitForReady(PortAllocator.WellKnown.I2pdBNtcp2);

        try
        {
            I2pdBInfo = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(
                I2pdBDataDir);
            Logging.LogInformation(
                $"i2pd B: {I2pdBInfo.Identity.IdentHash.Id32Short:x8}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Could not get i2pd B RouterInfo: {ex.Message}");
        }

        // 7. Cross-inject all RouterInfos into C# Router A (in-process)
        if (I2pdAInfo != null) CSharpA.InjectPeerRouterInfo(I2pdAInfo);
        if (I2pdBInfo != null) CSharpA.InjectPeerRouterInfo(I2pdBInfo);
        if (CSharpBInfo != null) CSharpA.InjectPeerRouterInfo(CSharpBInfo);

        // 8. Inject into C# Router B's netDb (place files for it to discover)
        if (I2pdAInfo != null) CSharpB.InjectPeerRouterInfo(I2pdAInfo);
        if (I2pdBInfo != null) CSharpB.InjectPeerRouterInfo(I2pdBInfo);
        // C# A info was already placed before B started

        // 9. Inject i2pd A's and B's infos into each other's netDb
        if (I2pdAInfo != null)
            RouterInfoExchanger.PlaceRouterInfoForI2pd(I2pdAInfo, I2pdBDataDir);
        if (I2pdBInfo != null)
            RouterInfoExchanger.PlaceRouterInfoForI2pd(I2pdBInfo, I2pdADataDir);

        Logging.LogInformation("=== 4-router network started ===");
        Logging.LogInformation(
            $"C# A: SAM={PortAllocator.WellKnown.CSharpSam}, " +
            $"i2pd A: SAM={PortAllocator.WellKnown.I2pdSam}, " +
            $"C# B: SAM={PortAllocator.WellKnown.CSharpBSam}, " +
            $"i2pd B: SAM={PortAllocator.WellKnown.I2pdBSam}");

        // 10. Wait a bit for all routers to discover each other and build tunnels
        Logging.LogInformation("Waiting for tunnel establishment across 4-router network...");
        await Task.Delay(15000);
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
            I2pdBManager?.Dispose();
        }
        catch
        {
        }

        // Only dispose i2pd A if we started it (not reused from TestNetworkFixture)
        if (_ownsI2pdA)
            try
            {
                I2pdAManager?.Dispose();
            }
            catch
            {
            }

        try
        {
            CSharpB?.Dispose();
        }
        catch
        {
        }

        // Only dispose C# A if we started it (not reused from TestNetworkFixture)
        if (_ownsCSharpA)
            try
            {
                CSharpA?.Dispose();
            }
            catch
            {
            }

        // Only delete i2pd A data dir if we created it
        if (_ownsI2pdA)
            try
            {
                if (!string.IsNullOrEmpty(I2pdADataDir) && Directory.Exists(I2pdADataDir))
                    Directory.Delete(I2pdADataDir, true);
            }
            catch
            {
            }

        try
        {
            if (!string.IsNullOrEmpty(I2pdBDataDir) && Directory.Exists(I2pdBDataDir))
                Directory.Delete(I2pdBDataDir, true);
        }
        catch
        {
        }
    }

    /// <summary>
    ///     Require the full 4-router network. Skips test if not available.
    /// </summary>
    public static void Require()
    {
        if (RouterProcessManager.FindI2pdBinary() == null)
            Assert.Ignore("i2pd not available");
        if (!IsReady)
            Assert.Ignore("4-router network not ready — setup may have failed");
    }
}