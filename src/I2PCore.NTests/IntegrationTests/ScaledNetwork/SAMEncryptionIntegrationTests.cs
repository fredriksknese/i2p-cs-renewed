using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.ScaledNetwork;

[TestFixture]
[Category("ScaledNetwork")]
public class SAMEncryptionIntegrationTests
{
    private readonly List<CSharpProcessManager> _routers = new();
    private readonly List<I2PRouterInfo> _routerInfos = new();
    private string _testDataDir;

    [OneTimeSetUp]
    public async Task SetUp()
    {
        Logging.LogToConsole = true;
        Logging.SetLogLevel(Logging.LogLevels.Information);
        
        _testDataDir = Path.Combine(Path.GetTempPath(), $"sam_enc_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDataDir);

        // Build the CLI if needed
        CSharpProcessManager.FindOrBuildCli();

        // Kill any stale processes on our intended port range
        RouterProcessManager.KillStaleProcessesOnPorts(Enumerable.Range(30000, 300).ToArray());

        await Start15NodeNetwork();
    }

    private async Task Start15NodeNetwork()
    {
        var sw = Stopwatch.StartNew();
        Console.WriteLine("=== Starting 15-node C# I2P network (NTCP2 only) ===");

        const int nodeCount = 15;
        var startPort = 30000;

        // Phase 1: Create and start routers
        for (int i = 0; i < nodeCount; i++)
        {
            var router = new CSharpProcessManager(
                ntcp2Port: startPort + (i * 10),
                ssu2Port: startPort + (i * 10) + 1,
                samPort: startPort + (i * 10) + 2,
                httpProxyPort: startPort + (i * 10) + 3
            )
            {
                Floodfill = true,
                EnableSsu2 = false,
                ExploratoryLength = 1,
                ExploratoryQuantity = 2
            };
            _routers.Add(router);
        }

        Console.WriteLine("Starting 15 router processes...");
        await Task.WhenAll(_routers.Select(r => r.Start()));

        Console.WriteLine("Waiting for routers to be ready...");
        await Task.WhenAll(_routers.Select(r => r.WaitForReady(120000)));

        // Phase 2: Collect all RouterInfos
        Console.WriteLine("Collecting RouterInfos for bootstrapping...");
        foreach (var router in _routers)
        {
            var ri = await router.WaitForRouterInfo(60000);
            _routerInfos.Add(ri);
        }

        // Phase 3: Cross-inject RouterInfos (Full Mesh)
        Console.WriteLine("Injecting RouterInfos for full-mesh connectivity...");
        foreach (var router in _routers)
        {
            foreach (var ri in _routerInfos)
            {
                // Don't inject into self
                if (ri.Identity.IdentHash != _routerInfos[_routers.IndexOf(router)].Identity.IdentHash)
                {
                    router.InjectPeerRouterInfo(ri);
                }
            }
        }

        Console.WriteLine($"=== 15-node network started in {sw.Elapsed.TotalSeconds:F1}s ===");
        
        // Give some time for them to connect and build tunnels
        Console.WriteLine("Waiting for routers to discover each other...");
        var discoverySw = Stopwatch.StartNew();
        while (discoverySw.Elapsed.TotalMinutes < 5)
        {
            var counts = _routers.Select(r => r.GetKnownRouterCount()).ToArray();
            var minCount = counts.Min();
            Console.WriteLine($"Min routers known by any node: {minCount}/15");
            if (minCount >= 10) break; 
            await Task.Delay(5000);
        }

        Console.WriteLine("Waiting 120s for initial tunnel construction and stabilization...");
        await Task.Delay(120000);
    }

    [Test]
    [TestCase("4", "4", 1024 * 1024)] // ECIES to ECIES, 1MB
    // [TestCase("6,4", "4", 1024 * 512)] // Hybrid 6,4 to ECIES, 512KB
    // [TestCase("7,4", "6,4", 1024 * 512)] // Hybrid 7,4 to Hybrid 6,4
    public async Task TestSAMDataTransferWithEncryptionTypes(string senderEncTypes, string receiverEncTypes, int dataSize)
    {
        var testId = Guid.NewGuid().ToString("N")[..8];
        var receiverSid = $"recv-{testId}";
        var senderSid = $"send-{testId}";

        // Use Router 3 as Sender and Router 4 as Receiver
        var senderRouter = _routers[3];
        var receiverRouter = _routers[4];

        Logging.LogInformation($"Testing SAM Transfer [{testId}]: Sender(Enc={senderEncTypes}) -> Receiver(Enc={receiverEncTypes}), Size={dataSize}");

        using var receiverHelper = await SAMHelper.CreateAndHelloAsync("127.0.0.1", receiverRouter.SamPort);
        using var senderHelper = await SAMHelper.CreateAndHelloAsync("127.0.0.1", senderRouter.SamPort);

        // Create receiver session
        var receiverDest = await receiverHelper.CreateSessionAsync(
            receiverSid, 
            inboundLength: 1, outboundLength: 1,
            inboundQuantity: 1, outboundQuantity: 1,
            additionalOptions: $"i2cp.leaseSetEncType={receiverEncTypes}");
        
        // Accept connection in background
        var acceptTask = receiverHelper.StreamAcceptAsync(receiverSid);

        // Create sender session FIRST so NAMING LOOKUP will use it to perform real NetDb lookups
        await senderHelper.CreateSessionAsync(
            senderSid, 
            inboundLength: 1, outboundLength: 1,
            inboundQuantity: 1, outboundQuantity: 1,
            additionalOptions: $"i2cp.leaseSetEncType={senderEncTypes}");

        // Wait a bit for LeaseSet to propagate
        Logging.LogInformation("Waiting for LeaseSet to be resolvable via NAMING LOOKUP...");
        var lookupSw = Stopwatch.StartNew();
        bool resolvable = false;
        while (lookupSw.Elapsed.TotalMinutes < 5)
        {
            try {
                var lookupResult = await senderHelper.NamingLookupAsync(receiverDest);
                if (lookupResult.Contains("RESULT=OK"))
                {
                    resolvable = true;
                    Logging.LogInformation($"LeaseSet resolvable after {lookupSw.Elapsed.TotalSeconds:F1}s");
                    break;
                }
            } catch (Exception ex) {
                Logging.LogDebug($"Naming lookup attempt failed: {ex.Message}");
            }
            await Task.Delay(10000);
        }
        Assert.IsTrue(resolvable, "Receiver destination not resolvable after 5 minutes");

        // Connect to receiver
        await senderHelper.StreamConnectAsync(senderSid, receiverDest);
        await acceptTask;

        // Prepare data
        var testData = SAMHelper.GenerateTestData(dataSize);
        var expectedHash = SAMHelper.ComputeSha256(testData);

        // Start receiving in background
        var receiveTask = receiverHelper.ReceiveDataAsync(dataSize);

        // Send data
        await senderHelper.SendDataAsync(testData);

        // Wait for receive
        var receivedData = await receiveTask;
        var actualHash = SAMHelper.ComputeSha256(receivedData);

        Assert.IsTrue(SAMHelper.HashesMatch(expectedHash, actualHash), "Data integrity verification failed - hashes do not match!");
        Logging.LogInformation("Data transfer successful and verified via hash.");
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        Logging.LogInformation("=== Tearing down 15-node network ===");
        foreach (var router in _routers)
        {
            router.Dispose();
        }

        try
        {
            if (Directory.Exists(_testDataDir))
                Directory.Delete(_testDataDir, true);
        }
        catch { }
    }
}
