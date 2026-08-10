using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.IntegrationTests.MultiHop;

/// <summary>
///     Multi-hop 5MB data transfer tests through a 4-router network.
///     Uses 2 C# routers and 2 i2pd routers to create real 2-hop tunnels.
///     Data is sent via SAM streams and verified with SHA-256 hashes.
///     Network: C# A ↔ i2pd A ↔ C# B ↔ i2pd B
///     With 4 peers, tunnels have real intermediate hops.
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("MultiHop")]
public class MultiHopDataTransferTests
{
    [SetUp]
    public void SetUp()
    {
        MultiHopTestFixture.Require();
    }

    private const int DataSize = 5 * 1024 * 1024; // 5MB
    // Batch 4-0g (docs/PRODUCTION-PLAN.md): capped so no integration test can exceed ~5 minutes.
    // Measured on the run that prompted this: the slowest *passing* test took 120s, while
    // TestBidirectional5MB burned 946s and failed -- despite carrying [CancelAfter(300000)].
    // CancelAfter cancels a CancellationToken that none of these tests declares as a parameter,
    // so it only reports a timeout; it never stops the work. The internal waits below are the
    // only thing that actually bounds a test, which is why they, not the attribute, were cut.
    private const int TransferTimeoutMs = 240_000; // 4 minutes
    private const int TunnelWaitMs = 180000; // 3 minutes for tunnel establishment

    /// <summary>
    ///     Wait for the in-process C# Router A to have tunnels established.
    ///     In a 4-router network, tunnel building takes longer.
    /// </summary>
    private async Task WaitForTunnels()
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < TunnelWaitMs)
        {
            var outCount = TunnelProvider.Inst?.OutboundTunnelCount ?? 0;
            var inCount = TunnelProvider.Inst?.InboundTunnelCount ?? 0;

            if (outCount > 0 && inCount > 0)
            {
                Logging.LogInformation(
                    $"Multi-hop tunnels ready: out={outCount}, in={inCount}");
                return;
            }

            Logging.LogDebug($"Waiting for multi-hop tunnels: out={outCount}, in={inCount}");
            await Task.Delay(5000);
        }

        Assert.Ignore("Multi-hop tunnels not established within timeout");
    }

    /// <summary>
    ///     Helper to perform a SAM-based 5MB transfer between two SAM bridges.
    /// </summary>
    private async Task PerformSAMTransfer(
        int senderSamPort, int receiverSamPort,
        string testName, int seed)
    {
        var testData = SAMHelper.GenerateTestData(DataSize, seed);
        var expectedHash = SAMHelper.ComputeSha256(testData);

        Logging.LogInformation(
            $"[{testName}] Sending {DataSize / 1024 / 1024}MB " +
            $"from SAM:{senderSamPort} → SAM:{receiverSamPort}");

        var sessionSuffix = $"_{seed}";

        // Create receiver session
        using var recvCtl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", receiverSamPort);
        var recvDest = await recvCtl.CreateSessionAsync($"recv{sessionSuffix}");
        Assert.IsNotNull(recvDest, $"[{testName}] Receiver destination should not be null");

        // Start STREAM ACCEPT on separate connection
        using var recvData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", receiverSamPort);
        var acceptTask = Task.Run(async () =>
        {
            var peer = await recvData.StreamAcceptAsync($"recv{sessionSuffix}");
            Logging.LogInformation(
                $"[{testName}] STREAM ACCEPT completed, peer {peer[..16]}...");
        });

        await Task.Delay(2000);

        // Create sender session and connect
        using var sendCtl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", senderSamPort);
        await sendCtl.CreateSessionAsync($"send{sessionSuffix}");

        using var sendData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", senderSamPort);

        Logging.LogInformation($"[{testName}] STREAM CONNECT to receiver...");
        await sendData.StreamConnectAsync($"send{sessionSuffix}", recvDest);
        Logging.LogInformation($"[{testName}] STREAM CONNECT completed");

        await acceptTask;

        // Transfer data
        using var cts = new CancellationTokenSource(TransferTimeoutMs);

        var sendTask = Task.Run(async () =>
        {
            await sendData.SendDataAsync(testData, cts.Token);
            Logging.LogInformation($"[{testName}] Sent {testData.Length} bytes");
        }, cts.Token);

        var receivedData = await recvData.ReceiveDataAsync(DataSize, cts.Token);
        await sendTask;

        Logging.LogInformation($"[{testName}] Received {receivedData.Length} bytes");

        // Verify
        var receivedHash = SAMHelper.ComputeSha256(receivedData);
        Assert.IsTrue(SAMHelper.HashesMatch(expectedHash, receivedHash),
            $"[{testName}] SHA-256 mismatch!\n" +
            $"  Expected: {Convert.ToHexString(expectedHash)}\n" +
            $"  Received: {Convert.ToHexString(receivedHash)}");

        Logging.LogInformation($"[{testName}] PASS");
    }

    /// <summary>
    ///     C# Router A sends 5MB to i2pd B through multi-hop tunnels.
    ///     Data traverses: C# A → [hops] → i2pd B
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_CSharpA_To_I2pdB_MultiHop()
    {
        await WaitForTunnels();
        await PerformSAMTransfer(
            PortAllocator.WellKnown.CSharpSam,
            PortAllocator.WellKnown.I2pdBSam,
            "C# A → i2pd B", 1001);
    }

    /// <summary>
    ///     i2pd B sends 5MB to C# Router A through multi-hop tunnels.
    ///     Reverse direction of the above test.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_I2pdB_To_CSharpA_MultiHop()
    {
        await WaitForTunnels();
        await PerformSAMTransfer(
            PortAllocator.WellKnown.I2pdBSam,
            PortAllocator.WellKnown.CSharpSam,
            "i2pd B → C# A", 1002);
    }

    /// <summary>
    ///     C# Router A sends 5MB to C# Router B through multi-hop tunnels.
    ///     Tests C#-to-C# communication via tunnel hops.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_CSharpA_To_CSharpB_MultiHop()
    {
        await WaitForTunnels();
        await PerformSAMTransfer(
            PortAllocator.WellKnown.CSharpSam,
            PortAllocator.WellKnown.CSharpBSam,
            "C# A → C# B", 1003);
    }

    /// <summary>
    ///     i2pd A sends 5MB to i2pd B through C# router hops.
    ///     Tests that C# routers correctly relay tunnel traffic.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_I2pdA_To_I2pdB_MultiHop()
    {
        await WaitForTunnels();
        await PerformSAMTransfer(
            PortAllocator.WellKnown.I2pdSam,
            PortAllocator.WellKnown.I2pdBSam,
            "i2pd A → i2pd B", 1004);
    }

    /// <summary>
    ///     Bidirectional 5MB transfer between C# A and i2pd B simultaneously.
    ///     Tests concurrent multi-hop tunnel traffic.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestBidirectional5MB_MultiHop()
    {
        await WaitForTunnels();

        Logging.LogInformation(
            "Starting bidirectional multi-hop 5MB transfer: " +
            "C# A ↔ i2pd B");

        // Run both directions concurrently
        var task1 = PerformSAMTransfer(
            PortAllocator.WellKnown.CSharpSam,
            PortAllocator.WellKnown.I2pdBSam,
            "Bidir C# A → i2pd B", 1005);

        var task2 = PerformSAMTransfer(
            PortAllocator.WellKnown.I2pdBSam,
            PortAllocator.WellKnown.CSharpSam,
            "Bidir i2pd B → C# A", 1006);

        await Task.WhenAll(task1, task2);

        Logging.LogInformation("Bidirectional multi-hop 5MB: PASS");
    }
}