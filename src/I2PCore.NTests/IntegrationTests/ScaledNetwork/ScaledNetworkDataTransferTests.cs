using System;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.ScaledNetwork;

/// <summary>
///     5MB end-to-end data transfer tests through a 10-router I2P network.
///     Uses real multi-hop tunnels (2-hop) and floodfill-based LeaseSet publishing.
///     Network: 1 C# router (in-process) + 9 i2pd routers, 3 floodfills.
///     Tests verify:
///     1. i2pd server tunnel/leaseset via SAM
///     2. C# and i2pd routers as tunnel participants
///     3. 5MB transfer with SHA-256 integrity verification
///     4. Both directions (C# → i2pd and i2pd → C#)
///     5. Bidirectional simultaneous transfer
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("ScaledNetwork")]
public class ScaledNetworkDataTransferTests
{
    [SetUp]
    public void SetUp()
    {
        ScaledNetworkFixture.Require();
    }

    private const int DataSize = 5 * 1024 * 1024; // 5MB
    private const int TransferTimeoutMs = 900_000; // 15 minutes
    private const int SessionCreateTimeoutMs = 900_000; // 15 minutes for SAM session (real tunnel build)

    private const int StreamConnectTimeoutMs = 300_000; // 5 minutes for stream connect

    // Both Sender and Receiver use 2-hop tunnels as strictly required.
    private const int ReceiverTunnelHops = 2;
    private const int SenderTunnelHops = 2;
    private const int TunnelQuantity = 1;

    /// <summary>
    ///     Helper to perform a SAM-based 5MB transfer between two SAM bridges
    ///     using real multi-hop tunnels.
    /// </summary>
    private async Task PerformSAMTransfer(
        int senderSamPort, int receiverSamPort,
        string testName, int seed)
    {
        var testData = SAMHelper.GenerateTestData(DataSize, seed);
        var expectedHash = SAMHelper.ComputeSha256(testData);

        Logging.LogInformation(
            $"[{testName}] {DataSize / 1024 / 1024}MB transfer " +
            $"SAM:{senderSamPort} → SAM:{receiverSamPort}, " +
            $"{SenderTunnelHops}-hop tunnels");

        var sessionSuffix = $"_{seed}";

        // Step 1: Create receiver session with zero-hop tunnels for fast LeaseSet publishing
        using var recvCtl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", receiverSamPort, 30000);
        var recvDest = await recvCtl.CreateSessionAsync(
            $"recv{sessionSuffix}",
            inboundLength: ReceiverTunnelHops,
            outboundLength: ReceiverTunnelHops,
            inboundQuantity: TunnelQuantity,
            outboundQuantity: TunnelQuantity,
            timeoutMs: SessionCreateTimeoutMs);
        Assert.IsNotNull(recvDest,
            $"[{testName}] Receiver destination should not be null");
        Logging.LogInformation(
            $"[{testName}] Receiver session created ({recvDest.Length} chars)");

        // Step 2: Start STREAM ACCEPT on separate connection
        using var recvData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", receiverSamPort, 30000);
        var acceptTask = Task.Run(async () =>
        {
            await recvData.StreamAcceptAsync($"recv{sessionSuffix}");
            Logging.LogInformation($"[{testName}] STREAM ACCEPT completed");
        });

        // Give ACCEPT time to start waiting
        await Task.Delay(3000);

        // Step 3: Create sender session with real tunnels for multi-hop data path
        using var sendCtl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", senderSamPort, 30000);
        await sendCtl.CreateSessionAsync(
            $"send{sessionSuffix}",
            inboundLength: SenderTunnelHops,
            outboundLength: SenderTunnelHops,
            inboundQuantity: TunnelQuantity,
            outboundQuantity: TunnelQuantity,
            timeoutMs: SessionCreateTimeoutMs);

        Logging.LogInformation(
            $"[{testName}] Sender session created. Connecting...");

        // Step 4: STREAM CONNECT
        using var sendData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", senderSamPort, 30000);
        await sendData.StreamConnectAsync(
            $"send{sessionSuffix}", recvDest);
        Logging.LogInformation($"[{testName}] STREAM CONNECT completed");

        await acceptTask;

        // Step 5: Transfer data
        using var cts = new CancellationTokenSource(TransferTimeoutMs);

        var sendTask = Task.Run(async () =>
        {
            await sendData.SendDataAsync(testData, cts.Token);
            Logging.LogInformation($"[{testName}] Sent {testData.Length} bytes");
        }, cts.Token);

        var receivedData = await recvData.ReceiveDataAsync(DataSize, cts.Token);
        await sendTask;

        Logging.LogInformation(
            $"[{testName}] Received {receivedData.Length} bytes");

        // Step 6: Verify SHA-256 hash
        var receivedHash = SAMHelper.ComputeSha256(receivedData);
        Assert.IsTrue(SAMHelper.HashesMatch(expectedHash, receivedHash),
            $"[{testName}] SHA-256 mismatch!\n" +
            $"  Expected: {Convert.ToHexString(expectedHash)}\n" +
            $"  Received: {Convert.ToHexString(receivedHash)}");

        Logging.LogInformation($"[{testName}] PASS");
    }

    /// <summary>
    ///     C# Router 0 sends 5MB to i2pd 0 through real multi-hop tunnels.
    ///     i2pd 0 acts as server (SAM ACCEPT), C# 0 acts as client (SAM CONNECT).
    ///     Tunnels use C# and i2pd routers as intermediate hops.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_CSharp0_To_I2pd0()
    {
        await PerformSAMTransfer(
            ScaledNetworkFixture.Cs0SamPort,
            PortAllocator.Scaled.I2pd0Sam,
            "C# 0 → i2pd 0", 2001);
    }

    /// <summary>
    ///     i2pd 0 sends 5MB to C# Router 0 (reverse direction).
    ///     C# 0 acts as server (SAM ACCEPT), i2pd 0 acts as client.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_I2pd0_To_CSharp0()
    {
        await PerformSAMTransfer(
            PortAllocator.Scaled.I2pd0Sam,
            ScaledNetworkFixture.Cs0SamPort,
            "i2pd 0 → C# 0", 2002);
    }

    /// <summary>
    ///     i2pd 2 sends 5MB to i2pd 3.
    ///     Both endpoints are non-floodfill i2pd routers; C# router and
    ///     floodfill i2pd routers serve as tunnel participants and LeaseSet stores.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_I2pd2_To_I2pd3()
    {
        await PerformSAMTransfer(
            PortAllocator.Scaled.I2pd2Sam,
            PortAllocator.Scaled.I2pd3Sam,
            "i2pd 2 → i2pd 3", 2003);
    }

    /// <summary>
    ///     i2pd 0 sends 5MB to i2pd 1.
    ///     Both endpoints are i2pd; C# routers serve as tunnel participants.
    ///     This is the critical test: proves C# routers correctly relay
    ///     tunnel traffic as intermediate hops for i2pd.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestSend5MB_I2pd0_To_I2pd1()
    {
        await PerformSAMTransfer(
            PortAllocator.Scaled.I2pd0Sam,
            PortAllocator.Scaled.I2pd1Sam,
            "i2pd 0 → i2pd 1 (C# as hops)", 2004);
    }

    /// <summary>
    ///     Bidirectional 5MB transfer: C# 0 ↔ i2pd 0 simultaneously.
    ///     Both sides send and receive 5MB concurrently.
    /// </summary>
    [Test]
    [CancelAfter(TransferTimeoutMs)]
    public async Task TestBidirectional5MB()
    {
        Logging.LogInformation(
            "Starting bidirectional 5MB transfer: C# 0 ↔ i2pd 0");

        var task1 = PerformSAMTransfer(
            ScaledNetworkFixture.Cs0SamPort,
            PortAllocator.Scaled.I2pd0Sam,
            "Bidir C# 0 → i2pd 0", 2005);

        var task2 = PerformSAMTransfer(
            PortAllocator.Scaled.I2pd0Sam,
            ScaledNetworkFixture.Cs0SamPort,
            "Bidir i2pd 0 → C# 0", 2006);

        await Task.WhenAll(task1, task2);

        Logging.LogInformation("Bidirectional 5MB: PASS");
    }
}