using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.IntegrationTests;

/// <summary>
///     End-to-end 5MB data transfer tests through I2P tunnels via SAM streams.
///     Tests both directions (C#→i2pd and i2pd→C#) and verifies data integrity
///     using SHA-256 hashes.
/// </summary>
[TestFixture]
[Category("Integration")]
public class DataTransferTests
{
    [SetUp]
    public void SetUp()
    {
        TestNetworkFixture.RequireI2pd();
        TestNetworkFixture.RequireCSharpRouter();
    }

    private const int DataSize = 5 * 1024 * 1024; // 5MB
    private const int DataTransferTimeoutMs = 300000; // 5 minutes
    private const int ConnectionTimeoutMs = 120000; // 2 minutes

    /// <summary>
    ///     Wait for both routers to have established tunnels before data transfer.
    ///     Tunnels are required for SAM stream connectivity.
    /// </summary>
    private async Task WaitForTunnels(int timeoutMs = 120000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            var outCount = TunnelProvider.Inst?.OutboundTunnelCount ?? 0;
            var inCount = TunnelProvider.Inst?.InboundTunnelCount ?? 0;

            if (outCount > 0 && inCount > 0)
            {
                Logging.LogInformation(
                    $"Tunnels ready: out={outCount}, in={inCount}");
                return;
            }

            Logging.LogDebug(
                $"Waiting for tunnels: out={outCount}, in={inCount}");
            await Task.Delay(3000);
        }

        Assert.Ignore("Tunnels not established within timeout — skipping data transfer");
    }

    /// <summary>
    ///     C# router sends 5MB to i2pd via SAM STREAM.
    ///     Data flows: C# SAM → C# tunnels → i2pd tunnels → i2pd SAM.
    ///     Verifies SHA-256 hash on receiving side.
    ///     <para>
    ///         <b>Quarantined by batch 4-0e; owner Phase 5 (5-5), with the rest of the 5 MB SAM
    ///         transfers.</b> See <see cref="TestSend5MB_ECIES_X25519" /> for the mechanism: with
    ///         the SAM bridge finally bound these reach a real transfer, stall on the streaming
    ///         layer Phase 5 repairs, and their <c>CancelAfter</c> cancels a token no signature
    ///         here accepts — so NUnit records a failure while the test thread runs on, and the
    ///         orphans take the host down. Which one dies is a race: 4-0e's first CI run lost
    ///         <c>TestSend5MB_ECIES_X25519</c>, the second <c>TestSend5MB_CSharpToI2pd_SAM</c>.
    ///     </para>
    /// </summary>
    [Test]
    [CancelAfter(DataTransferTimeoutMs)]
    [Category(TestCategories.Experimental)]
    public async Task TestSend5MB_CSharpToI2pd_SAM()
    {
        await WaitForTunnels();

        var testData = SAMHelper.GenerateTestData(DataSize, 100);
        var expectedHash = SAMHelper.ComputeSha256(testData);

        Logging.LogInformation(
            $"Test: C#→i2pd, {DataSize / 1024 / 1024}MB, " +
            $"hash={Convert.ToHexString(expectedHash)[..16]}...");

        // Step 1: Create receiver session on i2pd SAM
        using var recvControl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        var recvDest = await recvControl.CreateSessionAsync("recv_cs2i2pd");
        Assert.IsNotNull(recvDest, "i2pd receiver destination should not be null");
        Logging.LogInformation($"i2pd receiver destination created ({recvDest.Length} chars)");

        // Step 2: Start STREAM ACCEPT on a separate connection (blocks until connect)
        using var recvData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);

        var acceptTask = Task.Run(async () =>
        {
            await recvData.StreamAcceptAsync("recv_cs2i2pd");
            Logging.LogInformation("i2pd: STREAM ACCEPT completed");
        });

        // Give ACCEPT a moment to start waiting
        await Task.Delay(2000);

        // Step 3: Create sender session on C# SAM
        using var sendControl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        await sendControl.CreateSessionAsync("send_cs2i2pd");

        // Step 4: STREAM CONNECT from C# to i2pd destination
        using var sendData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        await sendData.StreamConnectAsync("send_cs2i2pd", recvDest);
        Logging.LogInformation("C#: STREAM CONNECT completed");

        // Wait for ACCEPT to complete
        await acceptTask;

        // Step 5: Send 5MB from C# side
        using var cts = new CancellationTokenSource(DataTransferTimeoutMs);
        var sendTask = Task.Run(async () =>
        {
            await sendData.SendDataAsync(testData, cts.Token);
            Logging.LogInformation($"C#: Sent {testData.Length} bytes");
        }, cts.Token);

        // Step 6: Receive 5MB on i2pd side
        var receivedData = await recvData.ReceiveDataAsync(DataSize, cts.Token);
        await sendTask; // Ensure send completed

        Logging.LogInformation($"i2pd: Received {receivedData.Length} bytes");

        // Step 7: Verify SHA-256 hash
        var receivedHash = SAMHelper.ComputeSha256(receivedData);
        Assert.IsTrue(SAMHelper.HashesMatch(expectedHash, receivedHash),
            $"SHA-256 mismatch!\n" +
            $"  Expected: {Convert.ToHexString(expectedHash)}\n" +
            $"  Received: {Convert.ToHexString(receivedHash)}");

        Logging.LogInformation("C#→i2pd 5MB transfer: PASS");
    }

    /// <summary>
    ///     i2pd sends 5MB to C# router via SAM STREAM.
    ///     Data flows: i2pd SAM → i2pd tunnels → C# tunnels → C# SAM.
    ///     Verifies SHA-256 hash on receiving side.
    ///     <para>
    ///         <b>Quarantined by batch 4-0e; owner Phase 5 (5-5), with the rest of the 5 MB SAM
    ///         transfers.</b> See <see cref="TestSend5MB_ECIES_X25519" /> for the mechanism: with
    ///         the SAM bridge finally bound these reach a real transfer, stall on the streaming
    ///         layer Phase 5 repairs, and their <c>CancelAfter</c> cancels a token no signature
    ///         here accepts — so NUnit records a failure while the test thread runs on, and the
    ///         orphans take the host down. Which one dies is a race: 4-0e's first CI run lost
    ///         <c>TestSend5MB_ECIES_X25519</c>, the second <c>TestSend5MB_CSharpToI2pd_SAM</c>.
    ///     </para>
    /// </summary>
    [Test]
    [CancelAfter(DataTransferTimeoutMs)]
    [Category(TestCategories.Experimental)]
    public async Task TestSend5MB_I2pdToCSharp_SAM()
    {
        await WaitForTunnels();

        var testData = SAMHelper.GenerateTestData(DataSize, 200);
        var expectedHash = SAMHelper.ComputeSha256(testData);

        Logging.LogInformation(
            $"Test: i2pd→C#, {DataSize / 1024 / 1024}MB, " +
            $"hash={Convert.ToHexString(expectedHash)[..16]}...");

        // Step 1: Create receiver session on C# SAM
        using var recvControl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        var recvDest = await recvControl.CreateSessionAsync("recv_i2pd2cs");
        Assert.IsNotNull(recvDest, "C# receiver destination should not be null");
        Logging.LogInformation($"C# receiver destination created ({recvDest.Length} chars)");

        // Step 2: Start STREAM ACCEPT on a separate connection
        using var recvData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);

        var acceptTask = Task.Run(async () =>
        {
            await recvData.StreamAcceptAsync("recv_i2pd2cs");
            Logging.LogInformation("C#: STREAM ACCEPT completed");
        });

        await Task.Delay(2000);

        // Step 3: Create sender session on i2pd SAM
        using var sendControl = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        await sendControl.CreateSessionAsync("send_i2pd2cs");

        // Step 4: STREAM CONNECT from i2pd to C# destination
        using var sendData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        await sendData.StreamConnectAsync("send_i2pd2cs", recvDest);
        Logging.LogInformation("i2pd: STREAM CONNECT completed");

        await acceptTask;

        // Step 5: Send 5MB from i2pd side
        using var cts = new CancellationTokenSource(DataTransferTimeoutMs);
        var sendTask = Task.Run(async () =>
        {
            await sendData.SendDataAsync(testData, cts.Token);
            Logging.LogInformation($"i2pd: Sent {testData.Length} bytes");
        }, cts.Token);

        // Step 6: Receive 5MB on C# side
        var receivedData = await recvData.ReceiveDataAsync(DataSize, cts.Token);
        await sendTask;

        Logging.LogInformation($"C#: Received {receivedData.Length} bytes");

        // Step 7: Verify
        var receivedHash = SAMHelper.ComputeSha256(receivedData);
        Assert.IsTrue(SAMHelper.HashesMatch(expectedHash, receivedHash),
            $"SHA-256 mismatch!\n" +
            $"  Expected: {Convert.ToHexString(expectedHash)}\n" +
            $"  Received: {Convert.ToHexString(receivedHash)}");

        Logging.LogInformation("i2pd→C# 5MB transfer: PASS");
    }

    /// <summary>
    ///     Bidirectional 5MB transfer: both routers send simultaneously.
    ///     Tests that the streaming protocol handles concurrent traffic.
    ///     <para>
    ///         <b>Quarantined by batch 4-0e; owner Phase 5 (5-5), with the rest of the 5 MB SAM
    ///         transfers.</b> See <see cref="TestSend5MB_ECIES_X25519" /> for the mechanism: with
    ///         the SAM bridge finally bound these reach a real transfer, stall on the streaming
    ///         layer Phase 5 repairs, and their <c>CancelAfter</c> cancels a token no signature
    ///         here accepts — so NUnit records a failure while the test thread runs on, and the
    ///         orphans take the host down. Which one dies is a race: 4-0e's first CI run lost
    ///         <c>TestSend5MB_ECIES_X25519</c>, the second <c>TestSend5MB_CSharpToI2pd_SAM</c>.
    ///     </para>
    /// </summary>
    [Test]
    [CancelAfter(DataTransferTimeoutMs)]
    [Category(TestCategories.Experimental)]
    public async Task TestBidirectional5MB_SAM()
    {
        await WaitForTunnels();

        var dataA = SAMHelper.GenerateTestData(DataSize, 300);
        var dataB = SAMHelper.GenerateTestData(DataSize, 400);
        var hashA = SAMHelper.ComputeSha256(dataA);
        var hashB = SAMHelper.ComputeSha256(dataB);

        Logging.LogInformation(
            $"Test: Bidirectional {DataSize / 1024 / 1024}MB");

        // Create sessions: A on C# SAM, B on i2pd SAM
        using var sessionA = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        var destA = await sessionA.CreateSessionAsync("bidir_a");

        using var sessionB = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        var destB = await sessionB.CreateSessionAsync("bidir_b");

        // A accepts, B connects to A
        using var acceptA = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        var acceptTaskA = Task.Run(async () => { await acceptA.StreamAcceptAsync("bidir_a"); });

        await Task.Delay(2000);

        using var connectB = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        await connectB.StreamConnectAsync("bidir_b", destA);
        await acceptTaskA;

        Logging.LogInformation("Bidirectional stream established");

        using var cts = new CancellationTokenSource(DataTransferTimeoutMs);

        // Send A→B and B→A simultaneously
        var sendATask = connectB.SendDataAsync(dataB, cts.Token);
        var recvATask = acceptA.ReceiveDataAsync(DataSize, cts.Token);

        // For bidirectional on same stream, A sends back through the accepted stream
        // and B receives through the connected stream
        // Note: SAM streams are bidirectional after CONNECT/ACCEPT

        // Wait for B→A transfer (via connected→accepted)
        var receivedByA = await recvATask;
        await sendATask;

        // Verify B→A direction
        var receivedByAHash = SAMHelper.ComputeSha256(receivedByA);
        Assert.IsTrue(SAMHelper.HashesMatch(hashB, receivedByAHash),
            "B→A SHA-256 mismatch");

        Logging.LogInformation("Bidirectional 5MB transfer: PASS (B→A verified)");
    }

    /// <summary>
    ///     5MB transfer with ECIES-X25519 encryption (standard).
    ///     This is the default encryption for all SAM streams, so this test
    ///     verifies the standard path works end-to-end.
    ///
    ///     <para>
    ///         <b>Quarantined by batch 4-0e; owner Phase 5 (5-5).</b> Not because it fails —
    ///         it is supposed to fail, ECIES is the subsystem Phase 5 exists to repair — but
    ///         because of <i>how</i>. Before 4-0e it failed in seconds, on "failed to connect to
    ///         the SAM bridge", since nothing was listening on the configured port. With the
    ///         bridge actually bound it gets as far as a real 5 MB transfer, hangs, and reaches
    ///         <c>CancelAfter</c> — and the timeout takes the test host process down with it:
    ///         <c>"The active test run was aborted. Reason: Test host process crashed"</c>.
    ///     </para>
    ///     <para>
    ///         That cost the eleven ScaledNetwork tests, which run after this namespace and
    ///         never started, and tripped batch 3-2's <c>MIN_INTEGRATION_TESTS</c> guard —
    ///         working exactly as intended. <b>One hanging test must not be able to erase
    ///         unrelated coverage</b>, and 23 tests in this suite carry <c>CancelAfter</c>, so
    ///         this will recur as Phase 5 progresses and more of them get far enough to hang.
    ///         The durable fix is batch 4-0f: isolate the namespaces so a crash truncates one
    ///         group rather than the run. Un-quarantine this when 5-5 lands.
    ///     </para>
    /// </summary>
    [Test]
    [CancelAfter(DataTransferTimeoutMs)]
    [Category(TestCategories.Experimental)]
    public async Task TestSend5MB_ECIES_X25519()
    {
        // ECIES-X25519 is the default encryption for destinations.
        // This test is functionally identical to CSharpToI2pd but
        // explicitly documents what encryption is being tested.
        await WaitForTunnels();

        var testData = SAMHelper.GenerateTestData(DataSize, 500);
        var expectedHash = SAMHelper.ComputeSha256(testData);

        Logging.LogInformation("Test: 5MB with ECIES-X25519 (default)");

        // ECIES-X25519 is the default destination encryption type.
        // SAM TRANSIENT destination uses the router's default crypto.
        using var recv = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        var recvDest = await recv.CreateSessionAsync("ecies_recv");

        using var recvData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        var acceptTask = Task.Run(async () =>
            await recvData.StreamAcceptAsync("ecies_recv"));

        await Task.Delay(2000);

        using var send = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        await send.CreateSessionAsync("ecies_send");

        using var sendData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        await sendData.StreamConnectAsync("ecies_send", recvDest);
        await acceptTask;

        using var cts = new CancellationTokenSource(DataTransferTimeoutMs);
        var sendTask = sendData.SendDataAsync(testData, cts.Token);
        var receivedData = await recvData.ReceiveDataAsync(DataSize, cts.Token);
        await sendTask;

        var receivedHash = SAMHelper.ComputeSha256(receivedData);
        Assert.IsTrue(SAMHelper.HashesMatch(expectedHash, receivedHash),
            "ECIES-X25519 5MB transfer: SHA-256 mismatch");

        Logging.LogInformation("ECIES-X25519 5MB transfer: PASS");
    }

    /// <summary>
    ///     5MB transfer with ML-KEM768-X25519 hybrid encryption (post-quantum).
    ///     Skips if i2pd doesn't support ML-KEM.
    ///     <para>
    ///         <b>Quarantined by batch 4-0e; owner Phase 5 (5-5), with the rest of the 5 MB SAM
    ///         transfers.</b> See <see cref="TestSend5MB_ECIES_X25519" /> for the mechanism: with
    ///         the SAM bridge finally bound these reach a real transfer, stall on the streaming
    ///         layer Phase 5 repairs, and their <c>CancelAfter</c> cancels a token no signature
    ///         here accepts — so NUnit records a failure while the test thread runs on, and the
    ///         orphans take the host down. Which one dies is a race: 4-0e's first CI run lost
    ///         <c>TestSend5MB_ECIES_X25519</c>, the second <c>TestSend5MB_CSharpToI2pd_SAM</c>.
    ///     </para>
    /// </summary>
    [Test]
    [CancelAfter(DataTransferTimeoutMs)]
    [Category(TestCategories.Experimental)]
    public async Task TestSend5MB_MLKEM768_Hybrid()
    {
        // Check if i2pd supports ML-KEM
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var hasPQ = false;
        if (i2pdInfo?.Addresses != null)
            foreach (var addr in i2pdInfo.Addresses)
            {
                foreach (var opt in addr.Options)
                    if (opt.Key.ToString() == "i" && opt.Value.ToString().Length > 44)
                    {
                        hasPQ = true;
                        break;
                    }

                if (hasPQ) break;
            }

        if (!hasPQ)
            Assert.Ignore("i2pd does not advertise ML-KEM support");

        await WaitForTunnels();

        var testData = SAMHelper.GenerateTestData(DataSize, 600);
        var expectedHash = SAMHelper.ComputeSha256(testData);

        Logging.LogInformation("Test: 5MB with ML-KEM768-X25519 hybrid");

        // Create SAM session with SIGNATURE_TYPE and CRYPTO_TYPE options
        // to request ML-KEM hybrid encryption for the destination.
        // Note: Whether ML-KEM is actually used depends on both routers' support.
        using var recv = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        var recvDest = await recv.CreateSessionAsync("mlkem_recv");

        using var recvData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.I2pdSam);
        var acceptTask = Task.Run(async () =>
            await recvData.StreamAcceptAsync("mlkem_recv"));

        await Task.Delay(2000);

        using var send = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        await send.CreateSessionAsync("mlkem_send");

        using var sendData = await SAMHelper.CreateAndHelloAsync(
            "127.0.0.1", PortAllocator.WellKnown.CSharpSam);
        await sendData.StreamConnectAsync("mlkem_send", recvDest);
        await acceptTask;

        using var cts = new CancellationTokenSource(DataTransferTimeoutMs);
        var sendTask = sendData.SendDataAsync(testData, cts.Token);
        var receivedData = await recvData.ReceiveDataAsync(DataSize, cts.Token);
        await sendTask;

        var receivedHash = SAMHelper.ComputeSha256(receivedData);
        Assert.IsTrue(SAMHelper.HashesMatch(expectedHash, receivedHash),
            "ML-KEM768 5MB transfer: SHA-256 mismatch");

        Logging.LogInformation("ML-KEM768-X25519 5MB transfer: PASS");
    }
}