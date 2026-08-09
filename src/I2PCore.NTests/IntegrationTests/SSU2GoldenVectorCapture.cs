using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;

namespace I2PTests.IntegrationTests;

/// <summary>
///     Captures the first SSU2 packet i2pd sends when dialling us, and writes it to
///     <c>TestData/ssu2_tokenrequest_i2pd.txt</c> as a checked-in golden vector.
///
///     Batch 3-5 (docs/PRODUCTION-PLAN.md).
///
///     <para>
///         <b>Why this matters more than the plan implies.</b> Batch 3-3 showed that our own
///         SSU2 SessionRequest cannot be authenticated by our own responder — the Noise layer is
///         self-consistent, so the header bytes the initiator hashes are not the bytes the
///         responder recovers. That narrows it to header handling but does not say which side is
///         wrong. A SessionRequest built by i2pd is the reference that decides it: if ours
///         fails to parse but i2pd's succeeds, our construction is at fault; if i2pd's fails the
///         same way, our processing is.
///     </para>
///     <para>
///         <b>How the capture works.</b> A RouterInfo advertising only an SSU2 address, with
///         keys we choose, is written into a fresh i2pd netDb. i2pd is then started on the
///         private test network with reseed off, so that RouterInfo is the only peer it knows,
///         and it dials us. We hold the UDP port ourselves and never answer, so the first
///         datagram to arrive is i2pd's opening move — which turned out to be a TokenRequest,
///         not a SessionRequest. See <c>Ssu2GoldenVectorTest</c>.
///     </para>
///     <para>
///         The static private key and intro key are stored alongside the packet. Without them
///         the bytes are unopenable, and they are throwaway keys generated for one capture.
///     </para>
///     <para>
///         Integration-category and not run in the unit suite. It is a *producer*: run it once
///         when the vector needs refreshing, check in the result, and the unit tests over that
///         fixture run everywhere without i2pd.
///     </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Integration)]
[NonParallelizable]
public class SSU2GoldenVectorCapture
{
    /// <summary>Outside the 29000-29099 block so a capture cannot collide with the test network.</summary>
    private const int CapturePort = 29200;

    private const int WaitForDialSeconds = 120;

    /// <summary>Batch 4-2c: a second capture port, so the two producers cannot collide.</summary>
    private const int SessionRequestCapturePort = 29210;

    /// <summary>i2pd answers an accepted Retry promptly; this only has to outlast one RTT.</summary>
    private const int WaitForReplySeconds = 60;

    [Test]
    public void CaptureFirstSsu2MessageFromI2pd()
    {
        if (RouterProcessManager.FindI2pdBinary() == null)
            Assert.Ignore("i2pd not found; set I2PD_PATH. See CLAUDE.md.");

        var originalNetId = I2PConstants.I2PNetworkId;
        I2PConstants.I2PNetworkId = I2pdConfigGenerator.TestNetworkId;

        var dataDir = Path.Combine(Path.GetTempPath(), $"ssu2_capture_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dataDir);

        using var manager = new RouterProcessManager();
        UdpClient socket = null;

        try
        {
            var (routerInfo, staticPrivate, staticPublic, introKey) = PublishSsu2OnlyRouterInfo();

            // Hold the port before i2pd starts, so its first dial cannot arrive at a closed one.
            socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, CapturePort));

            RouterInfoExchanger.ExportRouterInfo(routerInfo, Path.Combine(dataDir, "netDb"));

            var configFile = Path.Combine(dataDir, "i2pd.conf");
            File.WriteAllText(configFile, I2pdConfigGenerator.GenerateConfig(
                dataDir,
                ntcp2Port: CapturePort + 1,
                ssu2Port: CapturePort + 2,
                samPort: CapturePort + 5,
                i2cpPort: CapturePort + 3,
                httpPort: CapturePort + 6,
                logFile: Path.Combine(dataDir, "i2pd.log")));

            manager.StartI2pd(configFile, dataDir).GetAwaiter().GetResult();

            var packet = WaitForDatagram(socket, TimeSpan.FromSeconds(WaitForDialSeconds));

            Assert.That(packet, Is.Not.Null,
                $"i2pd sent nothing to {CapturePort} within {WaitForDialSeconds}s. It may have "
                + "declined to dial an SSU2-only peer; check the i2pd log in " + dataDir);

            var written = WriteVector(packet, staticPrivate, staticPublic, introKey,
                RouterProcessManager.GetI2pdVersion(RouterProcessManager.FindI2pdBinary()));

            TestContext.Out.WriteLine($"Captured {packet.Length} bytes to {written}");

            // Any SSU2 long-header message is at least a 32-byte header plus a 16-byte MAC.
            // Deliberately not asserting a SessionRequest size: what i2pd actually sends first
            // is a TokenRequest, which is what made this capture worth doing.
            Assert.That(packet.Length, Is.GreaterThanOrEqualTo(48),
                "captured datagram is too short to be an SSU2 long-header message");
        }
        finally
        {
            socket?.Dispose();
            manager.StopI2pd();
            I2PConstants.I2PNetworkId = originalNetId;
            TryDelete(dataDir);
        }
    }

    /// <summary>
    ///     Build a RouterContext advertising an SSU2 address and nothing else, with keys we keep.
    ///     Uses the batch 3-3 <see cref="SSU2Host" /> test constructor, which publishes the
    ///     address without binding a socket — we want the port for ourselves.
    /// </summary>
    private static (I2PRouterInfo ri, byte[] priv, byte[] pub, byte[] introKey)
        PublishSsu2OnlyRouterInfo(int udpPort = CapturePort)
    {
        var routerContext = new RouterContext
        {
            DefaultUdpPort = udpPort,
            DefaultTcpPort = CapturePort,
            DefaultExtAddress = IPAddress.Loopback,
            IsFirewalled = false
        };

        var (priv, pub) = X25519.GenerateKeyPair();
        var introKey = BufUtils.RandomBytes(32);

        // Constructing it is what publishes the address into routerContext.
        _ = new SSU2Host(routerContext, priv, pub, introKey);

        return (routerContext.MyRouterInfo, priv, pub, introKey);
    }

    /// <summary>
    ///     Batch 4-2c. Answer i2pd's TokenRequest with a Retry built by production code, then
    ///     capture what it sends next — which should be a Session Request.
    ///
    ///     <para>
    ///         <b>The existence of the captured file is itself the assertion.</b> i2pd only
    ///         proceeds to a Session Request if the Retry authenticated and carried a token it
    ///         accepted, so a Session Request arriving is end-to-end proof that batch 4-2a's
    ///         Retry is correct — against the real peer, not against ourselves. If our Retry were
    ///         wrong, i2pd would simply retransmit its TokenRequest or give up, and this test
    ///         would fail with nothing captured.
    ///     </para>
    ///     <para>
    ///         The captured Session Request is what batch <b>4-0b</b> has been blocked on since
    ///         batch 3-5: it carries the ephemeral key, so it is the only thing that can settle
    ///         whether packet bytes 16..64 are one 48-byte ChaCha20 pass (i2pd) or two restarted
    ///         ones (us). Nothing already in the repository can answer that — the TokenRequest
    ///         vector has no ephemeral key at all.
    ///     </para>
    ///     <para>
    ///         A *producer*, like its sibling: run it when the vector needs refreshing, check in
    ///         the result, and let socket-free unit tests read the bytes everywhere else.
    ///     </para>
    ///     <para>
    ///         <b>Needs a recent i2pd.</b> Neither this capture nor its sibling elicits a dial from
    ///         Debian's i2pd 2.45.1 — the sibling, which batch 3-5 ran successfully against 2.61.0
    ///         in CI, fails there too. That is the plan's risk R4 in miniature, so if this test
    ///         captures nothing, check the i2pd version before suspecting the Retry.
    ///     </para>
    /// </summary>
    [Test]
    public void CaptureSessionRequestByAnsweringTheTokenRequest()
    {
        if (RouterProcessManager.FindI2pdBinary() == null)
            Assert.Ignore("i2pd not found; set I2PD_PATH. See CLAUDE.md.");

        var originalNetId = I2PConstants.I2PNetworkId;
        I2PConstants.I2PNetworkId = I2pdConfigGenerator.TestNetworkId;

        var dataDir = Path.Combine(Path.GetTempPath(), $"ssu2_sr_capture_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dataDir);

        using var manager = new RouterProcessManager();
        UdpClient socket = null;

        try
        {
            // The advertised port must be the port we actually hold: i2pd dials what the
            // RouterInfo says, and defaulting this to the sibling capture's port sent i2pd to
            // 29200 while this test listened on 29210 and captured nothing.
            var (routerInfo, staticPrivate, staticPublic, introKey) =
                PublishSsu2OnlyRouterInfo(SessionRequestCapturePort);

            // A different port from the sibling capture, so the two can never collide.
            socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, SessionRequestCapturePort));

            RouterInfoExchanger.ExportRouterInfo(routerInfo, Path.Combine(dataDir, "netDb"));

            var configFile = Path.Combine(dataDir, "i2pd.conf");
            File.WriteAllText(configFile, I2pdConfigGenerator.GenerateConfig(
                dataDir,
                ntcp2Port: SessionRequestCapturePort + 1,
                ssu2Port: SessionRequestCapturePort + 2,
                samPort: SessionRequestCapturePort + 5,
                i2cpPort: SessionRequestCapturePort + 3,
                httpPort: SessionRequestCapturePort + 6,
                logFile: Path.Combine(dataDir, "i2pd.log")));

            manager.StartI2pd(configFile, dataDir).GetAwaiter().GetResult();

            // 1. i2pd opens with a TokenRequest.
            var first = WaitForDatagram(socket, TimeSpan.FromSeconds(WaitForDialSeconds), out var peer);

            Assert.That(first, Is.Not.Null,
                $"i2pd sent nothing to {SessionRequestCapturePort} within {WaitForDialSeconds}s; "
                + "check the i2pd log in " + dataDir);

            Assert.That(
                Retry.TryOpen(first, introKey, SSU2Header.TYPE_TOKEN_REQUEST, out var request, out _),
                Is.True,
                "the first datagram did not open as a TokenRequest. Either i2pd opened with "
                + "something else, or our header/AEAD convention has regressed — "
                + "Ssu2RetryTokenTest checks the same path against the checked-in vector.");

            // 2. Answer it with a Retry built by production code.
            var token = (ulong)BufUtils.RandomUint() | ((ulong)BufUtils.RandomUint() << 32);
            var retry = Retry.Build(request, token, introKey, peer);
            socket.Send(retry, retry.Length, peer);

            TestContext.Out.WriteLine(
                $"answered TokenRequest from {peer} with a {retry.Length}-byte Retry, token {token:x16}");

            // 3. If the Retry was accepted, i2pd now sends a Session Request.
            var second = WaitForDatagram(socket, TimeSpan.FromSeconds(WaitForReplySeconds));

            Assert.That(second, Is.Not.Null,
                "i2pd sent nothing after our Retry. It either did not accept it or could not read "
                + "it; the i2pd log in " + dataDir + " says which.");

            var written = WriteVector(second, staticPrivate, staticPublic, introKey,
                RouterProcessManager.GetI2pdVersion(RouterProcessManager.FindI2pdBinary()),
                GoldenVectors.Ssu2SessionRequest,
                "# SSU2 SessionRequest captured from i2pd, after it accepted our Retry. Batch 4-2c.");

            TestContext.Out.WriteLine($"Captured {second.Length} bytes to {written}");

            // A Session Request is 32 header + 32 ephemeral key + payload + 16 tag. Asserting the
            // floor rather than the type, because reading its type is precisely what batch 4-0b
            // is not yet able to do reliably — that is the point of capturing it.
            Assert.That(second.Length, Is.GreaterThanOrEqualTo(80),
                "the datagram after our Retry is too short to be a Session Request carrying an "
                + "ephemeral key; it may be a retransmitted TokenRequest, which would mean our "
                + "Retry was not accepted");
        }
        finally
        {
            socket?.Dispose();
            manager.StopI2pd();
            I2PConstants.I2PNetworkId = originalNetId;
            TryDelete(dataDir);
        }
    }

    private static byte[] WaitForDatagram(UdpClient socket, TimeSpan timeout)
    {
        return WaitForDatagram(socket, timeout, out _);
    }

    /// <summary>
    ///     Batch 4-2c also needs the sender, in order to answer it.
    /// </summary>
    private static byte[] WaitForDatagram(UdpClient socket, TimeSpan timeout, out IPEndPoint sender)
    {
        var deadline = DateTime.UtcNow + timeout;
        sender = null;

        while (DateTime.UtcNow < deadline)
        {
            if (socket.Available > 0)
            {
                var from = new IPEndPoint(IPAddress.Any, 0);
                var d = socket.Receive(ref from);
                TestContext.Out.WriteLine($"datagram from {from}, {d.Length} bytes");
                sender = from;
                return d;
            }

            Thread.Sleep(100);
        }

        return null;
    }

    /// <summary>
    ///     Text header then raw bytes, so the file is greppable and self-describing in a diff.
    ///     A binary container would need its own parser and its own bugs.
    /// </summary>
    private static string WriteVector(byte[] packet, byte[] priv, byte[] pub, byte[] introKey,
        string i2pdVersion, string fileName = null, string description = null)
    {
        var dir = GoldenVectors.Directory();
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, fileName ?? GoldenVectors.Ssu2TokenRequest);

        var sb = new StringBuilder();
        sb.AppendLine(description
            ?? "# SSU2 TokenRequest captured from i2pd. Batch 3-5.");
        sb.AppendLine($"# source: {i2pdVersion ?? "unknown"}");
        sb.AppendLine($"# netid: {I2pdConfigGenerator.TestNetworkId}");
        sb.AppendLine("# Throwaway keys, generated for this capture only.");
        sb.AppendLine($"static_private={Convert.ToHexString(priv)}");
        sb.AppendLine($"static_public={Convert.ToHexString(pub)}");
        sb.AppendLine($"intro_key={Convert.ToHexString(introKey)}");
        sb.AppendLine($"packet={Convert.ToHexString(packet)}");

        File.WriteAllText(path, sb.ToString());
        return path;
    }

    private static void TryDelete(string dir)
    {
        try
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"SSU2GoldenVectorCapture: could not remove {dir}: {ex.Message}");
        }
    }
}
