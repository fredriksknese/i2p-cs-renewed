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
        PublishSsu2OnlyRouterInfo()
    {
        var routerContext = new RouterContext
        {
            DefaultUdpPort = CapturePort,
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

    private static byte[] WaitForDatagram(UdpClient socket, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            if (socket.Available > 0)
            {
                var from = new IPEndPoint(IPAddress.Any, 0);
                var d = socket.Receive(ref from);
                TestContext.Out.WriteLine($"datagram from {from}, {d.Length} bytes");
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
        string i2pdVersion)
    {
        var dir = GoldenVectors.Directory();
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, GoldenVectors.Ssu2TokenRequest);

        var sb = new StringBuilder();
        sb.AppendLine("# SSU2 SessionRequest captured from i2pd. Batch 3-5.");
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
