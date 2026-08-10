using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;

namespace I2PTests.IntegrationTests;

/// <summary>
///     Dial a real i2pd over SSU2 and establish a session.
///
///     <para>
///         <b>Everything else in Phase 4 is measured against a stored packet or against
///         ourselves.</b> The golden vectors prove we read i2pd's bytes correctly; the loopback
///         fixture proves our two halves agree. Neither proves a session establishes with a live
///         peer, and after five convention defects in a row that gap is the one worth closing.
///     </para>
///     <para>
///         <b>We dial i2pd, not the other way round.</b> Batch 4-2c recorded that i2pd does not
///         dial an SSU2-only peer on the local 2.45.1, so the inbound direction cannot be
///         exercised outside CI. The outbound direction depends on nothing but i2pd listening,
///         which it always does.
///     </para>
///     <para>
///         The host below is socket-backed rather than the loopback's channel-backed one, so the
///         packets on the wire are the packets production sends. It uses the same internal test
///         constructor: two hosts cannot otherwise coexist with the process-wide key store, and
///         a live router's keys are not ours to borrow.
///     </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Integration)]
public class SSU2LiveHandshakeTest
{
    private const int OurPort = 29260;
    private const int I2pdSsu2Port = 29261;
    private const int I2pdNtcp2Port = 29262;

    // Batch 4-1c: its own ports and its own i2pd. The two tests each start and stop a router, and
    // sharing a port between them would make whichever ran second depend on the first's teardown
    // having completed — a class of flake this suite has already paid for twice.
    private const int DataOurPort = 29270;
    private const int DataI2pdSsu2Port = 29271;
    private const int DataI2pdNtcp2Port = 29272;

    /// <summary>How long to wait for a handshake that is three round trips on loopback.</summary>
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    ///     One datagram and its ACK on loopback. Generous because i2pd may delay an ACK to
    ///     piggyback it, the same reason our own <c>MAX_ACK_DELAY_MS</c> exists.
    /// </summary>
    private static readonly TimeSpan DataPhaseTimeout = TimeSpan.FromSeconds(20);

    [Test]
    [CancelAfter(120000)]
    public void CSharpEstablishesAnSSU2SessionWithI2pd()
    {
        WithEstablishedSession(OurPort, I2pdSsu2Port, I2pdNtcp2Port, (_, _) => { });
    }

    /// <summary>
    ///     <b>Batch 4-1c. An established handshake is not a transport, and this is the difference.</b>
    ///
    ///     <para>
    ///         4-0n got a session to <c>Established</c> with i2pd 2.61.0, which retires the plan's
    ///         longest-standing open question but says nothing about carrying traffic: the data
    ///         phase uses different keys, a short header, and its own packet-number and ACK
    ///         bookkeeping, none of which the handshake exercises. **Batch 4-5 turns SSU2 on by
    ///         default and it must not do so on the strength of a handshake alone.**
    ///     </para>
    ///     <para>
    ///         <b>Measured by i2pd's acknowledgement, not by our own send succeeding.</b>
    ///         <c>UnackedPacketCount</c> returning to zero means i2pd received the datagram,
    ///         accepted it under the data-phase keys, and said so in an ACK block we then parsed.
    ///         A test that asserted only that <c>Send</c> was called would pass against a
    ///         black hole — which is precisely what the previous four CI runs were.
    ///     </para>
    ///     <para>
    ///         The message is a DatabaseStore of our own RouterInfo because that is what a real
    ///         router sends first on a new session, so a rejection is about our framing rather
    ///         than about i2pd objecting to something it never asked for.
    ///     </para>
    /// </summary>
    [Test]
    [CancelAfter(120000)]
    public void CSharpDeliversAnI2npMessageToI2pdOverSsu2()
    {
        WithEstablishedSession(DataOurPort, DataI2pdSsu2Port, DataI2pdNtcp2Port, (us, session) =>
        {
            session.Send(new DatabaseStoreMessage(us.MyRouterInfo));

            var deadline = DateTime.UtcNow + DataPhaseTimeout;
            while (DateTime.UtcNow < deadline && session.UnackedPacketCount > 0)
            {
                session.Tick();
                Thread.Sleep(100);
            }

            TestContext.Out.WriteLine(
                $"after send: {session.UnackedPacketCount} unacked, {us.Sent} sent / {us.Received} received");

            Assert.That(session.UnackedPacketCount, Is.Zero,
                "i2pd never acknowledged our I2NP message, so the SSU2 data phase does not carry "
                + "traffic to it even though the handshake completes. The session is established, "
                + $"{us.Sent} datagrams sent and {us.Received} received.");
        });
    }

    private void WithEstablishedSession(int ourPort, int i2pdSsu2Port, int i2pdNtcp2Port,
        Action<UdpSSU2Peer, SSU2Session> body)
    {
        if (RouterProcessManager.FindI2pdBinary() == null)
            Assert.Ignore("i2pd not found; set I2PD_PATH. See CLAUDE.md.");

        var originalNetId = I2PConstants.I2PNetworkId;
        I2PConstants.I2PNetworkId = I2pdConfigGenerator.TestNetworkId;

        var dataDir = Path.Combine(Path.GetTempPath(), $"ssu2_live_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dataDir);

        using var manager = new RouterProcessManager();
        UdpSSU2Peer us = null;

        try
        {
            var configFile = Path.Combine(dataDir, "i2pd.conf");
            File.WriteAllText(configFile, I2pdConfigGenerator.GenerateConfig(
                dataDir,
                i2pdNtcp2Port,
                i2pdSsu2Port,
                ourPort + 5,
                ourPort + 3,
                ourPort + 6,
                logFile: Path.Combine(dataDir, "i2pd.log")));

            manager.StartI2pd(configFile, dataDir).GetAwaiter().GetResult();

            var i2pdInfo = RouterInfoExchanger
                .WaitAndImportI2pdRouterInfo(dataDir, 60000)
                .GetAwaiter().GetResult();

            Assert.That(i2pdInfo, Is.Not.Null, $"i2pd published no RouterInfo. Log: {dataDir}/i2pd.log");

            var ssu2 = i2pdInfo.Addresses?.FirstOrDefault(a => a.TransportStyle == "SSU2");
            Assert.That(ssu2, Is.Not.Null,
                "i2pd advertises no SSU2 address, so there is nothing to dial");

            TestContext.Out.WriteLine($"i2pd SSU2 address: {ssu2}");

            us = new UdpSSU2Peer(ourPort);
            var session = us.ConnectTo(i2pdInfo);

            Assert.That(session, Is.Not.Null,
                "AddSession found no dialable SSU2 address in i2pd's RouterInfo");

            var deadline = DateTime.UtcNow + HandshakeTimeout;
            while (DateTime.UtcNow < deadline && session.State != SessionState.Established
                                              && session.State != SessionState.Terminated)
                Thread.Sleep(100);

            TestContext.Out.WriteLine(
                $"final state {session.State} after {us.Sent} sent / {us.Received} received");

            // Distinguish "this i2pd will not talk to us at all" from "our handshake is wrong".
            // i2pd 2.45.1 rejects unsolicited SSU2 from reserved-range source addresses before
            // any decryption — verified directly by firing 87, 200 and 1300 bytes of random data
            // at it and getting the identical rejection, and again from a non-loopback RFC1918
            // address. `reservedrange = false` does not take effect in that build. A run that
            // ends there says nothing about our protocol, so it must not be reported as if it
            // did; CI runs 2.61.0, which batch 4-2c showed does interoperate over loopback.
            var i2pdLog = Path.Combine(dataDir, "i2pd.log");
            if (us.Received == 0 && File.Exists(i2pdLog)
                                 && File.ReadAllText(i2pdLog).Contains("invalid endpoint"))
                Assert.Ignore(
                    "i2pd rejected our datagram at its endpoint check, before any crypto — it "
                    + "logs 'Incoming packet received from invalid endpoint'. This i2pd build "
                    + $"refuses unsolicited SSU2 from reserved-range addresses. Version: "
                    + $"{RouterProcessManager.FindI2pdBinary()}. Nothing here measures our "
                    + "handshake; run it against 2.61.0.");

            // The i2pd log lives in a per-run temp directory that CI does not upload, and this
            // test's whole value is in what i2pd says about our packet. Put its SSU2 lines in
            // the test output, where the run report already goes. Batch 4-0f learned this the
            // expensive way: absence of logs is not absence of execution, and a log nobody
            // collects is a log nobody has.
            if (session.State != SessionState.Established && File.Exists(i2pdLog))
            {
                TestContext.Out.WriteLine("--- i2pd log, SSU2 lines ---");
                foreach (var line in File.ReadAllLines(i2pdLog)
                             .Where(l => l.Contains("SSU2") || l.Contains("Transports"))
                             .TakeLast(40))
                    TestContext.Out.WriteLine(line);
            }

            Assert.That(session.State, Is.EqualTo(SessionState.Established),
                $"no SSU2 session with i2pd: state {session.State}, {us.Sent} datagrams sent, "
                + $"{us.Received} received. i2pd's own SSU2 log lines are in this test's output.");

            body(us, session);
        }
        finally
        {
            us?.Dispose();
            I2PConstants.I2PNetworkId = originalNetId;
        }
    }

    /// <summary>
    ///     An <see cref="SSU2Host" /> on a real UDP socket, with its own identity and keys.
    ///     The loopback fixture's peer with the channel replaced by a socket.
    /// </summary>
    private sealed class UdpSSU2Peer : IDisposable
    {
        private readonly LiveHost _host;
        private readonly RouterContext _routerContext;
        private readonly UdpClient _socket;
        private readonly Thread _receiver;
        private volatile bool _stop;

        public UdpSSU2Peer(int port)
        {
            var routerContext = new RouterContext
            {
                DefaultUdpPort = port,
                DefaultTcpPort = port,
                DefaultExtAddress = IPAddress.Loopback,
                IsFirewalled = false
            };

            _routerContext = routerContext;

            var (priv, pub) = X25519.GenerateKeyPair();
            _socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
            _host = new LiveHost(routerContext, priv, pub, BufUtils.RandomBytes(32), _socket, this);

            _receiver = new Thread(Receive) { IsBackground = true, Name = "ssu2-live-recv" };
            _receiver.Start();
        }

        public int Sent { get; set; }
        public int Received { get; private set; }

        /// <summary>Our own RouterInfo, so a test can send something a real router would send.</summary>
        public I2PRouterInfo MyRouterInfo => _routerContext.MyRouterInfo;

        public void Dispose()
        {
            _stop = true;
            _socket?.Dispose();
            _receiver?.Join(TimeSpan.FromSeconds(2));
        }

        public SSU2Session ConnectTo(I2PRouterInfo remote)
        {
            var session = (SSU2Session)_host.AddSession(remote);
            session?.Connect();
            return session;
        }

        private void Receive()
        {
            while (!_stop)
                try
                {
                    var from = new IPEndPoint(IPAddress.Any, 0);
                    var data = _socket.Receive(ref from);
                    Received++;
                    _host.DispatchPacket(from, data);
                }
                catch (Exception ex)
                {
                    // The socket closing under us at teardown is the normal exit from this loop;
                    // anything else is worth seeing, because a swallowed receive error here would
                    // look exactly like i2pd never replying.
                    if (_stop) return;
                    TestContext.Out.WriteLine($"receive loop: {ex.Message}");
                }
        }

        private sealed class LiveHost : SSU2Host
        {
            private readonly UdpSSU2Peer _owner;
            private readonly UdpClient _socket;

            internal LiveHost(RouterContext ctx, byte[] priv, byte[] pub, byte[] introKey,
                UdpClient socket, UdpSSU2Peer owner)
                : base(ctx, priv, pub, introKey)
            {
                _socket = socket;
                _owner = owner;
            }

            public override void SendPacket(IPEndPoint destination, byte[] data)
            {
                _owner.Sent++;
                _socket.Send(data, data.Length, destination);
            }
        }
    }
}
