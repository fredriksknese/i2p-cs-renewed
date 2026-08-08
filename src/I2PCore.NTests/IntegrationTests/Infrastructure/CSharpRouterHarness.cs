using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using I2PCore;
using I2PCore.Client;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PTests.IntegrationTests.Infrastructure;

/// <summary>
///     Wraps the C# I2P router for in-process integration testing.
///     Configures RouterContext for a private test network (netid=99)
///     with ports in the safe range (29000-29009).
/// </summary>
public class CSharpRouterHarness : IDisposable
{
    private readonly bool _floodfill;
    private readonly string _tempDir;

    private bool _disposed;

    // True if the router singleton was already running when Start() was called.
    // In that case, Stop() must NOT call Router.Stop() since we don't own the router.
    private bool _routerWasAlreadyRunning;
    private bool _started;

    public CSharpRouterHarness(
        int ntcp2Port = PortAllocator.WellKnown.CSharpNtcp2,
        int ssu2Port = PortAllocator.WellKnown.CSharpSsu2,
        int samPort = PortAllocator.WellKnown.CSharpSam,
        int i2cpPort = PortAllocator.WellKnown.CSharpI2cp,
        bool floodfill = false)
    {
        Ntcp2Port = ntcp2Port;
        Ssu2Port = ssu2Port;
        SamPort = samPort;
        I2cpPort = i2cpPort;
        _floodfill = floodfill;

        _tempDir = Path.Combine(Path.GetTempPath(), $"i2p_cs_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public int Ntcp2Port { get; }
    public int Ssu2Port { get; }
    public int SamPort { get; }
    public int I2cpPort { get; }

    /// <summary>
    ///     Whether this harness has a router that is actually usable right now.
    ///
    ///     <para>
    ///         Batch 4-0c (docs/PRODUCTION-PLAN.md). <b>A harness object outliving its router
    ///         is what broke 11 integration tests.</b> The router's state lives in process-wide
    ///         singletons, and <see cref="I2PCore.NetDb.NetDb.Stop" /> sets <c>NetDb.Inst</c> to
    ///         null — so once any fixture disposes a harness, every other harness object in the
    ///         process is a live C# reference to a dead router. <c>ScaledNetworkFixture</c>
    ///         tested <c>TestNetworkFixture.CSharpRouter != null</c>, which stayed true after
    ///         teardown, and went on to call <see cref="InjectPeerRouterInfo" /> —
    ///         <c>NetDb.Inst.AddRouterInfo</c> on a null <c>Inst</c>.
    ///     </para>
    ///     <para>
    ///         So <b>never branch on a harness reference being non-null</b>; branch on this.
    ///         It asks the singletons themselves, because they, not this object, are the router.
    ///     </para>
    /// </summary>
    public bool IsRunning =>
        _started && !_disposed && NetDb.Inst != null && TransportProvider.Inst != null;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Stop();

        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, true);
        }
        catch
        {
            // Best effort cleanup
        }
    }

    /// <summary>
    ///     Configure and start the C# router for the test network.
    /// </summary>
    public void Start()
    {
        if (_started)
            throw new InvalidOperationException("Router already started");

        // Reset RouterContext to ensure we pick up the new AppPathOverride
        RouterContext.Reset();

        Logging.LogToConsole = true;
        Logging.LogToDebug = true;
        Logging.SetLogLevel(Logging.LogLevels.Transport);

        // Set test network ID
        I2PConstants.I2PNetworkId = I2pdConfigGenerator.TestNetworkId;

        // Disable reseed — we inject peers directly
        Bootstrap.Disabled = true;

        // Redirect all router data to temp directory for test isolation
        StreamUtils.AppPathOverride = _tempDir;

        // Use a unique settings file in temp directory
        RouterContext.RouterSettingsFile =
            Path.Combine(_tempDir, "TestRouter.bin");

        // Configure the router
        var ctx = RouterContext.Inst;
        ctx.DefaultExtAddress = IPAddress.Loopback;
        ctx.DefaultTcpPort = Ntcp2Port;
        ctx.DefaultUdpPort = Ssu2Port;
        ctx.IsFirewalled = false;
        ctx.IsHidden = false;
        ctx.EnableSSU2 = true;
        ctx.FloodfillEnabled = _floodfill;
        ctx.ConfiguredBandwidth = RouterContext.BandwidthClass.X;

        ctx.ApplyNewSettings();

        Logging.LogInformation(
            $"C# test router configured: NTCP2={Ntcp2Port}, SSU2={Ssu2Port}, " +
            $"netId={I2PConstants.I2PNetworkId}, " +
            $"identity={ctx.MyRouterIdentity.IdentHash.Id32Short:x8}");

        // Batch 4-0e: configure the client services BEFORE Router.Start(), because
        // Router.Start() starts ClientContext itself. This block used to sit after it, so the
        // SAM bridge came up on its default 7656 and every test connecting to SamPort found
        // nothing listening. ClientContext.Start() now reconciles rather than discarding, so
        // this ordering is belt-and-braces — but it is also the honest order: settings before
        // the thing that reads them.
        ClientContext.Inst.SetConfig(
            ClientContext.CfgSamEnabled, "true");
        ClientContext.Inst.SetConfig(
            ClientContext.CfgSamPort, SamPort.ToString());
        // Disable other services to avoid port conflicts with a live router on this machine
        ClientContext.Inst.SetConfig(
            ClientContext.CfgHttpProxyEnabled, "false");
        ClientContext.Inst.SetConfig(
            ClientContext.CfgSocksProxyEnabled, "false");

        // Track if router was already running before we call Start().
        // Router.Start() is a no-op if already running, but we must not stop it
        // in that case — stopping would kill the shared singleton for other test fixtures.
        _routerWasAlreadyRunning = TransportProvider.Inst != null;

        // Start the router
        Router.Start();
        _started = true;

        try
        {
            ClientContext.Inst.Start();

            // Report what is bound, not what was asked for. The old message printed SamPort
            // unconditionally and so claimed a bridge on 29002 while one was running on 7656.
            var bound = ClientContext.Inst.SAMBridge is null ? "nothing" : $"port {SamPort}";
            Logging.LogInformation($"C# test router SAM bridge: {bound}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to start SAM bridge: {ex.Message}");
        }

        Logging.LogInformation("C# test router started");
    }

    /// <summary>
    ///     Get the router's RouterInfo for exchange with other routers.
    /// </summary>
    public I2PRouterInfo GetMyRouterInfo()
    {
        return RouterContext.Inst.MyRouterInfo;
    }

    /// <summary>
    ///     Get the router's identity hash.
    /// </summary>
    public I2PIdentHash GetMyIdentHash()
    {
        return RouterContext.Inst.MyRouterIdentity.IdentHash;
    }

    /// <summary>
    ///     Inject a peer's RouterInfo into our NetDb.
    /// </summary>
    public bool InjectPeerRouterInfo(I2PRouterInfo ri)
    {
        return NetDb.Inst.AddRouterInfo(ri);
    }

    /// <summary>
    ///     Wait for a transport connection to be established with the given peer.
    /// </summary>
    public async Task<bool> WaitForConnection(I2PIdentHash peer, int timeoutMs = 30000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (TransportProvider.Inst != null)
            {
                var et = TransportProvider.Inst.EstablishedTransports;
                if (et.TryGetValue(peer, out var info)
                    && info != null && info.IsEstablished
                    && !info.Transport.IsTerminated)
                    return true;
            }

            await Task.Delay(500);
        }

        return false;
    }

    /// <summary>
    ///     Check if we have an established transport connection to a peer.
    /// </summary>
    public bool IsConnectedTo(I2PIdentHash peer)
    {
        if (TransportProvider.Inst == null) return false;
        var et = TransportProvider.Inst.EstablishedTransports;
        return et.TryGetValue(peer, out var info)
               && info != null && info.IsEstablished
               && !info.Transport.IsTerminated;
    }

    /// <summary>
    ///     Get the protocol name of the established transport to a peer.
    /// </summary>
    public string GetConnectionProtocol(I2PIdentHash peer)
    {
        if (TransportProvider.Inst == null) return null;
        var et = TransportProvider.Inst.EstablishedTransports;
        if (et.TryGetValue(peer, out var info)
            && info?.Transport != null && info.IsEstablished)
            return info.Transport.GetType().Name;
        return null;
    }

    /// <summary>
    ///     Initiate a connection to a peer via TransportProvider.
    /// </summary>
    public void ConnectToPeer(I2PRouterInfo peerInfo)
    {
        // Sending a DatabaseStoreMessage with our RouterInfo triggers a connection
        var dsm = new DatabaseStoreMessage(
            RouterContext.Inst.MyRouterInfo);
        TransportProvider.Send(peerInfo.Identity.IdentHash, dsm);
    }

    public void Stop()
    {
        if (!_started) return;
        _started = false;

        if (_routerWasAlreadyRunning)
        {
            // We did not start the router — don't stop it.
            // Stopping would kill the shared singleton for other test fixtures.
            Logging.LogInformation("C# test router harness disposed (router was pre-existing; not stopped)");
        }
        else
        {
            try
            {
                Router.Stop();
                Logging.LogInformation("C# test router stopped");
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"Error stopping C# router: {ex.Message}");
            }

            // Batch 4-0c: this used to restore I2PConstants.I2PNetworkId = 0x02 and
            // Bootstrap.Disabled = false here, under the comment "restore defaults".
            //
            // Netid 2 is the live I2P network and that second line switches reseed back
            // on, so the "default" being restored was: talk to the real network, and
            // fetch peers from it. These are process-wide statics in a host that runs
            // many fixtures in sequence, and any router started afterwards that does not
            // go through Start() — ScaledNetworkFixture's reuse path, for one — inherits
            // them. CLAUDE.md and docs/PRODUCTION-PLAN.md rule 5 both forbid netid 2
            // outright until Gate 6.
            //
            // There is no correct value to restore. A test process has no legitimate
            // non-test consumer of these globals, so the safe thing is to leave the test
            // network id in place and leave reseed disabled. NetworkIdIsNeverRestoredToLive
            // in CSharpRouterHarnessTest fails if either line comes back.
            StreamUtils.AppPathOverride = null;
        }
    }
}