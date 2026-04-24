using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using I2PCore;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.Utils;

namespace I2PTests.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Wraps the C# I2P router for in-process integration testing.
    /// Configures RouterContext for a private test network (netid=99)
    /// with ports in the safe range (29000-29009).
    /// </summary>
    public class CSharpRouterHarness : IDisposable
    {
        private readonly string _tempDir;
        private readonly bool _floodfill;
        private bool _started;
        private bool _disposed;
        // True if the router singleton was already running when Start() was called.
        // In that case, Stop() must NOT call Router.Stop() since we don't own the router.
        private bool _routerWasAlreadyRunning;

        public int Ntcp2Port { get; }
        public int Ssu2Port { get; }
        public int SamPort { get; }
        public int I2cpPort { get; }

        public CSharpRouterHarness(
            int ntcp2Port = PortAllocator.WellKnown.CSharpNtcp2,
            int ssu2Port = PortAllocator.WellKnown.CSharpSsu2,
            int samPort = PortAllocator.WellKnown.CSharpSam,
            int i2cpPort = PortAllocator.WellKnown.CSharpI2cp,
            bool floodfill = false )
        {
            Ntcp2Port = ntcp2Port;
            Ssu2Port = ssu2Port;
            SamPort = samPort;
            I2cpPort = i2cpPort;
            _floodfill = floodfill;

            _tempDir = Path.Combine( Path.GetTempPath(), $"i2p_cs_test_{Guid.NewGuid():N}" );
            Directory.CreateDirectory( _tempDir );
        }

        /// <summary>
        /// Configure and start the C# router for the test network.
        /// </summary>
        public void Start()
        {
            if ( _started )
                throw new InvalidOperationException( "Router already started" );

            // Reset RouterContext to ensure we pick up the new AppPathOverride
            RouterContext.Reset();

            Logging.LogToConsole = true;
            Logging.LogToDebug = true;
            Logging.SetLogLevel( Logging.LogLevels.Transport );

            // Set test network ID
            I2PConstants.I2PNetworkId = I2pdConfigGenerator.TestNetworkId;

            // Disable reseed — we inject peers directly
            Bootstrap.Disabled = true;

            // Redirect all router data to temp directory for test isolation
            StreamUtils.AppPathOverride = _tempDir;

            // Use a unique settings file in temp directory
            RouterContext.RouterSettingsFile =
                Path.Combine( _tempDir, "TestRouter.bin" );

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
                $"identity={ctx.MyRouterIdentity.IdentHash.Id32Short:x8}" );

            // Track if router was already running before we call Start().
            // Router.Start() is a no-op if already running, but we must not stop it
            // in that case — stopping would kill the shared singleton for other test fixtures.
            _routerWasAlreadyRunning = TransportProvider.Inst != null;

            // Start the router
            Router.Start();
            _started = true;

            // Start SAM bridge for data transfer tests
            try
            {
                I2PCore.Client.ClientContext.Inst.SetConfig(
                    I2PCore.Client.ClientContext.CfgSamEnabled, "true" );
                I2PCore.Client.ClientContext.Inst.SetConfig(
                    I2PCore.Client.ClientContext.CfgSamPort, SamPort.ToString() );
                // Disable other services to avoid port conflicts with live router
                I2PCore.Client.ClientContext.Inst.SetConfig(
                    I2PCore.Client.ClientContext.CfgHttpProxyEnabled, "false" );
                I2PCore.Client.ClientContext.Inst.SetConfig(
                    I2PCore.Client.ClientContext.CfgSocksProxyEnabled, "false" );
                I2PCore.Client.ClientContext.Inst.Start();
                Logging.LogInformation( $"SAM bridge started on port {SamPort}" );
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"Failed to start SAM bridge: {ex.Message}" );
            }

            Logging.LogInformation( "C# test router started" );
        }

        /// <summary>
        /// Get the router's RouterInfo for exchange with other routers.
        /// </summary>
        public I2PRouterInfo GetMyRouterInfo()
        {
            return RouterContext.Inst.MyRouterInfo;
        }

        /// <summary>
        /// Get the router's identity hash.
        /// </summary>
        public I2PIdentHash GetMyIdentHash()
        {
            return RouterContext.Inst.MyRouterIdentity.IdentHash;
        }

        /// <summary>
        /// Inject a peer's RouterInfo into our NetDb.
        /// </summary>
        public bool InjectPeerRouterInfo( I2PRouterInfo ri )
        {
            return NetDb.Inst.AddRouterInfo( ri );
        }

        /// <summary>
        /// Wait for a transport connection to be established with the given peer.
        /// </summary>
        public async Task<bool> WaitForConnection( I2PIdentHash peer, int timeoutMs = 30000 )
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while ( sw.ElapsedMilliseconds < timeoutMs )
            {
                if ( TransportProvider.Inst != null )
                {
                    var et = TransportProvider.Inst.EstablishedTransports;
                    if ( et.TryGetValue( peer, out var info )
                        && info != null && info.IsEstablished
                        && !info.Transport.IsTerminated )
                    {
                        return true;
                    }
                }

                await Task.Delay( 500 );
            }
            return false;
        }

        /// <summary>
        /// Check if we have an established transport connection to a peer.
        /// </summary>
        public bool IsConnectedTo( I2PIdentHash peer )
        {
            if ( TransportProvider.Inst == null ) return false;
            var et = TransportProvider.Inst.EstablishedTransports;
            return et.TryGetValue( peer, out var info )
                && info != null && info.IsEstablished
                && !info.Transport.IsTerminated;
        }

        /// <summary>
        /// Get the protocol name of the established transport to a peer.
        /// </summary>
        public string GetConnectionProtocol( I2PIdentHash peer )
        {
            if ( TransportProvider.Inst == null ) return null;
            var et = TransportProvider.Inst.EstablishedTransports;
            if ( et.TryGetValue( peer, out var info )
                && info?.Transport != null && info.IsEstablished )
            {
                return info.Transport.GetType().Name;
            }
            return null;
        }

        /// <summary>
        /// Initiate a connection to a peer via TransportProvider.
        /// </summary>
        public void ConnectToPeer( I2PRouterInfo peerInfo )
        {
            // Sending a DatabaseStoreMessage with our RouterInfo triggers a connection
            var dsm = new I2PCore.TunnelLayer.I2NP.Messages.DatabaseStoreMessage(
                RouterContext.Inst.MyRouterInfo );
            TransportProvider.Send( peerInfo.Identity.IdentHash, dsm );
        }

        public void Stop()
        {
            if ( !_started ) return;
            _started = false;

            if ( _routerWasAlreadyRunning )
            {
                // We did not start the router — don't stop it.
                // Stopping would kill the shared singleton for other test fixtures.
                Logging.LogInformation( "C# test router harness disposed (router was pre-existing; not stopped)" );
            }
            else
            {
                try
                {
                    Router.Stop();
                    Logging.LogInformation( "C# test router stopped" );
                }
                catch ( Exception ex )
                {
                    Logging.LogWarning( $"Error stopping C# router: {ex.Message}" );
                }

                // Restore defaults only when we own the router
                I2PConstants.I2PNetworkId = 0x02;
                Bootstrap.Disabled = false;
                StreamUtils.AppPathOverride = null;
            }
        }

        public void Dispose()
        {
            if ( _disposed ) return;
            _disposed = true;

            Stop();

            try
            {
                if ( Directory.Exists( _tempDir ) )
                    Directory.Delete( _tempDir, true );
            }
            catch
            {
                // Best effort cleanup
            }
        }
    }
}
