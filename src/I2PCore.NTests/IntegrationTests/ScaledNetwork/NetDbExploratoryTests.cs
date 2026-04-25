using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer;
using I2PCore;
using I2PTests.IntegrationTests.Infrastructure;

namespace I2PTests.ScaledNetwork
{
    [TestFixture]
    [Category( "Integration" )]
    [Category( "ScaledNetwork" )]
    public class NetDbExploratoryTests
    {
        private const int TunnelWaitIterations = 60;
        private const int TunnelWaitDelayMs = 5000;
        private const int MinExploratoryTunnels = 3;

        [SetUp]
        public void SetUp()
        {
            ScaledNetworkFixture.Require();
        }

        /// <summary>
        /// Wait for at least <paramref name="minCount"/> established exploratory tunnels
        /// in each direction. Tunnels must be real (non-zero-hop).
        /// </summary>
        private async Task WaitForExploratoryTunnels( int minCount = MinExploratoryTunnels )
        {
            bool inboundOk = false;
            bool outboundOk = false;

            for ( int i = 0; i < TunnelWaitIterations; ++i )
            {
                var inbound = TunnelProvider.Inst.GetInboundTunnels()
                    .Where( t => t.Pool == TunnelConfig.TunnelPool.Exploratory
                              && t.Established
                              && ( t.TunnelMembers?.Count() ?? 0 ) >= 1 )
                    .ToArray();
                var outbound = TunnelProvider.Inst.GetOutboundTunnels()
                    .Where( t => t.Pool == TunnelConfig.TunnelPool.Exploratory
                              && t.Established
                              && ( t.TunnelMembers?.Count() ?? 0 ) >= 1 )
                    .ToArray();

                Logging.LogInformation(
                    $"Exploratory tunnels: {inbound.Length} inbound, {outbound.Length} outbound (need {minCount} each)" );

                inboundOk = inbound.Length >= minCount;
                outboundOk = outbound.Length >= minCount;

                if ( inboundOk && outboundOk ) break;
                await Task.Delay( TunnelWaitDelayMs );
            }

            Assert.IsTrue( inboundOk,
                $"Should have at least {minCount} established inbound exploratory tunnels" );
            Assert.IsTrue( outboundOk,
                $"Should have at least {minCount} established outbound exploratory tunnels" );
        }

        /// <summary>
        /// Verify that at least 3 inbound and 3 outbound exploratory tunnels are
        /// built with real (non-zero-hop) i2pd routers as hops.
        /// </summary>
        [Test, Order( 1 )]
        [CancelAfter( 600_000 )]
        public async Task ExploratoryTunnelsShouldBeBuilt()
        {
            Logging.LogInformation( "=== ExploratoryTunnelsShouldBeBuilt ===" );
            await WaitForExploratoryTunnels( MinExploratoryTunnels );

            var inbound = TunnelProvider.Inst.GetInboundTunnels()
                .Where( t => t.Pool == TunnelConfig.TunnelPool.Exploratory
                          && t.Established
                          && ( t.TunnelMembers?.Count() ?? 0 ) >= 1 )
                .ToArray();
            var outbound = TunnelProvider.Inst.GetOutboundTunnels()
                .Where( t => t.Pool == TunnelConfig.TunnelPool.Exploratory
                          && t.Established
                          && ( t.TunnelMembers?.Count() ?? 0 ) >= 1 )
                .ToArray();

            Assert.GreaterOrEqual( inbound.Length, MinExploratoryTunnels,
                $"Need >= {MinExploratoryTunnels} inbound exploratory tunnels" );
            Assert.GreaterOrEqual( outbound.Length, MinExploratoryTunnels,
                $"Need >= {MinExploratoryTunnels} outbound exploratory tunnels" );

            foreach ( var t in inbound.Concat<Tunnel>( outbound ) )
            {
                var members = t.TunnelMembers?.ToArray();
                Assert.IsNotNull( members, $"Tunnel {t.TunnelDebugTrace} should have members" );
                Assert.GreaterOrEqual( members.Length, 1,
                    $"Tunnel {t.TunnelDebugTrace} should have at least 1 hop" );

                Logging.LogInformation(
                    $"Tunnel {t.TunnelDebugTrace} ({t.Config.Direction}) members: " +
                    string.Join( ", ", members.Select( m => m.IdentHash.Id32Short ) ) );
            }
        }

        /// <summary>
        /// After initial establishment, wait 2 minutes and verify that the router
        /// maintains at least 3 inbound and 3 outbound exploratory tunnels.
        /// This proves tunnel recreation works as tunnels approach expiry.
        /// </summary>
        [Test, Order( 2 )]
        [CancelAfter( 600_000 )]
        public async Task ExploratoryTunnelsShouldBeMaintained()
        {
            Logging.LogInformation( "=== ExploratoryTunnelsShouldBeMaintained ===" );
            await WaitForExploratoryTunnels( MinExploratoryTunnels );

            Logging.LogInformation( "Tunnels established. Waiting 2 minutes to verify maintenance..." );
            await Task.Delay( 120_000 );

            var inbound = TunnelProvider.Inst.GetInboundTunnels()
                .Where( t => t.Pool == TunnelConfig.TunnelPool.Exploratory
                          && t.Established
                          && ( t.TunnelMembers?.Count() ?? 0 ) >= 1 )
                .ToArray();
            var outbound = TunnelProvider.Inst.GetOutboundTunnels()
                .Where( t => t.Pool == TunnelConfig.TunnelPool.Exploratory
                          && t.Established
                          && ( t.TunnelMembers?.Count() ?? 0 ) >= 1 )
                .ToArray();

            Logging.LogInformation(
                $"After 2min: {inbound.Length} inbound, {outbound.Length} outbound exploratory tunnels" );

            Assert.GreaterOrEqual( inbound.Length, MinExploratoryTunnels,
                "Inbound exploratory tunnels should be maintained after 2 minutes" );
            Assert.GreaterOrEqual( outbound.Length, MinExploratoryTunnels,
                "Outbound exploratory tunnels should be maintained after 2 minutes" );
        }

        /// <summary>
        /// Start a new i2pd router unknown to C# Router 0, inject its RouterInfo
        /// into a floodfill, then verify C# 0 discovers it via a NetDb lookup
        /// sent through exploratory tunnels.
        /// </summary>
        [Test, Order( 3 )]
        [CancelAfter( 600_000 )]
        public async Task NetDbDiscoveryViaExploratoryTunnels()
        {
            Logging.LogInformation( "=== NetDbDiscoveryViaExploratoryTunnels ===" );
            await WaitForExploratoryTunnels();

            // Use index 9 to avoid port conflict with fixture's i2pd 0-8 (ports 29200-29230 are taken)
            var newI2pdConfig = ScaledNetworkFixture.CreateI2pdConfig(
                9, false, new I2PRouterInfo[] { ScaledNetworkFixture.I2pd0Info } );
            var newI2pd = new RouterProcessManager();

            try
            {
                Logging.LogInformation( "Starting new i2pd (index 9) for discovery test..." );
                int expectedPort = 29200 + ( 9 - 5 ) * 10; // 29240
                await newI2pd.StartI2pd( newI2pdConfig.configPath, newI2pdConfig.dataDir );
                await newI2pd.WaitForReady( expectedPort, 60000 );

                var newInfo = await RouterInfoExchanger.WaitAndImportI2pdRouterInfo(
                    newI2pdConfig.dataDir, 30000 );
                Assert.IsNotNull( newInfo, "New i2pd RouterInfo should be available" );

                // Inject the new router's info into floodfill i2pd 0 so it can be discovered
                Logging.LogInformation(
                    $"Injecting new i2pd into i2pd 0 at {ScaledNetworkFixture.I2pd0DataDir}" );
                RouterInfoExchanger.PlaceRouterInfoForI2pd( newInfo, ScaledNetworkFixture.I2pd0DataDir );

                // Ensure C# 0 does NOT know this router yet
                NetDb.Inst.RemoveRouterInfo( newInfo.Identity.IdentHash );
                Assert.IsFalse( NetDb.Inst.Contains( newInfo.Identity.IdentHash ),
                    "CSharp0 should not know the new i2pd yet" );

                Logging.LogInformation(
                    $"Triggering NetDb lookup for {newInfo.Identity.IdentHash.Id32Short}" );
                bool found = false;
                for ( int i = 0; i < 20; ++i )
                {
                    NetDb.Inst.IdentHashLookup.LookupRouterInfo( newInfo.Identity.IdentHash );

                    await Task.Delay( 10000 );
                    if ( NetDb.Inst.Contains( newInfo.Identity.IdentHash ) )
                    {
                        found = true;
                        Logging.LogInformation(
                            $"Discovered {newInfo.Identity.IdentHash.Id32Short} after {( i + 1 ) * 10}s" );
                        break;
                    }
                    Logging.LogInformation( $"Still waiting for NetDb discovery (attempt {i + 1})..." );
                }

                Assert.IsTrue( found,
                    "CSharp0 should have discovered the new i2pd via NetDb lookup using exploratory tunnels" );
            }
            finally
            {
                newI2pd.Dispose();
            }
        }

        /// <summary>
        /// Create client tunnels (2-hop inbound + outbound) via SAM, verify they are
        /// established, verify the LeaseSet is published to floodfills, and verify
        /// that i2pd 1 can connect to the C# destination (proving LeaseSet discovery
        /// and end-to-end data flow).
        /// </summary>
        [Test, Order( 4 )]
        [CancelAfter( 900_000 )]
        public async Task ClientTunnelsAndLeaseSetPublication()
        {
            Logging.LogInformation( "=== ClientTunnelsAndLeaseSetPublication ===" );
            await WaitForExploratoryTunnels();

            int csSamPort = PortAllocator.Scaled.Cs0Sam;
            int i2pdSamPort = PortAllocator.Scaled.I2pd1Sam;

            using var cts = new CancellationTokenSource( 800_000 );

            using var csSam = await SAMHelper.CreateAndHelloAsync( "127.0.0.1", csSamPort );
            var csDestBase64 = await csSam.CreateSessionAsync(
                "CS_DEST", "STREAM", 2, 2, 3, 3,
                timeoutMs: 300_000 );
            Logging.LogInformation(
                $"Created C# SAM session. Destination: {csDestBase64.Substring( 0, 20 )}..." );

            // Start a receiver task for C# session
            var receiverTask = Task.Run( async () =>
            {
                using var csAcceptor = await SAMHelper.CreateAndHelloAsync( "127.0.0.1", csSamPort );
                await csAcceptor.StreamAcceptAsync( "CS_DEST" );

                var stream = csAcceptor.GetStream();
                var buf = new byte[1024];
                var readCts = CancellationTokenSource.CreateLinkedTokenSource( cts.Token );
                readCts.CancelAfter( 120_000 );
                int read = await stream.ReadAsync( buf, 0, buf.Length, readCts.Token );
                var msg = System.Text.Encoding.UTF8.GetString( buf, 0, read );
                Logging.LogInformation( $"C# Receiver got message: {msg}" );

                var ackMsg = System.Text.Encoding.UTF8.GetBytes( "ACK: " + msg );
                await csAcceptor.SendDataAsync( ackMsg, readCts.Token );
                return msg;
            }, cts.Token );

            // Wait for client tunnels to be established
            bool tunnelsOk = false;
            for ( int i = 0; i < 60; ++i )
            {
                cts.Token.ThrowIfCancellationRequested();

                var bridge = I2PCore.Client.ClientContext.Inst.SAMBridge;
                if ( bridge != null && bridge.TryGetSession( "CS_DEST", out var session ) )
                {
                    var dest = session.Destination;
                    var inCount = (int)dest.InboundTunnelCount;
                    var outCount = (int)dest.OutboundTunnelCount;
                    Logging.LogInformation( $"CS_DEST tunnels: in={inCount}, out={outCount}" );
                    if ( inCount > 0 && outCount > 0 )
                    {
                        tunnelsOk = true;
                        break;
                    }
                }
                await Task.Delay( 5000, cts.Token );
            }
            Assert.IsTrue( tunnelsOk, "C# client tunnels should be established" );

            // Connect from i2pd 1 to the C# destination (proves LeaseSet was published)
            using var i2pdSam = await SAMHelper.CreateAndHelloAsync( "127.0.0.1", i2pdSamPort );
            await i2pdSam.CreateSessionAsync( "I2PD_CLIENT", "STREAM",
                timeoutMs: 300_000 );

            Logging.LogInformation(
                "Trying to connect to C# destination from i2pd 1 (triggers LeaseSet lookup)..." );
            bool connected = false;
            for ( int i = 0; i < 40; ++i )
            {
                cts.Token.ThrowIfCancellationRequested();

                try
                {
                    using var i2pdConn = await SAMHelper.CreateAndHelloAsync( "127.0.0.1", i2pdSamPort );
                    await i2pdConn.StreamConnectAsync( "I2PD_CLIENT", csDestBase64 );
                    Logging.LogInformation( "Successfully connected to C# destination from i2pd!" );

                    var testMsg = "Hello from i2pd " + Guid.NewGuid().ToString().Substring( 0, 8 );
                    await i2pdConn.SendDataAsync( System.Text.Encoding.UTF8.GetBytes( testMsg ), cts.Token );

                    var stream = i2pdConn.GetStream();
                    var buf = new byte[1024];
                    var readCts = CancellationTokenSource.CreateLinkedTokenSource( cts.Token );
                    readCts.CancelAfter( 60_000 );
                    int read = await stream.ReadAsync( buf, 0, buf.Length, readCts.Token );
                    var reply = System.Text.Encoding.UTF8.GetString( buf, 0, read );
                    Logging.LogInformation( $"i2pd Sender got reply: {reply}" );

                    Assert.AreEqual( "ACK: " + testMsg, reply );
                    var receivedMsg = await receiverTask;
                    Assert.AreEqual( testMsg, receivedMsg );

                    connected = true;
                    break;
                }
                catch ( OperationCanceledException ) { throw; }
                catch ( Exception ex )
                {
                    Logging.LogInformation( $"Connect attempt {i} failed: {ex.Message}" );
                }
                await Task.Delay( 10000, cts.Token );
            }
            Assert.IsTrue( connected,
                "i2pd 1 should be able to connect and send data to C# destination" );
        }

        /// <summary>
        /// Publish a LeaseSet via SAM, then perform an explicit LeaseSet lookup
        /// via IdentResolver and verify the returned LeaseSet properties:
        /// type (LS2), encryption keys, lease count, and expiration.
        /// </summary>
        [Test, Order( 5 )]
        [CancelAfter( 900_000 )]
        public async Task LeaseSetLookupAndEncryptionVerification()
        {
            Logging.LogInformation( "=== LeaseSetLookupAndEncryptionVerification ===" );
            await WaitForExploratoryTunnels();

            // Create a SAM session on i2pd 0 which will publish a LeaseSet
            int samPort = PortAllocator.Scaled.I2pd0Sam;
            using var sam = await SAMHelper.CreateAndHelloAsync( "127.0.0.1", samPort );
            var destBase64 = await sam.CreateSessionAsync(
                "LS_VERIFY", "STREAM", 2, 2, 2, 2,
                timeoutMs: 300_000 );
            Assert.IsNotNull( destBase64, "SAM session destination should not be null" );
            Logging.LogInformation(
                $"Created i2pd 0 SAM session for LS verification. Dest: {destBase64.Substring( 0, 20 )}..." );

            // Give the session time to publish its LeaseSet to floodfills
            await Task.Delay( 30000 );

            // Now do an explicit LeaseSet lookup from C# Router 0 via exploratory tunnels
            // First, decode the SAM destination to get the ident hash
            // SAM destinations are base64-encoded full Destination (keys+cert)
            // We need the SHA-256 hash of the destination to look it up
            var destBytes = I2PCore.Utils.FreenetBase64.Decode( destBase64 );
            var destHash = new I2PIdentHash(
                new I2PBufferCursor(
                    I2PHashSha256.GetHash( destBytes, 0, destBytes.Length ) ) );

            Logging.LogInformation( $"Looking up LeaseSet for {destHash.Id32Short}..." );

            // Check cache first - it might already be there from the SAM session establishment
            var cachedLs = NetDb.Inst.FindLeaseSet( destHash );
            if ( cachedLs != null && cachedLs.Expire > DateTime.UtcNow )
            {
                Logging.LogInformation( $"LeaseSet found in cache: {cachedLs.GetType().Name}" );
                VerifyLeaseSet( cachedLs, destHash );
                return;
            }

            // Perform async lookup
            var tcs = new TaskCompletionSource<ILeaseSet>();
            IdentResolver.IdentResolverResultLeaseSetEx successHandler = null;
            IdentResolver.IdentResolverResultFailEx failHandler = null;

            successHandler = ( ls, info ) =>
            {
                if ( ls?.Destination?.IdentHash == destHash )
                {
                    NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx -= successHandler;
                    NetDb.Inst.IdentHashLookup.LookupFailureEx -= failHandler;
                    tcs.TrySetResult( ls );
                }
            };

            failHandler = ( key, info ) =>
            {
                if ( key == destHash )
                {
                    NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx -= successHandler;
                    NetDb.Inst.IdentHashLookup.LookupFailureEx -= failHandler;

                    // Log the failure details
                    if ( info?.Attempts != null )
                    {
                        lock ( info.Attempts )
                        {
                            foreach ( var attempt in info.Attempts )
                            {
                                Logging.LogInformation(
                                    $"Lookup attempt: {attempt.Details ?? "no details"}" );
                            }
                        }
                    }
                    tcs.TrySetResult( null );
                }
            };

            NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx += successHandler;
            NetDb.Inst.IdentHashLookup.LookupFailureEx += failHandler;

            // Retry the lookup a few times if needed (floodfill might not have it yet)
            ILeaseSet ls = null;
            for ( int attempt = 0; attempt < 5; ++attempt )
            {
                NetDb.Inst.IdentHashLookup.LookupLeaseSet( destHash );

                using var cts = new CancellationTokenSource( 60_000 );
                try
                {
                    ls = await tcs.Task.WaitAsync( cts.Token );
                    if ( ls != null ) break;

                    // Reset for next attempt
                    tcs = new TaskCompletionSource<ILeaseSet>();
                    NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx += successHandler;
                    NetDb.Inst.IdentHashLookup.LookupFailureEx += failHandler;
                }
                catch ( OperationCanceledException )
                {
                    Logging.LogInformation( $"Lookup attempt {attempt + 1} timed out, retrying..." );
                    tcs = new TaskCompletionSource<ILeaseSet>();
                    NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx += successHandler;
                    NetDb.Inst.IdentHashLookup.LookupFailureEx += failHandler;
                }
            }

            Assert.IsNotNull( ls,
                $"LeaseSet lookup for {destHash.Id32Short} should succeed" );
            VerifyLeaseSet( ls, destHash );
        }

        private static void VerifyLeaseSet( ILeaseSet ls, I2PIdentHash expectedHash )
        {
            Assert.IsNotNull( ls.Destination, "LeaseSet should have a destination" );
            Assert.AreEqual( expectedHash, ls.Destination.IdentHash,
                "LeaseSet destination hash should match lookup target" );

            // Verify LS2 type
            Assert.IsInstanceOf<I2PLeaseSet2>( ls,
                "Modern I2P routers should publish LeaseSet2 (LS2)" );

            // Verify expiration is in the future
            Assert.Greater( ls.Expire, DateTime.UtcNow,
                "LeaseSet should not be expired" );

            // Verify leases
            var leases = ls.Leases?.ToArray();
            Assert.IsNotNull( leases, "LeaseSet should have leases" );
            Assert.GreaterOrEqual( leases.Length, 1,
                "LeaseSet should have at least 1 lease" );

            foreach ( var lease in leases )
            {
                Assert.IsNotNull( lease.TunnelGw,
                    "Lease should have a tunnel gateway" );
                Logging.LogInformation(
                    $"  Lease: gw={lease.TunnelGw.Id32Short}, id={lease.TunnelId}, expires={lease.Expire}" );
            }

            // Verify encryption public keys
            var pubKeys = ls.PublicKeys?.ToArray();
            Assert.IsNotNull( pubKeys, "LeaseSet should have public encryption keys" );
            Assert.GreaterOrEqual( pubKeys.Length, 1,
                "LeaseSet should have at least 1 encryption key" );

            foreach ( var key in pubKeys )
            {
                Logging.LogInformation(
                    $"  Encryption key: type={key.Certificate.PublicKeyType}, " +
                    $"size={key.KeySizeBytes} bytes" );
                Assert.IsNotNull( key.Key, "Encryption key data should not be null" );
                Assert.Greater( key.KeySizeBytes, 0, "Encryption key should have non-zero size" );
            }
        }

        /// <summary>
        /// Full end-to-end test: create SAM sessions with real 2-hop tunnels,
        /// verify LeaseSet is discoverable via explicit lookup, then transfer data
        /// through the tunnels and verify receipt.
        /// </summary>
        [Test, Order( 6 )]
        [CancelAfter( 900_000 )]
        public async Task SamDataTransferWithLeaseSetLookup()
        {
            Logging.LogInformation( "=== SamDataTransferWithLeaseSetLookup ===" );
            await WaitForExploratoryTunnels();

            int csSamPort = PortAllocator.Scaled.Cs0Sam;
            int i2pdSamPort = PortAllocator.Scaled.I2pd0Sam;

            // Step 1: Create receiver session on i2pd 0 with 2-hop tunnels
            using var recvCtl = await SAMHelper.CreateAndHelloAsync(
                "127.0.0.1", i2pdSamPort, timeoutMs: 30000 );
            var recvDest = await recvCtl.CreateSessionAsync(
                "SAM_E2E_RECV", "STREAM", 2, 2, 2, 2,
                timeoutMs: 300_000 );
            Assert.IsNotNull( recvDest, "Receiver destination should not be null" );
            Logging.LogInformation( $"Receiver session created on i2pd 0" );

            // Give time for LeaseSet to be published
            await Task.Delay( 30000 );

            // Step 2: Create sender session on C# 0 with 2-hop tunnels
            using var sendCtl = await SAMHelper.CreateAndHelloAsync(
                "127.0.0.1", csSamPort, timeoutMs: 30000 );
            await sendCtl.CreateSessionAsync(
                "SAM_E2E_SEND", "STREAM", 2, 2, 2, 2,
                timeoutMs: 300_000 );
            Logging.LogInformation( $"Sender session created on C# 0" );

            // Step 3: Verify the receiver's LeaseSet is discoverable
            var recvDestBytes = I2PCore.Utils.FreenetBase64.Decode( recvDest );
            var recvHash = new I2PIdentHash(
                new I2PBufferCursor(
                    I2PHashSha256.GetHash( recvDestBytes, 0, recvDestBytes.Length ) ) );

            bool lsFound = false;
            for ( int i = 0; i < 10; ++i )
            {
                var cachedLs = NetDb.Inst.FindLeaseSet( recvHash );
                if ( cachedLs != null && cachedLs.Expire > DateTime.UtcNow )
                {
                    Logging.LogInformation(
                        $"Receiver LeaseSet found: {cachedLs.GetType().Name}, " +
                        $"{cachedLs.Leases?.Count() ?? 0} leases" );
                    lsFound = true;
                    break;
                }

                // Trigger a lookup
                NetDb.Inst.IdentHashLookup.LookupLeaseSet( recvHash );
                await Task.Delay( 15000 );
            }

            Assert.IsTrue( lsFound,
                $"Receiver LeaseSet {recvHash.Id32Short} should be discoverable via NetDb" );

            // Step 4: Start ACCEPT on receiver
            using var recvData = await SAMHelper.CreateAndHelloAsync(
                "127.0.0.1", i2pdSamPort, timeoutMs: 30000 );
            var acceptTask = Task.Run( async () =>
            {
                await recvData.StreamAcceptAsync( "SAM_E2E_RECV" );
                Logging.LogInformation( "STREAM ACCEPT completed" );
            } );

            await Task.Delay( 3000 );

            // Step 5: STREAM CONNECT from sender
            using var sendData = await SAMHelper.CreateAndHelloAsync(
                "127.0.0.1", csSamPort, timeoutMs: 30000 );
            await sendData.StreamConnectAsync( "SAM_E2E_SEND", recvDest );
            Logging.LogInformation( "STREAM CONNECT completed" );

            await acceptTask;

            // Step 6: Transfer test data and verify
            var testData = SAMHelper.GenerateTestData( 64 * 1024, seed: 9999 ); // 64KB
            var expectedHash = SAMHelper.ComputeSha256( testData );

            using var cts = new CancellationTokenSource( 120_000 );
            var sendTask = Task.Run( async () =>
            {
                await sendData.SendDataAsync( testData, cts.Token );
                Logging.LogInformation( $"Sent {testData.Length} bytes" );
            }, cts.Token );

            var receivedData = await recvData.ReceiveDataAsync( testData.Length, cts.Token );
            await sendTask;

            var receivedHash = SAMHelper.ComputeSha256( receivedData );
            Assert.IsTrue( SAMHelper.HashesMatch( expectedHash, receivedHash ),
                "SHA-256 mismatch on transferred data" );

            Logging.LogInformation(
                $"SamDataTransferWithLeaseSetLookup: {testData.Length} bytes transferred and verified. PASS" );
        }
    }
}
