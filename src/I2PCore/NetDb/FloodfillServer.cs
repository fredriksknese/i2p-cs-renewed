using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TransportLayer;
using I2PCore.Utils;

namespace I2PCore
{
    /// <summary>
    /// Floodfill server mode handler. When enabled, this class responds to
    /// incoming DatabaseLookup messages by serving RouterInfo and LeaseSet
    /// entries from the local NetDb, and handles incoming DatabaseStore
    /// messages from peers.
    /// </summary>
    public class FloodfillServer : IDisposable
    {
        private bool _enabled;
        private bool _disposed;
        private bool _registered;

        public event NetDb.NetworkDatabaseDatabaseLookupReceived DatabaseLookupReceived;

        /// <summary>
        /// Gets or sets whether floodfill server mode is active.
        /// When enabled, the server registers for incoming I2NP messages
        /// and responds to database queries from peers.
        /// </summary>
        public bool Enabled
        {
            get => _enabled;
            set
            {
                if ( _enabled == value ) return;
                _enabled = value;

                if ( _enabled )
                {
                    Register();
                }
                else
                {
                    Unregister();
                }
            }
        }

        public FloodfillServer()
        {
        }

        /// <summary>
        /// Start the floodfill server and begin handling queries.
        /// </summary>
        public void Start()
        {
            Enabled = true;
            Logging.LogInformation( "FloodfillServer: Started." );
        }

        /// <summary>
        /// Stop the floodfill server.
        /// </summary>
        public void Stop()
        {
            Enabled = false;
            Logging.LogInformation( "FloodfillServer: Stopped." );
        }

        private void Register()
        {
            if ( _registered ) return;
            _registered = true;
            Router.UnhandledI2NpMessage += OnI2NpMessageReceived;
            Logging.LogDebug( "FloodfillServer: Registered for incoming I2NP messages." );
        }

        private void Unregister()
        {
            if ( !_registered ) return;
            _registered = false;
            Router.UnhandledI2NpMessage -= OnI2NpMessageReceived;
            Logging.LogDebug( "FloodfillServer: Unregistered from incoming I2NP messages." );
        }

        private void OnI2NpMessageReceived( Ii2NpHeader msg, InboundTunnel from )
        {
            if ( !_enabled ) return;

            try
            {
                var fromHash = from?.Destination;
                switch ( msg.MessageType )
                {
                    case I2NpMessage.MessageTypes.DatabaseLookup:
                        ThreadPool.QueueUserWorkItem( _ =>
                        {
                            try
                            {
                                var lookup = (DatabaseLookupMessage)msg.Message;
                                HandleDatabaseLookup( lookup, fromHash );
                            }
                            catch ( Exception ex )
                            {
                                Logging.LogDebug( $"FloodfillServer: Error handling DatabaseLookup: {ex.Message}" );
                            }
                        } );
                        break;

                    case I2NpMessage.MessageTypes.DatabaseStore:
                        ThreadPool.QueueUserWorkItem( _ =>
                        {
                            try
                            {
                                var store = (DatabaseStoreMessage)msg.Message;
                                HandleDatabaseStore( store, fromHash );
                            }
                            catch ( Exception ex )
                            {
                                Logging.LogDebug( $"FloodfillServer: Error handling DatabaseStore: {ex.Message}" );
                            }
                        } );
                        break;
                }
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"FloodfillServer: Error processing I2NP message: {ex.Message}" );
            }
        }

        /// <summary>
        /// Handle a DatabaseLookup message by looking up the requested key
        /// in the local NetDb and returning a DatabaseStoreMessage if found,
        /// or a DatabaseSearchReply with closest floodfill routers if not found.
        /// </summary>
        /// <param name="lookup">The incoming DatabaseLookup message.</param>
        /// <param name="fromHash">The ident hash of the router that sent this message, if known.</param>
        /// <returns>A DatabaseStoreMessage with the result, or null if nothing found.</returns>
        public DatabaseStoreMessage HandleDatabaseLookup( DatabaseLookupMessage lookup, I2PIdentHash fromHash = null )
        {
            if ( lookup == null ) return null;

            var key = lookup.Key;
            var lookupType = lookup.LookupType;

            Logging.LogDebug( $"FloodfillServer: DatabaseLookup for {key.Id32Short}, type={lookupType}" );

            // Check if this is a RouterInfo lookup
            var isRouterInfoLookup = ( lookupType & DatabaseLookupMessage.LookupTypes.RouterInfo ) != 0;
            var isLeaseSetLookup = ( lookupType & DatabaseLookupMessage.LookupTypes.LeaseSet ) != 0;
            var isExploration = ( lookupType & DatabaseLookupMessage.LookupTypes.Exploration ) ==
                                DatabaseLookupMessage.LookupTypes.Exploration;

            // Try RouterInfo first (unless specifically requesting LeaseSet only)
            if ( !isLeaseSetLookup || isRouterInfoLookup || isExploration )
            {
                var routerInfo = NetDb.Inst[key];
                if ( routerInfo != null )
                {
                    Logging.LogDebug( $"FloodfillServer: Found RouterInfo for {key.Id32Short}" );

                    var response = new DatabaseStoreMessage( routerInfo );
                    SendReply( lookup, response );
                    DatabaseLookupReceived?.Invoke( lookup, fromHash, NetDb.DatabaseLookupResult.RouterInfoFound );
                    return response;
                }
            }

            // Try LeaseSet (unless specifically requesting RouterInfo only)
            if ( !isRouterInfoLookup || isLeaseSetLookup )
            {
                var leaseSet = NetDb.Inst.FindLeaseSet( key );
                if ( leaseSet != null )
                {
                    Logging.LogDebug( $"FloodfillServer: Found LeaseSet for {key.Id32Short}" );

                    var response = new DatabaseStoreMessage( leaseSet );
                    SendReply( lookup, response );
                    DatabaseLookupReceived?.Invoke( lookup, fromHash, NetDb.DatabaseLookupResult.LeaseSetFound );
                    return response;
                }
            }

            // Not found: send DatabaseSearchReply with closest floodfill routers
            Logging.LogDebug( $"FloodfillServer: Key {key.Id32Short} not found, sending closest floodfills" );
            SendSearchReply( lookup );
            DatabaseLookupReceived?.Invoke( lookup, fromHash, NetDb.DatabaseLookupResult.ClosestFloodfillsSent );

            return null;
        }

        // Tracks recently flooded keys to avoid duplicate floods
        private readonly ConcurrentDictionary<I2PIdentHash, long> _recentlyFlooded = new();
        private const int FLOOD_EXPIRY_MS = 60000; // Don't re-flood same key within 60s
        private const int FLOOD_PEER_COUNT = 3; // Number of closest floodfills to propagate to

        // Rate limiting for DatabaseStore to prevent flood abuse
        private const int RATE_LIMIT_MAX_STORES = 100;
        private const int RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
        private readonly ConcurrentQueue<long> _storeTimestamps = new();
        private long _lastRateLimitCleanup;

        /// <summary>
        /// Check if the incoming store rate exceeds the limit.
        /// Returns true if the request should be rejected.
        /// </summary>
        private bool IsStoreRateLimited()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Periodically clean up old timestamps
            if ( now - _lastRateLimitCleanup > 10000 )
            {
                _lastRateLimitCleanup = now;
                var cutoff = now - RATE_LIMIT_WINDOW_MS;
                while ( _storeTimestamps.TryPeek( out var oldest ) && oldest < cutoff )
                {
                    _storeTimestamps.TryDequeue( out _ );
                }
            }

            if ( _storeTimestamps.Count >= RATE_LIMIT_MAX_STORES )
            {
                // Check if the oldest entry is still within the window
                if ( _storeTimestamps.TryPeek( out var oldest ) && now - oldest < RATE_LIMIT_WINDOW_MS )
                {
                    return true;
                }
                // Remove expired entry
                _storeTimestamps.TryDequeue( out _ );
            }

            _storeTimestamps.Enqueue( now );
            return false;
        }

        /// <summary>
        /// Handle a DatabaseStore message by storing the RouterInfo or LeaseSet
        /// in the local NetDb, then propagating (flooding) to closest floodfill peers.
        /// </summary>
        public void HandleDatabaseStore( DatabaseStoreMessage store, I2PIdentHash from )
        {
            if ( store == null ) return;

            if ( IsStoreRateLimited() )
            {
                Logging.LogWarning( $"FloodfillServer: Rate limit exceeded, dropping DatabaseStore for {store.Key?.Id32Short}" );
                return;
            }

            if ( store.RouterInfo != null )
            {
                Logging.LogDebug( $"FloodfillServer: Storing RouterInfo for {store.Key.Id32Short}" );
                NetDb.Inst.AddRouterInfo( store.RouterInfo );
            }
            else if ( store.LeaseSet != null )
            {
                Logging.LogDebug( $"FloodfillServer: Storing LeaseSet for {store.Key.Id32Short}" );
                NetDb.Inst.AddLeaseSet( store.LeaseSet );
            }
            else
            {
                Logging.LogDebug( $"FloodfillServer: DatabaseStore with no RouterInfo or LeaseSet for {store.Key.Id32Short}" );
                return;
            }

            // Send delivery status acknowledgement if requested
            if ( store.ReplyToken != 0 )
            {
                SendDeliveryStatus( store );
            }

            // Flood propagation: forward to closest floodfill routers
            FloodToClosestPeers( store, from );
        }

        /// <summary>
        /// Propagate a DatabaseStore to the closest floodfill routers.
        /// This is the core flooding mechanism for the distributed hash table.
        /// </summary>
        private void FloodToClosestPeers( DatabaseStoreMessage store, I2PIdentHash from )
        {
            if ( store?.Key == null ) return;

            // Check if we recently flooded this key
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if ( _recentlyFlooded.TryGetValue( store.Key, out var lastFloodTime ) )
            {
                if ( now - lastFloodTime < FLOOD_EXPIRY_MS )
                    return; // Already flooded recently
            }

            _recentlyFlooded[store.Key] = now;

            // Clean up old entries periodically
            if ( _recentlyFlooded.Count > 1000 )
            {
                var expired = _recentlyFlooded
                    .Where( kv => now - kv.Value > FLOOD_EXPIRY_MS )
                    .Select( kv => kv.Key )
                    .ToList();
                foreach ( var k in expired )
                    _recentlyFlooded.TryRemove( k, out _ );
            }

            // Get closest floodfill routers to the stored key
            var myHash = RouterContext.Inst.MyRouterIdentity.IdentHash;
            var closestFf = NetDb.Inst.GetClosestFloodfill( store.Key, FLOOD_PEER_COUNT + 1, null );

            if ( closestFf == null ) return;

            int sent = 0;
            foreach ( var peer in closestFf )
            {
                // Don't flood to ourselves
                if ( peer.Equals( myHash ) ) continue;

                // Don't flood back to the sender
                if ( from != null && peer.Equals( from ) ) continue;

                // Don't flood back to the reply gateway (from spec)
                if ( store.ReplyGateway != null && peer.Equals( store.ReplyGateway ) ) continue;

                if ( sent >= FLOOD_PEER_COUNT ) break;

                try
                {
                    TransportProvider.Send( peer, store );
                    sent++;
                    Logging.LogDebug( $"FloodfillServer: Flooded {store.Key.Id32Short} to {peer.Id32Short}" );
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug( $"FloodfillServer: Failed to flood to {peer.Id32Short}: {ex.Message}" );
                }
            }

            if ( sent > 0 )
                Logging.LogDebug( $"FloodfillServer: Flooded {store.Key.Id32Short} to {sent} peers" );
        }

        private void SendReply( DatabaseLookupMessage lookup, DatabaseStoreMessage response )
        {
            var isTunnel = ( lookup.LookupType & DatabaseLookupMessage.LookupTypes.Tunnel ) != 0;

            if ( isTunnel && lookup.TunnelId != null )
            {
                // Prefer sending via our own outbound tunnel
                var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(
                    TunnelPoolSelection.RequireExploratory );

                if ( outtunnel != null )
                {
                    outtunnel.Send( new TunnelMessageRouter(
                        new TunnelGatewayMessage( response, lookup.TunnelId ),
                        lookup.From ) );
                }
                else
                {
                    // No outbound tunnel available — send TunnelGateway directly via transport.
                    // The remote will inject our message into their inbound tunnel.
                    Logging.LogDebug( $"FloodfillServer: No outbound tunnel, sending reply directly to {lookup.From?.Id32Short}" );
                    TransportProvider.Send( lookup.From,
                        new TunnelGatewayMessage( response, lookup.TunnelId ) );
                }
            }
            else
            {
                // Reply directly to the requesting router
                TransportProvider.Send( lookup.From, response );
            }
        }

        private void SendSearchReply( DatabaseLookupMessage lookup )
        {
            var closestFf = NetDb.Inst.GetClosestFloodfill( lookup.Key, 3, null );

            if ( closestFf == null || !closestFf.Any() )
            {
                closestFf = NetDb.Inst.GetRandomFloodfillRouter( true, 3 );
            }

            if ( closestFf == null || !closestFf.Any() )
            {
                Logging.LogDebug( "FloodfillServer: No floodfill routers to include in search reply" );
                return;
            }

            var peers = closestFf.ToArray();
            var from = RouterContext.Inst.MyRouterIdentity.IdentHash;

            // Use the proper constructor so SetBuffer is initialized correctly.
            // Constructing from raw BufRef breaks CreateHeader16 when wrapping in TunnelGatewayMessage.
            var reply = new DatabaseSearchReplyMessage( lookup.Key, peers, from );

            var isTunnel = ( lookup.LookupType & DatabaseLookupMessage.LookupTypes.Tunnel ) != 0;

            if ( isTunnel && lookup.TunnelId != null )
            {
                var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(
                    TunnelPoolSelection.RequireExploratory );

                if ( outtunnel != null )
                {
                    outtunnel.Send( new TunnelMessageRouter(
                        new TunnelGatewayMessage( reply, lookup.TunnelId ),
                        lookup.From ) );
                }
                else
                {
                    // No outbound tunnel — send TunnelGateway directly via transport
                    Logging.LogDebug( $"FloodfillServer: No outbound tunnel, sending search reply directly to {lookup.From?.Id32Short}" );
                    TransportProvider.Send( lookup.From,
                        new TunnelGatewayMessage( reply, lookup.TunnelId ) );
                }
            }
            else
            {
                TransportProvider.Send( lookup.From, reply );
            }
        }

        private void SendDeliveryStatus( DatabaseStoreMessage store )
        {
            var deliveryStatus = new DeliveryStatusMessage( store.ReplyToken );

            if ( store.ReplyTunnelId != 0 && store.ReplyGateway != null )
            {
                // Prefer sending via our own outbound tunnel
                var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(
                    TunnelPoolSelection.RequireExploratory );

                if ( outtunnel != null )
                {
                    outtunnel.Send( new TunnelMessageRouter(
                        new TunnelGatewayMessage(
                            deliveryStatus,
                            new I2PTunnelId( store.ReplyTunnelId ) ),
                        store.ReplyGateway ) );
                }
                else
                {
                    // No outbound tunnel — send TunnelGateway directly to the reply gateway.
                    // The gateway router will inject the DeliveryStatus into the specified tunnel.
                    Logging.LogDebug( $"FloodfillServer: No outbound tunnel, sending DeliveryStatus directly to {store.ReplyGateway?.Id32Short}" );
                    TransportProvider.Send( store.ReplyGateway,
                        new TunnelGatewayMessage(
                            deliveryStatus,
                            new I2PTunnelId( store.ReplyTunnelId ) ) );
                }
            }
            else if ( store.ReplyGateway != null )
            {
                TransportProvider.Send( store.ReplyGateway, deliveryStatus );
            }
        }

        public void Dispose()
        {
            if ( _disposed ) return;
            _disposed = true;
            Stop();
        }
    }
}
