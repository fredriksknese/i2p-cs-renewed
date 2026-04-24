using System.Threading;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using System;

namespace I2PCore.TunnelLayer
{
    public abstract class Tunnel
    {
        /// <summary>
        /// Inbound gateway for inbound tunnels. Outbound next hop for outbound tunnels.
        /// </summary>
        public abstract I2PIdentHash Destination { get; }

        /// <summary>
        /// The hop furthest from us.
        /// Inbound: Remote gateway.
        /// Outbound: Endpoint.
        /// </summary>
        public abstract I2PIdentHash FarEnd { get; }

        public abstract TickSpan TunnelEstablishmentTimeout { get; }

        // "each hop expires the tunnel after 10 minutes" https://geti2p.net/spec/tunnel-creation
        public static readonly TickSpan TunnelLifetime = TickSpan.Minutes( 10 );
        public static readonly TickSpan TunnelRecreationMargin = TickSpan.Minutes( 5 );
        public static TickSpan TunnelRecreationMarginPerHop
        {
            get
            {
                return ExpectedTunnelBuildTimePerHop * 1.5;
            }
        }

        // Time per hop for "ok" routers
        // Avg     1223 ms
        // StdDev  1972 ms
        public static TickSpan ExpectedTunnelBuildTimePerHop
        {
            get
            {
                return RouterContext.Inst.IsFirewalled 
                    ? TickSpan.Seconds( 15 )
                    : TickSpan.Seconds( 10 );
            }
        }

        public virtual TickSpan Lifetime { get { return TunnelLifetime; } }

        public virtual bool Active
        {
            get
            {
                var result = !Terminated 
                    && Established
                    && CreationTime.DeltaToNow < ( Lifetime - TunnelRecreationMargin );
                return result;
            }
        }

        public virtual bool Established { get; set; }

        public virtual bool NeedsRecreation
        {
            get
            {
                var panic = Config.Pool == TunnelConfig.TunnelPool.Client
                    && !TunnelProvider.Inst.ClientTunnelsStatusOk;

                return CreationTime.DeltaToNow > (
                    Lifetime
                        - ( panic
                            ? TunnelRecreationMargin * 1.5
                            : TunnelRecreationMargin )
                        - TunnelRecreationMarginPerHop * TunnelMemberHops );
            }
        }

        public virtual bool Expired 
        { 
            get 
            {
                return EstablishedTime.DeltaToNow > Lifetime * 1.1 || 
                    CreationTime.DeltaToNow > Lifetime * 1.2; 
            } 
        }

        public TunnelConfig.TunnelPool Pool { get { return Config.Pool; } }
        public TunnelConfig.TunnelDirection TunnelDirection { get { return Config.Direction; } }

        // Statistics
        public readonly TunnelQuality Metrics = new();

        // Info
        public TunnelConfig Config { get; private set; }
        public abstract IEnumerable<I2PRouterIdentity> TunnelMembers { get; }

        public readonly TickCounter CreationTime = TickCounter.Now;
        public TickCounter EstablishedTime = TickCounter.Now;

        public I2PTunnelId ReceiveTunnelId;

        public readonly int TunnelSeqNr;
        public readonly string TunnelDebugTrace;

        public static readonly BandwidthStatistics BandwidthTotal = new();
        public readonly BandwidthStatistics Bandwidth = new( BandwidthTotal );

        private int _messageCount;
        public int MessageCount => _messageCount;

        internal int AggregateErrors = 0;
        internal ITunnelOwner Owner { get; private set; }

        protected Tunnel( ITunnelOwner owner, TunnelConfig config )
        {
            Owner = owner;
            Config = config;
            TunnelMemberHops = config == null ? 1 : config.Info.Hops.Count;
            TunnelSeqNr = Interlocked.Increment( ref _tunnelIdCounter );

            var pool = config?.Pool.ToString() ?? "?";
            var dir = config?.Direction.ToString() == "Inbound" ? "In" : "Out";
            TunnelDebugTrace = $"{pool} {dir} <{TunnelSeqNr}>";

            if ( TunnelSeqNr > int.MaxValue - 100 ) _tunnelIdCounter = 1;
        }

        public bool Terminated { get; private set; }

        public event Action<Tunnel> TunnelShutdown;

        public virtual void Shutdown()
        {
            Terminated = true;
            TunnelShutdown?.Invoke( this );
        }

        public virtual void MessageReceived( I2NpMessage msg, int recvdatasize )
        {
#if LOG_ALL_TUNNEL_TRANSFER
            Logging.LogDebug( $"{this}: MessageReceived {msg}" );
#endif
            Bandwidth.DataReceived( recvdatasize );
            Interlocked.Increment( ref _messageCount );

            //Logging.LogDebug( $"{this}: MessageReceived {msg.MessageType} TDM len {recvsize}" );
            ReceiveQueue.Enqueue( msg );
        }

        private static int _tunnelIdCounter = 1;

        protected int TunnelMemberHops;

        protected ConcurrentQueue<I2NpMessage> ReceiveQueue = new();

        /// <summary>
        /// True: Tunnel is working. False: Tunnel has failed.
        /// </summary>
        /// <returns></returns>
        public abstract bool Exectue();

        internal static TunnelInfo CreateOutboundTunnelChain( int hops, bool exploratory, bool bootstrapping = false )
        {
            var hopinfo = new List<HopInfo>();
            var excludeSet = new HashSet<I2PIdentHash> { RouterContext.Inst.MyRouterIdentity.IdentHash };

            // For firewalled routers, the outbound endpoint (last hop) must send
            // the build reply back to us. Since we're firewalled, it can only reach
            // us if it already has an active connection. Java I2P (ExploratoryPeerSelector)
            // handles this by selecting the OBEP from actively-connected peers.
            var connectedRouters = TransportProvider.Inst.GetConnectedRouterHashes().ToHashSet();

            if ( connectedRouters.Count > 0 && hops >= 1 && ( exploratory || RouterContext.Inst.IsFirewalled || connectedRouters.Count < 15 ) )
            {
                var connectedList = connectedRouters
                    .Select( h => NetDb.Inst[h] )
                    .Where( ri => ri?.Identity != null )
                    .ToArray();

                if ( connectedList.Length > 0 )
                {
                    // Pick a connected router for the first hop (OBGW)
                    var gatewayRi = connectedList[BufUtils.RandomInt( connectedList.Length )];
                    hopinfo.Add( new HopInfo( gatewayRi.Identity, new I2PTunnelId() ) );

                    // Get random hops for the rest. Adjust if not enough routers.
                    var remainingHops = Math.Min( hops - 1, connectedList.Length - 1 );
                    excludeSet.Add( gatewayRi.Identity.IdentHash );

                    // For exploratory, we don't want to use too many connected peers
                    // to ensure we're actually exploring the network.
                    // Only use the gateway to ensure the message gets out.
                    if ( exploratory && remainingHops > 0 )
                    {
                        var pool = bootstrapping ? connectedList : null;
                        var hopsToSort = new List<HopInfo>();
                        
                        for ( int i = 0; i < remainingHops; ++i )
                        {
                            I2PRouterInfo ri = null;
                            // Only force the last hop (endpoint) to be connected if we have very few tunnels,
                            // are bootstrapping, or are firewalled. Otherwise, only the first hop (gateway) is forced.
                            bool forceConnected = ( i == remainingHops - 1 ) && 
                                                 ( bootstrapping || RouterContext.Inst.IsFirewalled || connectedRouters.Count < 10 );

                            if ( forceConnected && pool != null )
                            {
                                var choices = pool.Where( p => !excludeSet.Contains( p.Identity.IdentHash ) ).ToArray();
                                if ( choices.Length > 0 ) ri = choices[BufUtils.RandomInt( choices.Length )];
                            }

                            if ( ri == null )
                            {
                                var hash = NetDb.Inst.GetRandomRouterForTunnelBuild( true, excludeSet );
                                if ( hash != null ) ri = NetDb.Inst[hash];
                            }

                            if ( ri?.Identity != null )
                            {
                                hopsToSort.Add( new HopInfo( ri.Identity, new I2PTunnelId() ) );
                                excludeSet.Add( ri.Identity.IdentHash );
                            }
                        }

                        // Java-like XOR locality for exploratory tunnels: sort peers by XOR distance from a stable key
                        var key = RouterContext.Inst.ExploratoryKey;
                        hopinfo.AddRange( hopsToSort.OrderBy( h => h.Peer.IdentHash ^ key ) );
                    }
                    else if ( !exploratory && remainingHops >= 1 )
                    {
                        // For non-exploratory, we also prefer a connected router for the endpoint
                        // to ensure the build reply can reach us.
                        var middleHopsCount = remainingHops - 1;
                        if ( middleHopsCount > 0 )
                        {
                            foreach ( var hop in NetDb.Inst.GetRandomRoutersForTunnelBuild( false, middleHopsCount, excludeSet ) )
                            {
                                var ri = NetDb.Inst[hop];
                                if ( ri?.Identity == null || excludeSet.Contains( ri.Identity.IdentHash ) ) continue;
                                hopinfo.Add( new HopInfo( ri.Identity, new I2PTunnelId() ) );
                                excludeSet.Add( ri.Identity.IdentHash );
                            }
                        }

                        var endpointChoices = connectedList
                            .Where( ri => !excludeSet.Contains( ri.Identity.IdentHash ) )
                            .ToArray();
                        
                        var endpointRi = ( endpointChoices.Length > 0 ) 
                            ? endpointChoices[BufUtils.RandomInt( endpointChoices.Length )]
                            : NetDb.Inst[NetDb.Inst.GetRandomRouterForTunnelBuild( false, excludeSet )];

                        if ( endpointRi != null )
                        {
                            hopinfo.Add( new HopInfo( endpointRi.Identity, new I2PTunnelId() ) );
                        }
                    }
                    else if ( remainingHops > 0 )
                    {
                        // For exploratory, we just pick random routers for the rest
                        foreach ( var hop in NetDb.Inst.GetRandomRoutersForTunnelBuild( true, remainingHops, excludeSet ) )
                        {
                            var ri = NetDb.Inst[hop];
                            if ( ri?.Identity == null || excludeSet.Contains( ri.Identity.IdentHash ) ) continue;
                            hopinfo.Add( new HopInfo( ri.Identity, new I2PTunnelId() ) );
                            excludeSet.Add( ri.Identity.IdentHash );
                        }
                    }

                    return new TunnelInfo( hopinfo );
                }
            }

            // Default: random selection for all hops
            excludeSet.Clear();
            excludeSet.Add( RouterContext.Inst.MyRouterIdentity.IdentHash );
            foreach( var hop in NetDb.Inst.GetRandomRoutersForTunnelBuild( exploratory, hops, excludeSet ) )
            {
                var ri = NetDb.Inst[hop];
                if ( ri?.Identity == null || excludeSet.Contains( ri.Identity.IdentHash ) ) continue;
                hopinfo.Add( new HopInfo( ri.Identity, new I2PTunnelId() ) );
                excludeSet.Add( ri.Identity.IdentHash );
            }

            if ( hopinfo.Count == 0 ) return null;

            return new TunnelInfo( hopinfo );
        }

        internal static TunnelInfo CreateInboundTunnelChain( int hops, bool exploratory, bool bootstrapping = false )
        {
            var hopinfo = new List<HopInfo>();
            var excludeSet = new HashSet<I2PIdentHash> { RouterContext.Inst.MyRouterIdentity.IdentHash };

            // For the endpoint hop (last external hop, sends build reply to us),
            // prefer routers we already have active transport sessions with.
            // This is critical for firewalled routers where remote routers can't
            // initiate new connections to us.
            var connectedRouters = TransportProvider.Inst.GetConnectedRouterHashes().ToHashSet();

            if ( connectedRouters.Count > 0 && hops >= 1 && ( exploratory || RouterContext.Inst.IsFirewalled || connectedRouters.Count < 15 ) )
            {
                // Pick a connected router for the endpoint (last hop closest to us)
                var connectedList = connectedRouters
                    .Select( h => NetDb.Inst[h] )
                    .Where( ri => ri?.Identity != null )
                    .ToArray();

                if ( connectedList.Length > 0 )
                {
                    var endpointRi = connectedList[BufUtils.RandomInt( connectedList.Length )];

                    // Get remaining hops from random selection (if any). Adjust if not enough routers.
                    var remainingHops = Math.Min( hops - 1, connectedList.Length - 1 );
                    excludeSet.Add( endpointRi.Identity.IdentHash );

                    // For exploratory, we already picked a connected endpoint.
                    // If bootstrapping, also prefer connected for the rest (especially gateway).
                    if ( exploratory && remainingHops > 0 )
                    {
                        var hopsToSort = new List<HopInfo>();
                        for ( int i = 0; i < remainingHops; ++i )
                        {
                            I2PRouterInfo ri = null;
                            // For inbound, we already have the endpoint (hop before us) which is connected.
                            // The rest (gateway and middle hops) should be random to ensure exploration.
                            // Only force connected if we have extremely few connections.
                            bool forceConnected = bootstrapping && connectedRouters.Count < 5;

                            if ( forceConnected )
                            {
                                var choices = connectedList.Where( p => !excludeSet.Contains( p.Identity.IdentHash ) ).ToArray();
                                if ( choices.Length > 0 ) ri = choices[BufUtils.RandomInt( choices.Length )];
                            }

                            if ( ri == null )
                            {
                                var hash = NetDb.Inst.GetRandomRouterForTunnelBuild( true, excludeSet );
                                if ( hash != null ) ri = NetDb.Inst[hash];
                            }

                            if ( ri?.Identity != null )
                            {
                                hopsToSort.Add( new HopInfo( ri.Identity, new I2PTunnelId() ) );
                                excludeSet.Add( ri.Identity.IdentHash );
                            }
                        }

                        // Java-like XOR locality for exploratory tunnels: sort peers by XOR distance from a stable key
                        var key = RouterContext.Inst.ExploratoryKey;
                        hopinfo.AddRange( hopsToSort.OrderBy( h => h.Peer.IdentHash ^ key ) );
                    }
                    else if ( remainingHops > 0 )
                    {
                        foreach ( var hop in NetDb.Inst.GetRandomRoutersForTunnelBuild( exploratory, remainingHops, excludeSet ) )
                        {
                            var ri = NetDb.Inst[hop];
                            if ( ri?.Identity == null || excludeSet.Contains( ri.Identity.IdentHash ) ) continue;
                            hopinfo.Add( new HopInfo( ri.Identity, new I2PTunnelId() ) );
                            excludeSet.Add( ri.Identity.IdentHash );
                        }
                    }

                    // Add the connected router as the endpoint (last external hop)
                    // only if it's not already the gateway (e.g. 1-hop tunnel)
                    if ( hopinfo.Count == 0 || hopinfo.Last().Peer.IdentHash != endpointRi.Identity.IdentHash )
                    {
                        hopinfo.Add( new HopInfo( endpointRi.Identity, new I2PTunnelId() ) );
                    }
                    hopinfo.Add( new HopInfo( RouterContext.Inst.MyRouterIdentity, new I2PTunnelId() ) );

                    // Java's ExploratoryPeerSelector returns endpoint first, gateway last.
                    // C# TunnelInfo expects Gateway first, endpoint/us last. 
                    // Our construction [middle..., connected_endpoint, us] matches this.
                    return new TunnelInfo( hopinfo );
                }
            }

            // Fallback: use random routers
            excludeSet.Clear();
            excludeSet.Add( RouterContext.Inst.MyRouterIdentity.IdentHash );

            foreach( var hop in NetDb.Inst.GetRandomRoutersForTunnelBuild( exploratory, hops, excludeSet ) )
            {
                var ri = NetDb.Inst[hop];
                if ( ri?.Identity == null || excludeSet.Contains( ri.Identity.IdentHash ) ) continue;
                hopinfo.Add( new HopInfo( ri.Identity, new I2PTunnelId() ) );
                excludeSet.Add( ri.Identity.IdentHash );
            }

            if ( hopinfo.Count == 0 ) return null;

            hopinfo.Add( new HopInfo( RouterContext.Inst.MyRouterIdentity, new I2PTunnelId() ) );

            return new TunnelInfo( hopinfo );
        }

        public override string ToString()
        {
            var pool = Config?.Pool.ToString() ?? "<?>";
            return $"{this.GetType().Name} {pool} {TunnelDebugTrace} {CreationTime.DeltaToNow:MS}";
        }
    }
}
