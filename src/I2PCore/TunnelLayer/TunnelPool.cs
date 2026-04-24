using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.SessionLayer;

namespace I2PCore.TunnelLayer
{
    public class TunnelPool : ITunnelOwner
    {
        public TunnelPoolSettings Settings { get; private set; }
        private readonly ConcurrentDictionary<Tunnel, bool> Tunnels = new();
        private readonly TunnelProvider TunnelMgr;

        public SuccessRatio BuildSuccessRatio = new();

        public TunnelPool( TunnelProvider tp, TunnelPoolSettings settings )
        {
            TunnelMgr = tp;
            Settings = settings;
        }

        public int EstablishedCount => Tunnels.Count( t => t.Value && !t.Key.NeedsRecreation );
        public int InProgressCount => Tunnels.Count( t => !t.Value );

        public int CountHowManyToBuild()
        {
            var establishedCount = EstablishedCount;
            var realEstablishedCount = Tunnels.Count( t => t.Value && !t.Key.NeedsRecreation && !( t.Key is ZeroHopTunnel || t.Key is ZeroHopOutboundTunnel ) );
            var connectedCount = TransportProvider.Inst.ConnectedRoutersCount;
            
            // Java-like logic: if we have very few tunnels or connections, be more aggressive
            var target = ( establishedCount < Settings.Quantity || connectedCount < 5 ) 
                ? Math.Max( 10, Settings.Quantity * 2 ) 
                : Settings.Quantity;
            
            var inProgress = InProgressCount;

            // If we have absolutely no real tunnels, be even more aggressive and ignore some in-progress
            // to avoid getting stuck during long timeouts.
            if ( realEstablishedCount == 0 && connectedCount > 0 )
            {
                target = Math.Max( target, 30 );
            }

            var needed = target - establishedCount - inProgress;
            return Math.Max( 0, needed );
        }

        public void CreateTunnels( int count )
        {
            for ( int i = 0; i < count; ++i )
            {
                var tunnel = CreateTunnel();
                if ( tunnel == null )
                {
                    Logging.LogDebug( $"TunnelPool: CreateTunnel failed for {this}. No routers available?" );
                    break;
                }
            }
        }

        public void CreateFallbackTunnel()
        {
            var config = new TunnelConfig(
                Settings.IsInbound ? TunnelConfig.TunnelDirection.Inbound : TunnelConfig.TunnelDirection.Outbound,
                Settings.IsExploratory ? TunnelConfig.TunnelPool.Exploratory : TunnelConfig.TunnelPool.Client,
                new TunnelInfo( new List<HopInfo>() ) );

            Tunnel tunnel;
            if ( Settings.IsInbound )
            {
                tunnel = new ZeroHopTunnel( this, config, RouterContext.Inst.MyRouterIdentity.IdentHash );
            }
            else
            {
                tunnel = new ZeroHopOutboundTunnel( this, config );
            }

            Tunnels[tunnel] = true;
            if ( tunnel is OutboundTunnel ot ) TunnelMgr.AddTunnel( ot );
            else if ( tunnel is InboundTunnel it ) TunnelMgr.AddTunnel( it );
            Logging.LogInformation( $"TunnelPool: Fallback 0-hop tunnel established: {tunnel} for {this}" );
        }

        private Tunnel CreateTunnel()
        {
            TunnelInfo chain;
            var realEstablished = Tunnels.Count( t => t.Value && !t.Key.NeedsRecreation && !( t.Key is ZeroHopTunnel || t.Key is ZeroHopOutboundTunnel ) );
            var bootstrapping = realEstablished == 0;
            if ( Settings.IsInbound )
            {
                chain = Tunnel.CreateInboundTunnelChain( Settings.Length, Settings.IsExploratory, bootstrapping );
            }
            else
            {
                chain = Tunnel.CreateOutboundTunnelChain( Settings.Length, Settings.IsExploratory, bootstrapping );
            }

            if ( chain == null ) return null;

            var config = new TunnelConfig(
                Settings.IsInbound ? TunnelConfig.TunnelDirection.Inbound : TunnelConfig.TunnelDirection.Outbound,
                Settings.IsExploratory ? TunnelConfig.TunnelPool.Exploratory : TunnelConfig.TunnelPool.Client,
                chain );

            var tunnel = TunnelMgr.CreateTunnel( this, config );
            if ( tunnel != null )
            {
                Tunnels[tunnel] = false;
                if ( tunnel is OutboundTunnel ot ) TunnelMgr.AddTunnel( ot );
                else if ( tunnel is InboundTunnel it ) TunnelMgr.AddTunnel( it );
            }
            return tunnel;
        }

        public T SelectTunnel<T>() where T : Tunnel
        {
            var tunnels = Tunnels.Where( t => t.Value && !t.Key.NeedsRecreation ).Select( t => (T)t.Key );
            return TunnelProvider.SelectTunnel( tunnels );
        }

        public T SelectTunnel<T>( I2PIdentHash closestTo ) where T : Tunnel
        {
            var tunnels = Tunnels.Where( t => t.Value && !t.Key.NeedsRecreation ).Select( t => (T)t.Key );
            return TunnelProvider.SelectTunnel( tunnels, closestTo );
        }

        #region ITunnelOwner
        public void TunnelEstablished( Tunnel tunnel )
        {
            BuildSuccessRatio.Success();
            Tunnels[tunnel] = true;
            Logging.LogInformation( $"TunnelPool: Tunnel established: {tunnel.TunnelDebugTrace} for {this}" );
        }

        public void TunnelBuildFailed( Tunnel tunnel, bool timeout )
        {
            BuildSuccessRatio.Failure();
            Tunnels.TryRemove( tunnel, out _ );
            Logging.LogDebug( $"TunnelPool: Tunnel build failed: {tunnel.TunnelDebugTrace} for {this}" );
        }

        public void TunnelExpired( Tunnel tunnel )
        {
            Tunnels.TryRemove( tunnel, out _ );
            Logging.LogDebug( $"TunnelPool: Tunnel expired: {tunnel.TunnelDebugTrace} for {this}" );
        }

        public void TunnelFailed( Tunnel tunnel )
        {
            Tunnels.TryRemove( tunnel, out _ );
            Logging.LogDebug( $"TunnelPool: Tunnel failed: {tunnel.TunnelDebugTrace} for {this}" );
        }
        #endregion

        public override string ToString()
        {
            return $"TunnelPool {(Settings.IsInbound ? "Inbound" : "Outbound")} {(Settings.IsExploratory ? "Exploratory" : "Client")}";
        }
    }
}
