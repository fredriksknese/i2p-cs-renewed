using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using System.Collections.Concurrent;

namespace I2PCore.TunnelLayer
{
    public class ClientTunnelProvider: ITunnelOwner
    {
        // Java I2P builds exactly the number needed, no multiplier
        public static double NewTunnelCreationFactor = 2;

        private List<IClient> Clients = new();

        private ConcurrentDictionary<Tunnel, IClient> PendingTunnels = new();

        private ConcurrentDictionary<Tunnel, IClient> Destinations = new();

        public int ClientTunnelCount { get => Destinations.Count; }

        internal TunnelProvider TunnelMgr;
        public SuccessRatio ClientTunnelBuildSuccessRatio = new();

        internal ClientTunnelProvider( TunnelProvider tp )
        {
            TunnelMgr = tp;
        }

        internal void AttachClient( IClient client )
        {
            lock ( Clients )
            {
                Clients.Add( client );
            }
        }

        internal void DetachClient( IClient client )
        {
            lock ( Clients )
            {
                Clients.Remove( client );
            }
        }

        private OutboundTunnel CreateOutboundTunnel( IClient client, TunnelInfo prototype )
        {
            var config = new TunnelConfig(
                TunnelConfig.TunnelDirection.Outbound,
                TunnelConfig.TunnelPool.Client,
                prototype ?? Tunnel.CreateOutboundTunnelChain( client.OutboundTunnelHopCount, false ) );

            var tunnel = (OutboundTunnel)TunnelMgr.CreateTunnel( this, config );
            if ( tunnel != null )
            {
                TunnelMgr.AddTunnel( tunnel );
                client.AddOutboundPending( tunnel );
                PendingTunnels[tunnel] = client;
            }
            return tunnel;
        }

        private InboundTunnel CreateInboundTunnel( IClient client, TunnelInfo prototype )
        {
            var config = new TunnelConfig(
                TunnelConfig.TunnelDirection.Inbound,
                TunnelConfig.TunnelPool.Client,
                prototype ?? Tunnel.CreateInboundTunnelChain( client.InboundTunnelHopCount, false ) );

            var tunnel = (InboundTunnel)TunnelMgr.CreateTunnel( this, config );
            if ( tunnel != null )
            {
                TunnelMgr.AddTunnel( tunnel );
                client.AddInboundPending( tunnel );
                PendingTunnels[tunnel] = client;
            }
            return tunnel;
        }

        private PeriodicAction TunnelBuild = new( TickSpan.Seconds( 1 ) );
        private PeriodicAction DestinationExecute = new( TickSpan.Seconds( 1 ) );
        private PeriodicAction ReplaceTunnels = new( TickSpan.Seconds( 5 ) );
        private PeriodicAction LogStatus = new( TickSpan.Seconds( 20 ) );

        public void Execute()
        {
            TunnelBuild.Do( () => 
            {
                try
                {
                    BuildNewTunnels();
                }
                catch ( Exception ex )
                {
                    Logging.Log( "ClientTunnelProvider Execute BuildNewTunnels", ex );
                }
            });

            DestinationExecute.Do( () =>
            {
                var dests = Destinations.Select( d => d.Value ).ToArray();

                foreach ( var onedest in dests )
                {
                    try
                    {
                        onedest.Execute();
                    }
                    catch ( Exception ex )
                    {
                        Logging.Log( "ClientTunnelProvider Execute DestExecute", ex );
                    }
                }

                LogStatus.Do( LogStatusReport );
            } );
        }

        private void LogStatusReport()
        {
            var dti = Destinations.Where( t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Inbound );
            var pti = PendingTunnels.Where( t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Inbound );
            var dto = Destinations.Where( t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Outbound );
            var pto = PendingTunnels.Where( t => t.Key.Config.Direction == TunnelConfig.TunnelDirection.Outbound );

            var ei = dti.Count();
            var pi = pti.Count();
            var eo = dto.Count();
            var po = pto.Count();

            var post = "";
            var pist = "";

#if LOG_ALL_TUNNEL_TRANSFER
            pist = string.Join( ", ", pti.Select( t => t.Key.TunnelDebugTrace ) );
            post = string.Join( ", ", pto.Select( t => t.Key.TunnelDebugTrace ) );
#endif

            Logging.LogInformation(
                $"Established client tunnels in : {ei,2} ( {pi,2} {pist}), out: {eo,2} ( {po,2} {post}) {ClientTunnelBuildSuccessRatio}" );
        }

        private class TunnelsNeededInfo
        {
            internal IClient Client;
            internal int TunnelsNeeded;
        }

        private void BuildNewTunnels()
        {
            TunnelsNeededInfo[] tocreateinbound;
            TunnelsNeededInfo[] tocreateoutbound;

            lock ( Clients )
            {
                tocreateinbound = Clients.Where( c => c.InboundTunnelsNeeded > 0 ).
                    Select( c => new TunnelsNeededInfo() { Client = c, TunnelsNeeded = c.InboundTunnelsNeeded } ).ToArray();

                tocreateoutbound = Clients.Where( c => c.OutboundTunnelsNeeded > 0 ).
                    Select( c => new TunnelsNeededInfo() { Client = c, TunnelsNeeded = c.OutboundTunnelsNeeded } ).ToArray();

            }

            foreach ( var create in tocreateinbound )
            {
                var needed = create.TunnelsNeeded * NewTunnelCreationFactor;
                for ( int i = 0; i < needed; ++i )
                {
                    Logging.LogInformation( $"{this} building new inbound tunnel {i + 1}/{needed}" );

                    var t = CreateInboundTunnel( create.Client, null );
                    if ( t == null )
                    {
                        // No outbound tunnels available
                        TunnelBuild.TimeToAction = TickSpan.Seconds( 10 );
                        break;
                    }
                }
            }

            foreach ( var create in tocreateoutbound )
            {
                var needed = create.TunnelsNeeded * NewTunnelCreationFactor;
                for ( int i = 0; i < create.TunnelsNeeded * NewTunnelCreationFactor; ++i )
                {
                    Logging.LogInformation( $"{this} building new outbound tunnel {i + 1}/{needed}" );
                    CreateOutboundTunnel( create.Client, null );
                }
            }

            TunnelMgr.ClientTunnelsStatusOk = Clients.All( ct => ct.ClientTunnelsStatusOk );
        }

        #region TunnelEvents
        public void TunnelEstablished( Tunnel tunnel )
        {
            ClientTunnelBuildSuccessRatio.Success();

            if ( !PendingTunnels.TryRemove( tunnel, out var client ) )
            {
                Logging.LogDebug( $"ClientTunnelProvider: WARNING. Unable to find client for established tunnel {tunnel}" );
                return;
            }
            Destinations[tunnel] = client;

            try
            {
                client.TunnelEstablished( tunnel );
            }
            catch ( Exception ex )
            {
                Logging.Log( ex );
            }
        }

        public void TunnelBuildFailed( Tunnel tunnel, bool timeout )
        {
            ClientTunnelBuildSuccessRatio.Failure();

            if ( !PendingTunnels.TryRemove( tunnel, out var client ) )
            {
                Logging.LogDebug( $"ClientTunnelProvider: WARNING. Unable to find client TunnelBuildTimeout! {tunnel}" );
                return;
            }

            try
            {
                client.RemoveTunnel( tunnel, RemovalReason.BuildFailed );
            }
            catch ( Exception ex )
            {
                Logging.Log( ex );
            }
        }

        public void TunnelFailed( Tunnel tunnel )
        {
            if ( !Destinations.TryRemove( tunnel, out var client ) )
            {
                Logging.LogDebug( $"ClientTunnelProvider: WARNING. Unable to find client for TunnelFailed {tunnel}" );
                return;
            }

            client.RemoveTunnel( tunnel, RemovalReason.Failed );
        }

        public void TunnelExpired( Tunnel tunnel )
        {
            if ( !Destinations.TryRemove( tunnel, out var client ) )
            {
                Logging.LogDebug( $"ClientTunnelProvider: WARNING. Unable to find client for TunnelExpired {tunnel}" );
                return;
            }

            client.RemoveTunnel( tunnel, RemovalReason.Expired );
        }

        #endregion

        public override string ToString()
        {
            return GetType().Name;
        }
    }
}
