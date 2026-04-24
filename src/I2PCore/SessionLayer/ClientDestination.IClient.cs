using System;
using System.Linq;
using I2PCore.TunnelLayer;
using I2PCore.Utils;

namespace I2PCore.SessionLayer
{
    public partial class ClientDestination : IClient
    {
        bool IClient.ClientTunnelsStatusOk
        {
            get
            {
                return InboundEstablishedPool.Count >= TargetInboundTunnelCount
                    && OutboundEstablishedPool.Count >= TargetOutboundTunnelCount;
            }
        }

        int IClient.InboundTunnelsNeeded
        {
            get
            {
                var stable = InboundEstablishedPool.Count( t => !t.Key.NeedsRecreation );

                var result = TargetInboundTunnelCount
                            - stable
                            - InboundPending.Count;

                return Math.Max( 0, result );
            }
        }

        int IClient.OutboundTunnelsNeeded
        {
            get
            {
                var stable = OutboundEstablishedPool.Count( t => !t.Key.NeedsRecreation );

                var result = TargetOutboundTunnelCount
                            - stable
                            - OutboundPending.Count;

                return Math.Max( 0, result );
            }
        }
        void IClient.AddOutboundPending( OutboundTunnel tunnel )
        {
            OutboundPending[tunnel] = 0;
        }

        void IClient.AddInboundPending( InboundTunnel tunnel )
        {
            InboundPending[tunnel] = 0;
        }

        void IClient.TunnelEstablished( Tunnel tunnel )
        {
            RemovePendingTunnel( tunnel );

            if ( tunnel is OutboundTunnel ot )
            {
                OutboundEstablishedPool[ot] = 0;
            }

            if ( tunnel is InboundTunnel it )
            {
                InboundEstablishedPool[it] = 0;

                it.TunnelShutdown += InboundTunnel_TunnelShutdown;
                it.GarlicMessageReceived += InboundTunnel_GarlicMessageReceived;

                AddTunnelToEstablishedLeaseSet( it );
            }

            UpdateClientState();
        }

        void IClient.RemoveTunnel( Tunnel tunnel, RemovalReason reason )
        {
            RemovePendingTunnel( tunnel );
            RemovePoolTunnel( tunnel, reason );

            UpdateClientState();
        }

        void IClient.Execute()
        {
            if ( Terminated ) return;

            if ( AutomaticIdleUpdateRemotes )
            {
                KeepClientStateUpdated.Do( () =>
                {
                    UpdateClientState();
                } );
            }

            QueueStatusLog.Do( () =>
            {
                Logging.LogInformation(
                    $"{this}: Established tunnels in: {InboundEstablishedPool.Count,2}, " +
                    $"out: {OutboundEstablishedPool.Count,2}. " +
                    $"Pending in: {InboundPending.Count,2}, out {OutboundPending.Count,2}" );
            } );
        }

    }
}