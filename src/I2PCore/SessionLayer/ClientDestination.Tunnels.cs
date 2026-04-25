using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.TunnelLayer;
using I2PCore.Utils;

namespace I2PCore.SessionLayer;

public partial class ClientDestination : IClient
{
    internal InboundTunnel SelectInboundTunnel()
    {
        return TunnelProvider.SelectTunnel(InboundEstablishedPool.Keys, 5);
    }

    internal OutboundTunnel SelectOutboundTunnel()
    {
        return TunnelProvider.SelectTunnel(OutboundEstablishedPool.Keys, 5);
    }

    public static ILease SelectLease(IEnumerable<ILease> ls)
    {
        return ls
            .Where(l => l.Expire > DateTime.UtcNow)
            .RandomWeighted(l => l.Expire.ToFileTime(), 4);
    }

    private void RemovePendingTunnel(Tunnel tunnel)
    {
        if (tunnel is OutboundTunnel ot) OutboundPending.TryRemove(ot, out _);

        if (tunnel is InboundTunnel it) InboundPending.TryRemove(it, out _);
    }

    private void RemovePoolTunnel(Tunnel tunnel, RemovalReason reason)
    {
        if (tunnel is OutboundTunnel ot) OutboundEstablishedPool.TryRemove(ot, out _);

        if (tunnel is InboundTunnel it)
        {
            var removed = InboundEstablishedPool.TryRemove(it, out _);
            RemoveTunnelFromEstablishedLeaseSet((InboundTunnel)tunnel);

            // Always update signed leases when tunnels are removed,
            // including on expiration. Java I2P's ExpireJob always
            // regenerates the lease set to stop advertising dead tunnels.
            if (removed) UpdateSignedLeases();
        }
    }

    private void InboundTunnel_TunnelShutdown(Tunnel tunnel)
    {
        tunnel.TunnelShutdown -= InboundTunnel_TunnelShutdown;

        if (tunnel is InboundTunnel)
            ((InboundTunnel)tunnel).GarlicMessageReceived -= InboundTunnel_GarlicMessageReceived;
    }
}