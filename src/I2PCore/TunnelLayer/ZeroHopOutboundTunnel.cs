using System;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TunnelLayer
{
    public class ZeroHopOutboundTunnel: OutboundTunnel
    {
        public override TickSpan Lifetime => TickSpan.Minutes( 5 );

        public override TickSpan TunnelEstablishmentTimeout => TickSpan.Seconds( 100 );

        public override bool NeedsRecreation => false;

        public ZeroHopOutboundTunnel( ITunnelOwner owner, TunnelConfig config )
            : base( owner, config, 0 )
        {
            NextHop = RouterContext.Inst.MyRouterIdentity.IdentHash;
            Established = true;
        }

        public override void Send( TunnelMessage msg )
        {
            msg.Distribute( this );
        }

        public override I2PIdentHash FarEnd => RouterContext.Inst.MyRouterIdentity.IdentHash;
    }
}
