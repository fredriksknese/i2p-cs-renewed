using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer;

public class ZeroHopOutboundTunnel : OutboundTunnel
{
    public ZeroHopOutboundTunnel(ITunnelOwner owner, TunnelConfig config)
        : base(owner, config, 0)
    {
        NextHop = RouterContext.Inst.MyRouterIdentity.IdentHash;
        Established = true;
    }

    public override TickSpan Lifetime => TickSpan.Minutes(5);

    public override TickSpan TunnelEstablishmentTimeout => TickSpan.Seconds(100);

    public override bool NeedsRecreation => false;

    public override I2PIdentHash FarEnd => RouterContext.Inst.MyRouterIdentity.IdentHash;

    public override void Send(TunnelMessage msg)
    {
        msg.Distribute(this);
    }
}