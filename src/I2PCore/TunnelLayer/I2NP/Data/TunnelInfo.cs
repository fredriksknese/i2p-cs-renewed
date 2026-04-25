using System.Collections.Generic;

namespace I2PCore.TunnelLayer.I2NP.Data;

public class TunnelInfo
{
    public readonly List<HopInfo> Hops;

    public TunnelInfo(List<HopInfo> hops)
    {
        Hops = hops;
    }
}