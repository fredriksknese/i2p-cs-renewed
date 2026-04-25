using System;

namespace I2PCore.Data;

public interface ILease
{
    I2PIdentHash TunnelGw { get; }
    I2PTunnelId TunnelId { get; }
    DateTime Expire { get; }
}