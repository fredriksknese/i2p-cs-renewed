using I2PCore.Utils;

namespace I2PCore.TunnelLayer;

public class TunnelQuality
{
    public TickSpan MinLatencyMeasured { get; set; }

    public bool PassedTunnelTest { get; set; }

    public TickSpan BuildTimePerHop { get; set; }

    public void UpdateMinLatency(TickSpan delta)
    {
        if (MinLatencyMeasured == null || MinLatencyMeasured > delta) MinLatencyMeasured = delta;
    }
}