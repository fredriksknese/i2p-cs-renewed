namespace I2PCore.TunnelLayer;

internal class TunnelSettings
{
    internal const float EndpointTunnelBitrateLimit = 500f * 1024f;
    internal const float GatewayTunnelBitrateLimit = 500f * 1024f;
    internal const float TransitTunnelBitrateLimit = 500f * 1024f;

    /// <summary>
    ///     0.0f (share nothing) -> 1.0f (only share)
    /// </summary>
    internal float BandwidthShareRatio = 0.5f;

    internal float InboundTunnelBitrateLimit = 0f;
    internal float OutboundTunnelBitrateLimit = 0f;
}