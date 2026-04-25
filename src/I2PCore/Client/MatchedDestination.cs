using System;
using System.Linq;
using System.Threading;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.Client;

/// <summary>
///     MatchedDestination optimizes tunnel construction by selecting outbound
///     tunnel endpoints that are topologically close to the target destination's
///     inbound tunnel gateways. This reduces latency for repeated connections
///     to the same remote destination.
///     Port of i2pd's MatchedTunnelDestination.
/// </summary>
public class MatchedDestination : IDisposable
{
    private const int RESOLVE_INTERVAL_MS = 60000; // Re-resolve every 60s
    private readonly string _remoteName;
    private bool _disposed;
    private Timer _resolveTimer;

    /// <summary>
    ///     Create a MatchedDestination that optimizes routing to a named destination.
    /// </summary>
    /// <param name="remoteName">The .i2p hostname or base32/base64 address of the target</param>
    public MatchedDestination(string remoteName)
    {
        _remoteName = remoteName ?? throw new ArgumentNullException(nameof(remoteName));
    }

    /// <summary>
    ///     Get the resolved remote identity hash, or null if not yet resolved.
    /// </summary>
    public I2PIdentHash RemoteIdentHash { get; private set; }

    /// <summary>
    ///     Get the current remote lease set, or null if not yet resolved.
    /// </summary>
    public ILeaseSet RemoteLeaseSet { get; private set; }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }

    /// <summary>
    ///     Start periodic resolution of the remote destination's lease set.
    /// </summary>
    public void Start()
    {
        ResolveRemote();
        _resolveTimer = new Timer(_ => ResolveRemote(), null, RESOLVE_INTERVAL_MS, RESOLVE_INTERVAL_MS);
    }

    /// <summary>
    ///     Stop periodic resolution.
    /// </summary>
    public void Stop()
    {
        _resolveTimer?.Dispose();
        _resolveTimer = null;
    }

    /// <summary>
    ///     Select the best outbound endpoint (OBEP) for reaching the remote destination.
    ///     Returns the identity hash of a router that is also an IBGW for the remote,
    ///     or null if no match is found.
    /// </summary>
    public I2PIdentHash SelectOptimalOutboundEndpoint()
    {
        var ls = RemoteLeaseSet;
        if (ls == null) return null;

        var leases = ls.Leases?.ToList();
        if (leases == null || leases.Count == 0) return null;

        // Find a lease whose gateway (IBGW) is a known router we could use as OBEP
        foreach (var lease in leases)
        {
            var gw = lease.TunnelGw;
            if (gw != null)
            {
                var routerInfo = NetDb.Inst[gw];
                if (routerInfo != null)
                    // This router exists in our NetDb, suitable as OBEP
                    return gw;
            }
        }

        return null;
    }

    /// <summary>
    ///     Check if a given peer would make a good outbound endpoint for reaching the remote.
    /// </summary>
    public bool IsGoodOutboundEndpoint(I2PIdentHash peer)
    {
        var ls = RemoteLeaseSet;
        if (ls == null) return false;

        return ls.Leases?.Any(l => l.TunnelGw?.Equals(peer) == true) ?? false;
    }

    private void ResolveRemote()
    {
        try
        {
            // Try to resolve as base32
            if (_remoteName.Contains(".b32.i2p", StringComparison.OrdinalIgnoreCase) ||
                (_remoteName.Length == 52 && !_remoteName.Contains('.')))
            {
                var stripped = _remoteName;
                if (stripped.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase))
                    stripped = stripped[..^4];
                if (stripped.EndsWith(".b32", StringComparison.OrdinalIgnoreCase))
                    stripped = stripped[..^4];

                RemoteIdentHash = new I2PIdentHash(stripped);
            }
            else if (RemoteIdentHash == null)
            {
                // Try base64 destination
                var destBytes = FreenetBase64.Decode(_remoteName);
                if (destBytes != null && destBytes.Length >= 387)
                {
                    var dest = new I2PDestination(new I2PBufferCursor(destBytes));
                    RemoteIdentHash = new I2PIdentHash(dest);
                }
            }

            // Look up the lease set
            if (RemoteIdentHash != null)
            {
                var ls = NetDb.Inst.FindLeaseSet(RemoteIdentHash);
                if (ls != null)
                {
                    RemoteLeaseSet = ls;
                    Logging.LogDebug($"MatchedDestination: Resolved {_remoteName} with {ls.Leases?.Count()} leases");
                }
            }
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"MatchedDestination: Resolve failed: {ex.Message}");
        }
    }
}