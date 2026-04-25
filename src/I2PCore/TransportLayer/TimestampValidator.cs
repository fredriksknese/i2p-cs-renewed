using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using I2PCore.Utils;

namespace I2PCore.TransportLayer;

/// <summary>
///     Timestamp validation and replay prevention for transport protocols
///     Used by both NTCP2 and SSU2
/// </summary>
public class TimestampValidator
{
    private readonly int maxClockSkewSeconds;
    private readonly ConcurrentDictionary<string, DateTime> replayCache;
    private readonly TimeSpan replayCacheLifetime;

    public TimestampValidator(int maxClockSkewSeconds = 60, int replayCacheMinutes = 10)
    {
        this.maxClockSkewSeconds = maxClockSkewSeconds;
        replayCacheLifetime = TimeSpan.FromMinutes(replayCacheMinutes);
        replayCache = new ConcurrentDictionary<string, DateTime>();
    }

    /// <summary>
    ///     Validate a timestamp and check for replays
    /// </summary>
    /// <param name="timestamp">Unix timestamp in seconds</param>
    /// <param name="sessionId">Unique identifier for this session/connection</param>
    /// <returns>True if timestamp is valid and not a replay</returns>
    public bool ValidateTimestamp(uint timestamp, string sessionId)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var diff = Math.Abs(now - timestamp);

        // Check clock skew
        if (diff > maxClockSkewSeconds)
        {
            Logging.LogDebug($"Timestamp validation failed: clock skew {diff}s exceeds max {maxClockSkewSeconds}s");
            return false;
        }

        // Check for replay
        var cacheKey = $"{sessionId}:{timestamp}";
        if (replayCache.ContainsKey(cacheKey))
        {
            Logging.LogDebug($"Timestamp validation failed: replay detected for {sessionId}");
            return false;
        }

        // Add to replay cache
        replayCache[cacheKey] = DateTime.UtcNow;

        return true;
    }

    /// <summary>
    ///     Clean up expired entries from replay cache
    ///     Should be called periodically
    /// </summary>
    public void CleanupReplayCache()
    {
        var now = DateTime.UtcNow;
        var toRemove = new List<string>();

        foreach (var entry in replayCache)
            if (now - entry.Value > replayCacheLifetime)
                toRemove.Add(entry.Key);

        foreach (var key in toRemove) replayCache.TryRemove(key, out _);

        if (toRemove.Count > 0) Logging.LogDebug($"Cleaned up {toRemove.Count} expired replay cache entries");
    }

    /// <summary>
    ///     Get current Unix timestamp
    /// </summary>
    public static uint GetCurrentTimestamp()
    {
        return (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }
}