using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using I2PCore.Data;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     Security validation and replay prevention for SSU2
///     SSU2 spec lines 1207-1213, 1485-1488
/// </summary>
public static class SSU2SecurityValidator
{
    private const int MAX_TIME_DELTA = 60; // 60 seconds clock skew tolerance

    // Replay cache for handshake ephemeral keys
    // Cache lifetime must be at least 2*D where D = max clock skew
    private static readonly ConcurrentDictionary<string, DateTime> replayCache = new();

    /// <summary>
    ///     Validate timestamp is within acceptable range
    /// </summary>
    public static bool ValidateTimestamp(uint timestamp, int maxDelta = MAX_TIME_DELTA)
    {
        var messageTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        var currentTime = DateTimeOffset.UtcNow;
        var delta = Math.Abs((currentTime - messageTime).TotalSeconds);

        return delta <= maxDelta;
    }

    /// <summary>
    ///     Check and add ephemeral key to replay cache
    ///     Per spec lines 1207-1213: Cache handshake values for 2*D to prevent replay
    /// </summary>
    public static bool CheckAndAddToReplayCache(byte[] ephemeralKey, int maxDelta = MAX_TIME_DELTA)
    {
        if (ephemeralKey == null || ephemeralKey.Length != 32)
            throw new ArgumentException("Ephemeral key must be 32 bytes", nameof(ephemeralKey));

        var keyString = Convert.ToBase64String(ephemeralKey);
        var expirationTime = DateTime.UtcNow.AddSeconds(2 * maxDelta);

        // Try to add to cache
        if (!replayCache.TryAdd(keyString, expirationTime))
            // Key already exists - replay attack detected
            return false;

        // Cleanup expired entries periodically
        CleanupReplayCache();
        return true;
    }

    /// <summary>
    ///     Cleanup expired replay cache entries
    /// </summary>
    private static void CleanupReplayCache()
    {
        // Only cleanup occasionally to avoid overhead
        if (replayCache.Count < 1000)
            return;

        var now = DateTime.UtcNow;
        var expiredKeys = new List<string>();

        foreach (var entry in replayCache)
            if (entry.Value < now)
                expiredKeys.Add(entry.Key);

        foreach (var key in expiredKeys) replayCache.TryRemove(key, out _);
    }

    /// <summary>
    ///     Validate connection IDs are not equal
    ///     Per spec: Source and Destination Connection IDs must be different
    /// </summary>
    public static bool ValidateConnectionIds(ulong sourceId, ulong destinationId)
    {
        return sourceId != destinationId;
    }

    /// <summary>
    ///     Validate version and network ID
    /// </summary>
    public static bool ValidateVersionAndNetId(byte version, byte netId)
    {
        return version == 2 && netId == (byte)I2PConstants.I2PNetworkId;
    }
}