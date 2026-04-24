using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace I2PCore.TransportLayer.NTCP2
{
    /// <summary>
    /// Security validation for NTCP2 handshake messages
    /// Implements timestamp validation and replay prevention
    /// NTCP2 spec lines 503-544
    /// </summary>
    public class NTCP2SecurityValidator
    {
        // Maximum time delta in seconds (recommended: 2 minutes)
        private const int MAX_TIME_DELTA = 120;

        // Replay cache: stores handshake values to prevent replay attacks
        // Key is the 32-byte ephemeral key (X or Y), Value is expiration time
        private static readonly ConcurrentDictionary<string, DateTime> replayCache = new ConcurrentDictionary<string, DateTime>();

        // Blacklist for IPs with repeated failures
        private static readonly ConcurrentDictionary<string, (int count, DateTime expiry)> ipBlacklist = new ConcurrentDictionary<string, (int, DateTime)>();

        private const int MAX_FAILURES_BEFORE_BAN = 10;
        private static readonly TimeSpan BAN_DURATION = TimeSpan.FromHours(1);

        /// <summary>
        /// Validate timestamp from handshake message
        /// NTCP2 spec lines 503-511, 813-818
        /// </summary>
        /// <param name="timestamp">Unix timestamp from message (seconds)</param>
        /// <param name="maxDelta">Maximum allowed time delta in seconds (default 120)</param>
        /// <returns>True if timestamp is valid</returns>
        public static bool ValidateTimestamp(uint timestamp, int maxDelta = MAX_TIME_DELTA)
        {
            var messageTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
            var currentTime = DateTimeOffset.UtcNow;
            var delta = Math.Abs((currentTime - messageTime).TotalSeconds);

            var isValid = delta <= maxDelta;

            if (!isValid)
            {
                Utils.Logging.LogWarning($"NTCP2SecurityValidator: Timestamp validation failed - delta={delta:F1}s (max={maxDelta}s), message={messageTime:yyyy-MM-dd HH:mm:ss} UTC, current={currentTime:yyyy-MM-dd HH:mm:ss} UTC");
            }

            return isValid;
        }

        /// <summary>
        /// Check and add ephemeral key to replay cache
        /// NTCP2 spec lines 503-511: Must reject duplicates with lifetime >= 2*D
        /// </summary>
        /// <param name="ephemeralKey">32-byte ephemeral key (X or Y)</param>
        /// <param name="maxDelta">Maximum time delta (default 120 seconds)</param>
        /// <returns>True if key is new (not a replay), False if replay detected</returns>
        public static bool CheckAndAddToReplayCache(byte[] ephemeralKey, int maxDelta = MAX_TIME_DELTA)
        {
            if (ephemeralKey == null || ephemeralKey.Length != 32)
                throw new ArgumentException("Ephemeral key must be 32 bytes", nameof(ephemeralKey));

            // Convert key to string for dictionary lookup
            var keyString = Convert.ToBase64String(ephemeralKey);

            // Cache lifetime must be at least 2*D per spec
            var expirationTime = DateTime.UtcNow.AddSeconds(2 * maxDelta);

            // Try to add to cache
            if (!replayCache.TryAdd(keyString, expirationTime))
            {
                // Key already exists - replay attack detected
                return false;
            }

            // Cleanup expired entries periodically
            CleanupReplayCache();

            return true;
        }

        /// <summary>
        /// Check if encrypted ephemeral key is in replay cache
        /// Can use encrypted equivalent per spec line 508
        /// </summary>
        public static bool CheckAndAddEncryptedToReplayCache(byte[] encryptedEphemeralKey, int maxDelta = MAX_TIME_DELTA)
        {
            return CheckAndAddToReplayCache(encryptedEphemeralKey, maxDelta);
        }

        /// <summary>
        /// Remove expired entries from replay cache
        /// </summary>
        private static void CleanupReplayCache()
        {
            // Only cleanup every 1000 additions to avoid overhead
            if (replayCache.Count % 1000 != 0)
                return;

            var now = DateTime.UtcNow;
            var keysToRemove = new List<string>();

            foreach (var entry in replayCache)
            {
                if (entry.Value < now)
                    keysToRemove.Add(entry.Key);
            }

            foreach (var key in keysToRemove)
            {
                replayCache.TryRemove(key, out _);
            }
        }

        /// <summary>
        /// Record a handshake failure from an IP address
        /// NTCP2 spec lines 530-533, 543-544: Maintain blacklist for repeated failures
        /// </summary>
        public static void RecordFailure(string ipAddress)
        {
            var now = DateTime.UtcNow;

            ipBlacklist.AddOrUpdate(
                ipAddress,
                (count: 1, expiry: now + BAN_DURATION),  // First failure
                (key, existing) =>
                {
                    // Increment count if not expired
                    if (existing.expiry > now)
                    {
                        return (count: existing.count + 1, expiry: existing.expiry);
                    }
                    else
                    {
                        // Expired, reset
                        return (count: 1, expiry: now + BAN_DURATION);
                    }
                }
            );
        }

        /// <summary>
        /// Check if an IP address is blacklisted
        /// </summary>
        public static bool IsBlacklisted(string ipAddress)
        {
            if (ipBlacklist.TryGetValue(ipAddress, out var entry))
            {
                // Check if ban is still active
                if (entry.expiry > DateTime.UtcNow)
                {
                    return entry.count >= MAX_FAILURES_BEFORE_BAN;
                }
                else
                {
                    // Ban expired, remove
                    ipBlacklist.TryRemove(ipAddress, out _);
                    return false;
                }
            }

            return false;
        }

        /// <summary>
        /// Clear an IP from the blacklist (for testing or manual intervention)
        /// </summary>
        public static void ClearBlacklist(string ipAddress)
        {
            ipBlacklist.TryRemove(ipAddress, out _);
        }

        /// <summary>
        /// Validate static key matches RouterInfo
        /// NTCP2 spec lines 1044-1047
        /// </summary>
        public static bool ValidateStaticKeyMatchesRouterInfo(byte[] staticKey, I2PCore.Data.I2PRouterInfo routerInfo)
        {
            if (staticKey == null || staticKey.Length != 32)
                return false;

            if (routerInfo == null)
                return false;

            // Search for NTCP2 address with 's' option
            foreach (var address in routerInfo.Addresses)
            {
                if (address.TransportStyle == "NTCP2" || address.TransportStyle == "NTCP")
                {
                    try
                    {
                        var staticKeyBase64 = address.Options["s"];
                        if (!string.IsNullOrEmpty(staticKeyBase64))
                        {
                            var riStaticKey = Convert.FromBase64String(staticKeyBase64);
                            if (riStaticKey.Length == 32)
                            {
                                // Compare keys
                                return CompareBytes(staticKey, riStaticKey);
                            }
                        }
                    }
                    catch
                    {
                        // Key not found or invalid Base64
                        continue;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Constant-time byte array comparison
        /// </summary>
        private static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
        }

        /// <summary>
        /// Get cache statistics (for monitoring/debugging)
        /// </summary>
        public static (int replayCacheSize, int blacklistSize) GetCacheStats()
        {
            return (replayCache.Count, ipBlacklist.Count);
        }

        /// <summary>
        /// Clear all caches (for testing)
        /// </summary>
        public static void ClearAllCaches()
        {
            replayCache.Clear();
            ipBlacklist.Clear();
        }
    }
}
