using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore
{
    /// <summary>
    /// Per-router profiling for intelligent peer selection.
    /// Tracks tunnel creation success/failure, response times, and reliability.
    /// Compatible with i2pd Profiling.h/.cpp
    /// </summary>
    public class RouterProfile
    {
        public I2PIdentHash RouterHash { get; }

        // Tunnel build statistics
        public int TunnelBuildAttempts { get; internal set; }
        public int TunnelBuildSuccesses { get; internal set; }
        public int TunnelBuildFailures { get; internal set; }
        public int TunnelBuildTimeouts { get; internal set; }

        // Response time tracking
        public int LastResponseTime { get; private set; } // ms
        public double AverageResponseTime { get; private set; }
        public int MinResponseTime { get; private set; } = int.MaxValue;

        // Reliability
        public int TunnelTestAttempts { get; private set; }
        public int TunnelTestSuccesses { get; private set; }
        public int ConsecutiveFailures { get; private set; }

        // Timestamps
        public DateTime LastUsed { get; private set; }
        public DateTime Created { get; }
        public DateTime LastFailed { get; private set; }

        public RouterProfile(I2PIdentHash hash)
        {
            RouterHash = hash ?? throw new ArgumentNullException(nameof(hash));
            Created = DateTime.UtcNow;
            LastUsed = DateTime.UtcNow;
        }

        /// <summary>
        /// Record a tunnel build attempt result
        /// </summary>
        public void RecordTunnelBuild(bool success, int responseTimeMs = 0)
        {
            TunnelBuildAttempts++;
            if (success)
            {
                TunnelBuildSuccesses++;
                ConsecutiveFailures = 0;
                if (responseTimeMs > 0)
                {
                    LastResponseTime = responseTimeMs;
                    if (responseTimeMs < MinResponseTime)
                        MinResponseTime = responseTimeMs;
                    AverageResponseTime = AverageResponseTime == 0
                        ? responseTimeMs
                        : AverageResponseTime * 0.9 + responseTimeMs * 0.1;
                }
            }
            else
            {
                TunnelBuildFailures++;
                ConsecutiveFailures++;
                LastFailed = DateTime.UtcNow;
            }
            LastUsed = DateTime.UtcNow;
        }

        public void RecordTunnelBuildTimeout()
        {
            TunnelBuildAttempts++;
            TunnelBuildTimeouts++;
            ConsecutiveFailures++;
            LastFailed = DateTime.UtcNow;
            LastUsed = DateTime.UtcNow;
        }

        public void RecordTunnelTest(bool success)
        {
            TunnelTestAttempts++;
            if (success) TunnelTestSuccesses++;
            else ConsecutiveFailures++;
            LastUsed = DateTime.UtcNow;
        }

        /// <summary>
        /// Get a score for peer selection (higher = better)
        /// </summary>
        public double GetScore()
        {
            double successRate = TunnelBuildAttempts > 0
                ? (double)TunnelBuildSuccesses / TunnelBuildAttempts
                : 0.5;

            double responseScore = AverageResponseTime > 0
                ? Math.Max(0, 1.0 - AverageResponseTime / 5000.0)
                : 0.5;

            // Penalize consecutive failures
            double failPenalty = Math.Max(0, 1.0 - ConsecutiveFailures * 0.2);

            // Penalize recent failures
            double recentFailPenalty = 1.0;
            if (LastFailed > DateTime.MinValue)
            {
                var sinceFailure = (DateTime.UtcNow - LastFailed).TotalMinutes;
                if (sinceFailure < 5) recentFailPenalty = 0.5;
                else if (sinceFailure < 30) recentFailPenalty = 0.8;
            }

            return successRate * 0.4 + responseScore * 0.3 + failPenalty * 0.2 + recentFailPenalty * 0.1;
        }

        /// <summary>
        /// Whether this router should be avoided for tunnel building
        /// </summary>
        public bool IsBad => ConsecutiveFailures >= 5
            || (TunnelBuildAttempts > 10 && (double)TunnelBuildSuccesses / TunnelBuildAttempts < 0.1);

        /// <summary>
        /// Save profile to disk in INI-like format compatible with i2pd.
        /// </summary>
        public void Save( string profilesDirectory )
        {
            try
            {
                Directory.CreateDirectory( profilesDirectory );
                var filePath = Path.Combine( profilesDirectory, RouterHash.Id32 + ".profile" );
                var epoch = new DateTimeOffset( LastUsed ).ToUnixTimeSeconds();

                using var writer = new StreamWriter( filePath );
                writer.WriteLine( $"lastupdatetimestamp={epoch}" );
                writer.WriteLine( "[participation]" );
                writer.WriteLine( $"agreed={TunnelBuildSuccesses}" );
                writer.WriteLine( $"declined={TunnelBuildFailures}" );
                writer.WriteLine( $"nonreplied={TunnelBuildTimeouts}" );
                writer.WriteLine( "[usage]" );
                writer.WriteLine( $"taken={TunnelBuildAttempts}" );
                writer.WriteLine( $"rejected={TunnelBuildFailures}" );
                writer.WriteLine( $"connected={TunnelTestSuccesses}" );
            }
            catch ( Exception ex )
            {
                Logging.LogDebug( $"RouterProfile: Failed to save profile for {RouterHash.Id32Short}: {ex.Message}" );
            }
        }

        /// <summary>
        /// Load profile from disk.
        /// </summary>
        public static RouterProfile Load( string filePath )
        {
            try
            {
                if ( !File.Exists( filePath ) ) return null;

                var hashStr = Path.GetFileNameWithoutExtension( filePath );
                I2PIdentHash hash;
                try
                {
                    hash = new I2PIdentHash( hashStr );
                }
                catch
                {
                    return null;
                }

                var profile = new RouterProfile( hash );
                foreach ( var line in File.ReadAllLines( filePath ) )
                {
                    var trimmed = line.Trim();
                    if ( trimmed.StartsWith( "[" ) || string.IsNullOrEmpty( trimmed ) ) continue;
                    var parts = trimmed.Split( '=', 2 );
                    if ( parts.Length != 2 ) continue;

                    var key = parts[0].Trim();
                    if ( !int.TryParse( parts[1].Trim(), out var val ) ) continue;

                    switch ( key )
                    {
                        case "agreed": profile.TunnelBuildSuccesses = val; break;
                        case "declined": profile.TunnelBuildFailures = val; break;
                        case "nonreplied": profile.TunnelBuildTimeouts = val; break;
                        case "taken": profile.TunnelBuildAttempts = val; break;
                    }
                }

                return profile;
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Global router profiling database
    /// </summary>
    public class RouterProfileManager
    {
        private readonly ConcurrentDictionary<I2PIdentHash, RouterProfile> _profiles = new();

        public static RouterProfileManager Instance { get; } = new();

        public RouterProfile GetProfile(I2PIdentHash hash)
        {
            return _profiles.GetOrAdd(hash, h => new RouterProfile(h));
        }

        public void RecordTunnelBuild(I2PIdentHash hash, bool success, int responseTimeMs = 0)
        {
            GetProfile(hash).RecordTunnelBuild(success, responseTimeMs);
        }

        public void RecordTunnelBuildTimeout(I2PIdentHash hash)
        {
            GetProfile(hash).RecordTunnelBuildTimeout();
        }

        /// <summary>
        /// Clean up old profiles (> 24 hours since last use)
        /// </summary>
        public void Cleanup()
        {
            var cutoff = DateTime.UtcNow.AddHours(-24);
            foreach (var kvp in _profiles)
            {
                if (kvp.Value.LastUsed < cutoff)
                    _profiles.TryRemove(kvp.Key, out _);
            }
        }

        /// <summary>
        /// Save all profiles to disk. Called periodically (every ~22 minutes per i2pd convention).
        /// </summary>
        public void SaveAll( string profilesDirectory )
        {
            foreach ( var kvp in _profiles )
            {
                kvp.Value.Save( profilesDirectory );
            }
        }

        /// <summary>
        /// Load all profiles from disk on startup.
        /// </summary>
        public void LoadAll( string profilesDirectory )
        {
            if ( !Directory.Exists( profilesDirectory ) ) return;

            foreach ( var file in Directory.GetFiles( profilesDirectory, "*.profile" ) )
            {
                var profile = RouterProfile.Load( file );
                if ( profile != null )
                {
                    _profiles.TryAdd( profile.RouterHash, profile );
                }
            }
        }
    }
}
