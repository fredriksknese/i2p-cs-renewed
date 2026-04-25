using System;

namespace I2PCore.Utils;

/// <summary>
///     Token bucket bandwidth limiter.
///     Enforces a hard rate limit using the token bucket algorithm.
///     Compatible with i2pd's bandwidth tier system (K/L/M/N/O/P/X).
/// </summary>
public class BandwidthLimiter
{
    // Soft limit starts probabilistic dropping at this factor of max
    private const double SoftLimitFactor = 0.9;
    private readonly object _lock = new();

    private readonly Random _rnd = new();
    private readonly Bandwidth BandwidthMeasurement;
    private long _lastRefillTicks;
    private double _maxBurst;
    private double _maxBytesPerSecond;
    private double _tokens;

    /// <summary>
    ///     Create a bandwidth limiter with a token bucket.
    /// </summary>
    /// <param name="bwref">Bandwidth measurement reference for monitoring.</param>
    /// <param name="maxkbps">Maximum bandwidth in kilobytes per second.</param>
    public BandwidthLimiter(Bandwidth bwref, float maxkbps)
    {
        BandwidthMeasurement = bwref;
        SetLimit(maxkbps);
    }

    /// <summary>
    ///     Check if the current rate exceeds the limit without consuming tokens.
    /// </summary>
    public bool IsOverLimit => BandwidthMeasurement?.Bitrate > _maxBytesPerSecond;

    /// <summary>
    ///     Current available tokens (bytes that can be sent immediately).
    /// </summary>
    public double AvailableTokens
    {
        get
        {
            lock (_lock)
            {
                RefillTokens();
                return _tokens;
            }
        }
    }

    /// <summary>
    ///     Update the bandwidth limit.
    /// </summary>
    public void SetLimit(float maxkbps)
    {
        lock (_lock)
        {
            _maxBytesPerSecond = maxkbps * 1024.0;
            // Allow burst up to 2 seconds of traffic
            _maxBurst = _maxBytesPerSecond * 2.0;
            _tokens = _maxBurst;
            _lastRefillTicks = Environment.TickCount64;
        }
    }

    /// <summary>
    ///     Try to consume bytes from the token bucket.
    ///     Returns true if the message should be dropped (no tokens available).
    /// </summary>
    public bool DropMessage()
    {
        return !TryConsume(1024); // Assume average message ~1KB
    }

    /// <summary>
    ///     Try to consume a specific number of bytes.
    ///     Returns true if tokens were available, false if rate limited.
    /// </summary>
    public bool TryConsume(int bytes)
    {
        if (_maxBytesPerSecond <= 0) return true; // No limit

        lock (_lock)
        {
            RefillTokens();

            if (_tokens >= bytes)
            {
                _tokens -= bytes;
                return true;
            }

            // Soft limit: allow with decreasing probability near the limit
            // This smooths traffic instead of hard-cutting
            var ratio = _tokens / bytes;
            if (ratio > 0 && _rnd.NextDouble() < ratio * SoftLimitFactor)
            {
                _tokens = 0;
                return true;
            }

            return false;
        }
    }

    private void RefillTokens()
    {
        var now = Environment.TickCount64;
        var elapsed = (now - _lastRefillTicks) / 1000.0; // seconds
        _lastRefillTicks = now;

        if (elapsed <= 0) return;

        _tokens += elapsed * _maxBytesPerSecond;
        if (_tokens > _maxBurst)
            _tokens = _maxBurst;
    }
}