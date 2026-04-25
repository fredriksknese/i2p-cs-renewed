using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer;

public class TunnelBuildLogger
{
    private const int MaxEntries = 1000;
    public static readonly TunnelBuildLogger Inst = new();
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    private TunnelBuildLogger()
    {
    }

    public void Log(string message, string tunnelId = null, string pool = null, string direction = null)
    {
        _entries.Enqueue(new LogEntry(DateTime.UtcNow, message, tunnelId, pool, direction));

        // Keep the queue size in check
        while (_entries.Count > MaxEntries) _entries.TryDequeue(out _);
    }

    public IEnumerable<LogEntry> GetEntries()
    {
        return _entries.ToArray().Reverse();
    }

    public static string GetHopsString(IEnumerable<HopInfo> hops)
    {
        return string.Join(" -> ", hops.Select(h => h.Peer.IdentHash.Id32Short));
    }

    public class LogEntry
    {
        public LogEntry(DateTime timestamp, string message, string tunnelId, string pool = null,
            string direction = null)
        {
            Timestamp = timestamp;
            Message = message;
            TunnelId = tunnelId;
            Pool = pool;
            Direction = direction;
        }

        public DateTime Timestamp { get; }
        public string Message { get; }
        public string TunnelId { get; }
        public string Pool { get; }
        public string Direction { get; }
    }
}