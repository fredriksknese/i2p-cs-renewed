using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace I2PCore.Utils;

public class ServerTunnelLogger
{
    private const int MaxLogs = 2000;

    private readonly ConcurrentQueue<LogEntry> _logs = new();
    private int _lastId;

    public static ServerTunnelLogger Inst { get; } = new();

    public void Log(string tunnelName, string status, string details = null, string target = null)
    {
        var entry = new LogEntry
        {
            Id = Interlocked.Increment(ref _lastId),
            Timestamp = DateTime.UtcNow,
            TunnelName = tunnelName,
            Status = status,
            Details = details,
            Target = target
        };
        _logs.Enqueue(entry);
        while (_logs.Count > MaxLogs) _logs.TryDequeue(out _);
    }

    public IEnumerable<LogEntry> GetLogs()
    {
        return _logs.ToArray();
    }

    public class LogEntry
    {
        public int Id { get; set; }
        public DateTime Timestamp { get; set; }
        public string TunnelName { get; set; }
        public string Status { get; set; }
        public string Details { get; set; }
        public string Target { get; set; }
    }
}
