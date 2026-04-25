using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace I2PCore.TransportLayer.Log;

public class TransportConnectionLogger
{
    private const int MaxEntries = 1000;
    public static readonly TransportConnectionLogger Inst = new();
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    private TransportConnectionLogger()
    {
    }

    public void Log(string message, string routerId = null, string transport = null, string direction = null)
    {
        _entries.Enqueue(new LogEntry(DateTime.UtcNow, message, routerId, transport, direction));

        // Keep the queue size in check
        while (_entries.Count > MaxEntries) _entries.TryDequeue(out _);
    }

    public IEnumerable<LogEntry> GetEntries()
    {
        return _entries.ToArray().Reverse();
    }

    public class LogEntry
    {
        public LogEntry(DateTime timestamp, string message, string routerId, string transport, string direction)
        {
            Timestamp = timestamp;
            Message = message;
            RouterId = routerId;
            Transport = transport;
            Direction = direction;
        }

        public DateTime Timestamp { get; }
        public string Message { get; }
        public string RouterId { get; }
        public string Transport { get; }
        public string Direction { get; }
    }
}