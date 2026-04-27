using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using I2PCore.Data;

namespace I2PCore.TransportLayer.Log;

public class TransportConnectionLogger
{
    private const int MaxEntries = 1000;
    private const int MaxFailureReasons = 500;
    public static readonly TransportConnectionLogger Inst = new();
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    // Connection outcome counters: [transport][direction] -> count
    private int _ntcp2InboundSuccess;
    private int _ntcp2OutboundSuccess;
    private int _ntcp2InboundFailed;
    private int _ntcp2OutboundFailed;
    private int _ssu2InboundSuccess;
    private int _ssu2OutboundSuccess;
    private int _ssu2InboundFailed;
    private int _ssu2OutboundFailed;

    // Failure reason tracking
    private readonly ConcurrentQueue<FailureEntry> _ntcp2InboundFailures = new();
    private readonly ConcurrentQueue<FailureEntry> _ntcp2OutboundFailures = new();
    private readonly ConcurrentQueue<FailureEntry> _ssu2InboundFailures = new();
    private readonly ConcurrentQueue<FailureEntry> _ssu2OutboundFailures = new();

    private TransportConnectionLogger()
    {
    }

    public void Log(string message, string routerId = null, string transport = null, string direction = null)
    {
        _entries.Enqueue(new LogEntry(DateTime.UtcNow, message, routerId, transport, direction));

        // Keep the queue size in check
        while (_entries.Count > MaxEntries) _entries.TryDequeue(out _);
    }

    /// <summary>
    ///     Record a successful connection.
    /// </summary>
    public void RecordSuccess(string transport, string direction)
    {
        if (transport == "NTCP2")
        {
            if (direction == "Inbound") Interlocked.Increment(ref _ntcp2InboundSuccess);
            else Interlocked.Increment(ref _ntcp2OutboundSuccess);
        }
        else if (transport == "SSU2")
        {
            if (direction == "Inbound") Interlocked.Increment(ref _ssu2InboundSuccess);
            else Interlocked.Increment(ref _ssu2OutboundSuccess);
        }
    }

    /// <summary>
    ///     Record a failed connection with a reason.
    /// </summary>
    public void RecordFailure(string transport, string direction, string reason, string routerId = null, string routerFullId = null, I2PRouterInfo routerInfo = null)
    {
        ConcurrentQueue<FailureEntry> queue;
        if (transport == "NTCP2")
        {
            if (direction == "Inbound")
            {
                Interlocked.Increment(ref _ntcp2InboundFailed);
                queue = _ntcp2InboundFailures;
            }
            else
            {
                Interlocked.Increment(ref _ntcp2OutboundFailed);
                queue = _ntcp2OutboundFailures;
            }
        }
        else if (transport == "SSU2")
        {
            if (direction == "Inbound")
            {
                Interlocked.Increment(ref _ssu2InboundFailed);
                queue = _ssu2InboundFailures;
            }
            else
            {
                Interlocked.Increment(ref _ssu2OutboundFailed);
                queue = _ssu2OutboundFailures;
            }
        }
        else
        {
            return;
        }
 
        queue.Enqueue(new FailureEntry(reason, routerId, routerFullId, routerInfo));
        while (queue.Count > MaxFailureReasons) queue.TryDequeue(out _);
    }
 
    public I2PRouterInfo GetRouterInfo(string hash)
    {
        if (string.IsNullOrEmpty(hash)) return null;

        var allQueues = new[]
        {
            _ntcp2InboundFailures, _ntcp2OutboundFailures, _ssu2InboundFailures, _ssu2OutboundFailures
        };

        foreach (var queue in allQueues)
        {
            var entry = queue.FirstOrDefault(f =>
                (f.RouterId != null && f.RouterId.Equals(hash, StringComparison.OrdinalIgnoreCase)) ||
                (f.RouterFullId != null && f.RouterFullId.Equals(hash, StringComparison.OrdinalIgnoreCase)));
            if (entry?.RouterInfo != null) return entry.RouterInfo;
        }

        return null;
    }
 
    public ConnectionStats GetConnectionStats()
    {
        return new ConnectionStats
        {
            Ntcp2InboundSuccess = _ntcp2InboundSuccess,
            Ntcp2OutboundSuccess = _ntcp2OutboundSuccess,
            Ntcp2InboundFailed = _ntcp2InboundFailed,
            Ntcp2OutboundFailed = _ntcp2OutboundFailed,
            Ssu2InboundSuccess = _ssu2InboundSuccess,
            Ssu2OutboundSuccess = _ssu2OutboundSuccess,
            Ssu2InboundFailed = _ssu2InboundFailed,
            Ssu2OutboundFailed = _ssu2OutboundFailed
        };
    }

    /// <summary>
    ///     Get the top N failure reasons for a given transport and direction.
    /// </summary>
    public IEnumerable<(string Reason, int Count, IEnumerable<(string ShortId, string FullId)> Routers)>
        GetTopFailureReasons(string transport, string direction, int topN = 10)
    {
        ConcurrentQueue<FailureEntry> queue;
        if (transport == "NTCP2")
            queue = direction == "Inbound" ? _ntcp2InboundFailures : _ntcp2OutboundFailures;
        else if (transport == "SSU2")
            queue = direction == "Inbound" ? _ssu2InboundFailures : _ssu2OutboundFailures;
        else
            return Enumerable.Empty<(string, int, IEnumerable<(string, string)>)>();

        return queue.ToArray()
            .GroupBy(f => f.Reason)
            .Select(g => (
                Reason: g.Key,
                Count: g.Count(),
                Routers: g.Where(f => !string.IsNullOrEmpty(f.RouterId))
                    .Select(f => (ShortId: f.RouterId, FullId: f.RouterFullId))
                    .Distinct()
                    .Take(50) // Limit routers per reason to avoid bloating the UI
            ))
            .OrderByDescending(x => x.Count)
            .Take(topN);
    }

    public IEnumerable<DetailedFailureInfo> GetDetailedFailuresByReason(
        string transport, string direction, string reason)
    {
        ConcurrentQueue<FailureEntry> queue;
        if (transport == "NTCP2")
            queue = direction == "Inbound" ? _ntcp2InboundFailures : _ntcp2OutboundFailures;
        else if (transport == "SSU2")
            queue = direction == "Inbound" ? _ssu2InboundFailures : _ssu2OutboundFailures;
        else
            return Enumerable.Empty<DetailedFailureInfo>();

        return queue.ToArray()
            .Where(f => f.Reason == reason)
            .Select(f => new DetailedFailureInfo(f.Reason, f.RouterId, f.RouterFullId, f.RouterInfo));
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

    public class ConnectionStats
    {
        public int Ntcp2InboundSuccess { get; set; }
        public int Ntcp2OutboundSuccess { get; set; }
        public int Ntcp2InboundFailed { get; set; }
        public int Ntcp2OutboundFailed { get; set; }
        public int Ssu2InboundSuccess { get; set; }
        public int Ssu2OutboundSuccess { get; set; }
        public int Ssu2InboundFailed { get; set; }
        public int Ssu2OutboundFailed { get; set; }
    }

    public class DetailedFailureInfo
    {
        public DetailedFailureInfo(string reason, string routerId, string routerFullId, I2PRouterInfo routerInfo)
        {
            Reason = reason;
            RouterId = routerId;
            RouterFullId = routerFullId;
            RouterInfo = routerInfo;
        }

        public string Reason { get; }
        public string RouterId { get; }
        public string RouterFullId { get; }
        public I2PRouterInfo RouterInfo { get; }
    }

    private class FailureEntry
    {
        public FailureEntry(string reason, string routerId, string routerFullId, I2PRouterInfo routerInfo)
        {
            Reason = reason ?? "Unknown";
            RouterId = routerId;
            RouterFullId = routerFullId;
            RouterInfo = routerInfo;
        }
 
        public string Reason { get; }
        public string RouterId { get; }
        public string RouterFullId { get; }
        public I2PRouterInfo RouterInfo { get; }
    }
}
