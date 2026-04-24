using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace I2PCore.Utils
{
    public class HttpProxyLogger
    {
        public class LogEntry
        {
            public int Id { get; set; }
            public DateTime Timestamp { get; set; }
            public string Method { get; set; }
            public string Target { get; set; }
            public string Status { get; set; }
            public string Details { get; set; }
            public string RawData { get; set; }
        }

        public static HttpProxyLogger Inst { get; } = new HttpProxyLogger();

        private readonly ConcurrentQueue<LogEntry> _logs = new();
        private int _lastId = 0;
        private const int MaxLogs = 1000;

        public void Log(string method, string target, string status, string details = null, string rawData = null)
        {
            var entry = new LogEntry
            {
                Id = Interlocked.Increment(ref _lastId),
                Timestamp = DateTime.UtcNow,
                Method = method,
                Target = target,
                Status = status,
                Details = details,
                RawData = rawData
            };
            _logs.Enqueue(entry);
            while (_logs.Count > MaxLogs) _logs.TryDequeue(out _);
        }

        public IEnumerable<LogEntry> GetLogs() => _logs.ToArray();
    }
}
