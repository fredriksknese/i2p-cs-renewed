using I2PCore.Data;
using I2PCore;
using System.Collections.Concurrent;

namespace I2PRouterWeb.Services;

public enum NetDbLogCategory
{
    RouterInfoDiscovered,
    RouterInfoExpired,
    LeaseSetAnnounced,
    PeerHashesDiscovered
}

public class NetDbLogEntry
{
    public DateTime Timestamp { get; set; }
    public NetDbLogCategory Category { get; set; }
    public string IdentHash { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class NetDbLogService
{
    private readonly ConcurrentQueue<NetDbLogEntry> _logs = new();
    private const int MaxLogEntries = 1000;
    private bool _isInitialized = false;

    public void Initialize()
    {
        if (_isInitialized || NetDb.Inst == null) return;

        NetDb.Inst.RouterInfoUpdates += OnRouterInfoUpdated;
        NetDb.Inst.RouterInfoRemovals += OnRouterInfoRemoved;
        NetDb.Inst.LeaseSetUpdates += OnLeaseSetUpdated;
        NetDb.Inst.DatabaseSearchReplies += OnDatabaseSearchReplyReceived;
        
        _isInitialized = true;
    }

    private void OnDatabaseSearchReplyReceived(I2PCore.TunnelLayer.I2NP.Messages.DatabaseSearchReplyMessage dsm)
    {
        var hashes = dsm.Peers.Select(r => r.Id32Short).ToArray();
        var message = $"Discovered {hashes.Length} peer hashes via search reply: {string.Join(", ", hashes)}";
        AddLog(NetDbLogCategory.PeerHashesDiscovered, "Multiple", message);
    }

    private void OnRouterInfoUpdated(I2PRouterInfo info)
    {
        // Only log if we didn't have this router before, or if it was marked as deleted
        AddLog(NetDbLogCategory.RouterInfoDiscovered, info.Identity.IdentHash.Id32Short, $"Newly discovered RouterInfo: {info.Identity.IdentHash.Id32Short}");
    }

    private void OnRouterInfoRemoved(I2PIdentHash hash)
    {
        AddLog(NetDbLogCategory.RouterInfoExpired, hash.Id32Short, $"RouterInfo expired and removed: {hash.Id32Short}");
    }

    private void OnLeaseSetUpdated(ILeaseSet ls)
    {
        AddLog(NetDbLogCategory.LeaseSetAnnounced, ls.Destination.IdentHash.Id32Short, $"LeaseSet announced for {ls.Destination.IdentHash.Id32Short}");
    }

    private void AddLog(NetDbLogCategory category, string identHash, string message)
    {
        _logs.Enqueue(new NetDbLogEntry
        {
            Timestamp = DateTime.UtcNow,
            Category = category,
            IdentHash = identHash,
            Message = message
        });

        while (_logs.Count > MaxLogEntries)
        {
            _logs.TryDequeue(out _);
        }
    }

    public IEnumerable<NetDbLogEntry> GetLogs() => _logs.ToArray().Reverse();
}
