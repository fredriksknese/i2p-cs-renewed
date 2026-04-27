using System.Collections.Concurrent;
using I2PCore;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PRouterWeb.Services;

public enum NetDbLogCategory
{
    RouterInfoDiscovered,
    RouterInfoExpired,
    LeaseSetAnnounced,
    PeerHashesDiscovered,
    DatabaseLookupReceived
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
    private const int MaxLogEntries = 1000;
    private readonly ConcurrentQueue<NetDbLogEntry> _logs = new();
    private bool _isInitialized;

    public void Initialize()
    {
        if (_isInitialized || NetDb.Inst == null) return;

        NetDb.Inst.RouterInfoUpdates += OnRouterInfoUpdated;
        NetDb.Inst.RouterInfoRemovals += OnRouterInfoRemoved;
        NetDb.Inst.LeaseSetUpdates += OnLeaseSetUpdated;
        NetDb.Inst.DatabaseSearchReplies += OnDatabaseSearchReplyReceived;
        NetDb.Inst.DatabaseLookupReceived += OnDatabaseLookupReceived;

        _isInitialized = true;
    }

    private void OnDatabaseLookupReceived(DatabaseLookupMessage lookup, I2PIdentHash from,
        NetDb.DatabaseLookupResult result)
    {
        var isRouterInfoLookup = (lookup.LookupType & DatabaseLookupMessage.LookupTypes.RouterInfo) != 0;
        var keyStr = isRouterInfoLookup ? lookup.Key.Id64 : $"{lookup.Key.Id32}.b32.i2p";

        var isTunnel = (lookup.LookupType & DatabaseLookupMessage.LookupTypes.Tunnel) != 0;
        string viaStr;
        if (isTunnel)
            viaStr = $"Tunnel {lookup.TunnelId} at {lookup.From?.Id64Short ?? "Unknown"}";
        else
            viaStr = $"Direct to {lookup.From?.Id64Short ?? "Unknown"}";

        var resultStr = result switch
        {
            NetDb.DatabaseLookupResult.RouterInfoFound => "Success (Found RouterInfo)",
            NetDb.DatabaseLookupResult.LeaseSetFound => "Success (Found LeaseSet)",
            NetDb.DatabaseLookupResult.ClosestFloodfillsSent => "Not Found (Sent Closest Peers)",
            _ => "Unknown"
        };

        var message =
            $"Received {lookup.LookupType} lookup for {keyStr} ({lookup.Key.Id64}). Responding via {viaStr}. Result: {resultStr}";
        AddLog(NetDbLogCategory.DatabaseLookupReceived, lookup.Key.Id64, message);
    }

    private void OnDatabaseSearchReplyReceived(DatabaseSearchReplyMessage dsm)
    {
        var hashes = dsm.Peers.Select(r => r.Id64Short).ToArray();
        var message = $"Discovered {hashes.Length} peer hashes via search reply: {string.Join(", ", hashes)}";
        AddLog(NetDbLogCategory.PeerHashesDiscovered, "Multiple", message);
    }

    private void OnRouterInfoUpdated(I2PRouterInfo info)
    {
        // Only log if we didn't have this router before, or if it was marked as deleted
        AddLog(NetDbLogCategory.RouterInfoDiscovered, info.Identity.IdentHash.Id64,
            $"Newly discovered RouterInfo: {info.Identity.IdentHash.Id64}");
    }

    private void OnRouterInfoRemoved(I2PIdentHash hash)
    {
        AddLog(NetDbLogCategory.RouterInfoExpired, hash.Id64, $"RouterInfo expired and removed: {hash.Id64}");
    }

    private void OnLeaseSetUpdated(ILeaseSet ls)
    {
        AddLog(NetDbLogCategory.LeaseSetAnnounced, ls.Destination.IdentHash.Id64,
            $"LeaseSet announced for {ls.Destination.IdentHash.Id64}");
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

        while (_logs.Count > MaxLogEntries) _logs.TryDequeue(out _);
    }

    public IEnumerable<NetDbLogEntry> GetLogs()
    {
        return _logs.ToArray().Reverse();
    }
}