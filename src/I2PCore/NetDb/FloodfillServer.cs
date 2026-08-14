using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore;

/// <summary>
///     Floodfill server mode handler. When enabled, this class responds to
///     incoming DatabaseLookup messages by serving RouterInfo and LeaseSet
///     entries from the local NetDb, and handles incoming DatabaseStore
///     messages from peers.
/// </summary>
public class FloodfillServer : IDisposable
{
    private const int FLOOD_EXPIRY_MS = 60000; // Don't re-flood same key within 60s
    private const int FLOOD_PEER_COUNT = 3; // Number of closest floodfills to propagate to

    // Rate limiting for DatabaseStore to prevent flood abuse
    private const int RATE_LIMIT_MAX_STORES = 100;
    private const int RATE_LIMIT_WINDOW_MS = 60000; // 1 minute

    // Tracks recently flooded keys to avoid duplicate floods
    private readonly ConcurrentDictionary<I2PIdentHash, long> _recentlyFlooded = new();
    private readonly ConcurrentQueue<long> _storeTimestamps = new();
    private bool _disposed;
    private bool _enabled;
    private long _lastRateLimitCleanup;
    private bool _registered;

    // Lookup request stats: IdentHash -> request count
    private readonly ConcurrentDictionary<I2PIdentHash, int> _leaseSetLookupCounts = new();
    private readonly ConcurrentDictionary<I2PIdentHash, int> _routerInfoLookupCounts = new();

    /// <summary>
    ///     Get the top N most requested LeaseSets.
    /// </summary>
    public IEnumerable<(I2PIdentHash Key, int Count)> GetTopLeaseSetLookups(int topN = 100)
    {
        return _leaseSetLookupCounts
            .Select(kv => (Key: kv.Key, Count: kv.Value))
            .OrderByDescending(x => x.Count)
            .Take(topN);
    }

    /// <summary>
    ///     Get the top N most requested RouterInfos.
    /// </summary>
    public IEnumerable<(I2PIdentHash Key, int Count)> GetTopRouterInfoLookups(int topN = 100)
    {
        return _routerInfoLookupCounts
            .Select(kv => (Key: kv.Key, Count: kv.Value))
            .OrderByDescending(x => x.Count)
            .Take(topN);
    }

    /// <summary>
    ///     Gets or sets whether floodfill server mode is active.
    ///     When enabled, the server registers for incoming I2NP messages
    ///     and responds to database queries from peers.
    /// </summary>
    public bool Enabled
    {
        get => _enabled;
        set
        {
            if (_enabled == value) return;
            _enabled = value;

            if (_enabled)
                Register();
            else
                Unregister();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }

    public event NetDb.NetworkDatabaseDatabaseLookupReceived DatabaseLookupReceived;

    /// <summary>
    ///     Start the floodfill server and begin handling queries.
    /// </summary>
    public void Start()
    {
        Enabled = true;
        Logging.LogInformation("FloodfillServer: Started.");
    }

    /// <summary>
    ///     Stop the floodfill server.
    /// </summary>
    public void Stop()
    {
        Enabled = false;
        Logging.LogInformation("FloodfillServer: Stopped.");
    }

    private void Register()
    {
        if (_registered) return;
        _registered = true;
        Router.UnhandledI2NpMessage += OnI2NpMessageReceived;
        Logging.LogDebug("FloodfillServer: Registered for incoming I2NP messages.");
    }

    private void Unregister()
    {
        if (!_registered) return;
        _registered = false;
        Router.UnhandledI2NpMessage -= OnI2NpMessageReceived;
        Logging.LogDebug("FloodfillServer: Unregistered from incoming I2NP messages.");
    }

    private void OnI2NpMessageReceived(Ii2NpHeader msg, InboundTunnel from)
    {
        if (!_enabled) return;

        try
        {
            var fromHash = from?.Destination;
            switch (msg.MessageType)
            {
                case I2NpMessage.MessageTypes.DatabaseLookup:
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        try
                        {
                            var lookup = (DatabaseLookupMessage)msg.Message;
                            HandleDatabaseLookup(lookup, fromHash);
                        }
                        catch (Exception ex)
                        {
                            Logging.LogDebug($"FloodfillServer: Error handling DatabaseLookup: {ex.Message}");
                        }
                    });
                    break;

                case I2NpMessage.MessageTypes.DatabaseStore:
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        try
                        {
                            var store = (DatabaseStoreMessage)msg.Message;
                            HandleDatabaseStore(store, fromHash);
                        }
                        catch (Exception ex)
                        {
                            Logging.LogDebug($"FloodfillServer: Error handling DatabaseStore: {ex.Message}");
                        }
                    });
                    break;
            }
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"FloodfillServer: Error processing I2NP message: {ex.Message}");
        }
    }

    /// <summary>
    ///     Handle a DatabaseLookup message by looking up the requested key
    ///     in the local NetDb and returning a DatabaseStoreMessage if found,
    ///     or a DatabaseSearchReply with closest floodfill routers if not found.
    /// </summary>
    /// <param name="lookup">The incoming DatabaseLookup message.</param>
    /// <param name="fromHash">The ident hash of the router that sent this message, if known.</param>
    /// <returns>A DatabaseStoreMessage with the result, or null if nothing found.</returns>
    public DatabaseStoreMessage HandleDatabaseLookup(DatabaseLookupMessage lookup, I2PIdentHash fromHash = null)
    {
        if (lookup == null) return null;

        var key = lookup.Key;
        var lookupType = lookup.LookupType;

        Logging.LogDebug($"FloodfillServer: DatabaseLookup for {key.Id32Short}, type={lookupType}");

        // Check if this is a RouterInfo lookup
        var isRouterInfoLookup = (lookupType & DatabaseLookupMessage.LookupTypes.RouterInfo) != 0;
        var isLeaseSetLookup = (lookupType & DatabaseLookupMessage.LookupTypes.LeaseSet) != 0;
        var isExploration = (lookupType & DatabaseLookupMessage.LookupTypes.Exploration) ==
                            DatabaseLookupMessage.LookupTypes.Exploration;

        // Track lookup stats (count every request regardless of whether we have the data)
        if (isLeaseSetLookup && !isRouterInfoLookup && !isExploration)
            _leaseSetLookupCounts.AddOrUpdate(key, 1, (_, c) => c + 1);
        else if (isRouterInfoLookup || isExploration)
            _routerInfoLookupCounts.AddOrUpdate(key, 1, (_, c) => c + 1);

        // Try RouterInfo first (unless specifically requesting LeaseSet only)
        if (!isLeaseSetLookup || isRouterInfoLookup || isExploration)
        {
            var routerInfo = NetDb.Inst[key];
            if (routerInfo != null)
            {
                Logging.LogDebug($"FloodfillServer: Found RouterInfo for {key.Id32Short}");

                var response = new DatabaseStoreMessage(routerInfo);
                SendReply(lookup, response);
                DatabaseLookupReceived?.Invoke(lookup, fromHash, NetDb.DatabaseLookupResult.RouterInfoFound);
                return response;
            }
        }

        // Try LeaseSet (unless specifically requesting RouterInfo only)
        if (!isRouterInfoLookup || isLeaseSetLookup)
        {
            var leaseSet = NetDb.Inst.FindLeaseSet(key);
            if (leaseSet != null)
            {
                Logging.LogDebug($"FloodfillServer: Found LeaseSet for {key.Id32Short}");

                var response = new DatabaseStoreMessage(leaseSet);
                SendReply(lookup, response);
                DatabaseLookupReceived?.Invoke(lookup, fromHash, NetDb.DatabaseLookupResult.LeaseSetFound);
                return response;
            }
        }

        // Not found: send DatabaseSearchReply with closest floodfill routers
        Logging.LogDebug($"FloodfillServer: Key {key.Id32Short} not found, sending closest floodfills");
        SendSearchReply(lookup);
        DatabaseLookupReceived?.Invoke(lookup, fromHash, NetDb.DatabaseLookupResult.ClosestFloodfillsSent);

        return null;
    }

    /// <summary>
    ///     Check if the incoming store rate exceeds the limit.
    ///     Returns true if the request should be rejected.
    /// </summary>
    private bool IsStoreRateLimited()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Periodically clean up old timestamps
        if (now - _lastRateLimitCleanup > 10000)
        {
            _lastRateLimitCleanup = now;
            var cutoff = now - RATE_LIMIT_WINDOW_MS;
            while (_storeTimestamps.TryPeek(out var oldest) && oldest < cutoff) _storeTimestamps.TryDequeue(out _);
        }

        if (_storeTimestamps.Count >= RATE_LIMIT_MAX_STORES)
        {
            // Check if the oldest entry is still within the window
            if (_storeTimestamps.TryPeek(out var oldest) && now - oldest < RATE_LIMIT_WINDOW_MS) return true;
            // Remove expired entry
            _storeTimestamps.TryDequeue(out _);
        }

        _storeTimestamps.Enqueue(now);
        return false;
    }

    /// <summary>
    ///     Handle a DatabaseStore message by storing the RouterInfo or LeaseSet
    ///     in the local NetDb, then propagating (flooding) to closest floodfill peers.
    /// </summary>
    public void HandleDatabaseStore(DatabaseStoreMessage store, I2PIdentHash from)
    {
        if (store == null) return;

        Logging.LogInformation($"FloodfillServer: HandleDatabaseStore from {from?.Id32Short ?? "unknown"}: {store.Key.Id32Short}");

        if (IsStoreRateLimited())
        {
            Logging.LogWarning(
                $"FloodfillServer: Rate limit exceeded, dropping DatabaseStore for {store.Key?.Id32Short}");
            return;
        }

        if (store.RouterInfo != null)
        {
            Logging.LogInformation($"FloodfillServer: Storing RouterInfo for {store.Key.Id32Short}");
            NetDb.Inst.AddRouterInfo(store.RouterInfo);
        }
        else if (store.LeaseSet != null)
        {
            Logging.LogInformation($"FloodfillServer: Storing LeaseSet for {store.Key.Id32Short} (Type {store.LeaseSet.MessageType})");
            NetDb.Inst.AddLeaseSet(store.LeaseSet);
        }
        else
        {
            Logging.LogDebug(
                $"FloodfillServer: DatabaseStore with no RouterInfo or LeaseSet for {store.Key.Id32Short}");
            return;
        }

        // Send delivery status acknowledgement if requested
        if (store.ReplyToken != 0) SendDeliveryStatus(store);

        // Flood propagation: forward to closest floodfill routers
        FloodToClosestPeers(store, from);
    }

    /// <summary>
    ///     Propagate a DatabaseStore to the closest floodfill routers.
    ///     This is the core flooding mechanism for the distributed hash table.
    /// </summary>
    private void FloodToClosestPeers(DatabaseStoreMessage store, I2PIdentHash from)
    {
        if (store?.Key == null) return;

        // Check if we recently flooded this key
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (_recentlyFlooded.TryGetValue(store.Key, out var lastFloodTime))
            if (now - lastFloodTime < FLOOD_EXPIRY_MS)
                return; // Already flooded recently

        _recentlyFlooded[store.Key] = now;

        // Clean up old entries periodically
        if (_recentlyFlooded.Count > 1000)
        {
            var expired = _recentlyFlooded
                .Where(kv => now - kv.Value > FLOOD_EXPIRY_MS)
                .Select(kv => kv.Key)
                .ToList();
            foreach (var k in expired)
                _recentlyFlooded.TryRemove(k, out _);
        }

        // Get closest floodfill routers to the stored key
        var myHash = RouterContext.Inst.MyRouterIdentity.IdentHash;
        var closestFf = NetDb.Inst.GetClosestFloodfill(store.Key, FLOOD_PEER_COUNT + 1, null);

        if (closestFf == null) return;

        var sent = 0;
        foreach (var peer in closestFf)
        {
            // Don't flood to ourselves
            if (peer.Equals(myHash)) continue;

            // Don't flood back to the sender
            if (from != null && peer.Equals(from)) continue;

            // Don't flood back to the reply gateway (from spec)
            if (store.ReplyGateway != null && peer.Equals(store.ReplyGateway)) continue;

            if (sent >= FLOOD_PEER_COUNT) break;

            try
            {
                TransportProvider.Send(peer, store);
                sent++;
                Logging.LogDebug($"FloodfillServer: Flooded {store.Key.Id32Short} to {peer.Id32Short}");
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"FloodfillServer: Failed to flood to {peer.Id32Short}: {ex.Message}");
            }
        }

        if (sent > 0)
            Logging.LogDebug($"FloodfillServer: Flooded {store.Key.Id32Short} to {sent} peers");
    }

    /// <summary>
    ///     Encrypt a lookup reply if the requester asked for one, and say plainly when it asked for
    ///     something we cannot give it. Returns the message to put on the wire.
    /// </summary>
    /// <remarks>
    ///     Batch 3-16 (docs/PRODUCTION-PLAN.md). <b>This router answered every DatabaseLookup in the
    ///     clear, including the ones that carried a reply key.</b> A destination looking up a
    ///     LeaseSet always asks for an encrypted reply — i2pd's <c>SendLeaseSetRequest</c>
    ///     (Destination.cpp) draws a random 32-byte key and 8-byte tag, calls
    ///     <c>AddECIESx25519Key</c> so it can decrypt the answer, and puts both in the lookup. Its
    ///     own floodfill honours that with <c>WrapECIESX25519Message (replyMsg, sessionKey, tag)</c>
    ///     (NetDb.cpp), which is byte-for-byte the one-time garlic batch 3-13 already proved
    ///     correct against i2pd for tunnel build replies — hence the shared
    ///     <see cref="TunnelProvider.CreateOneTimeGarlicMessage(I2NpMessage,byte[],byte[])" />.
    ///     <para>
    ///     i2pd will accept a cleartext DatabaseStore at a destination too
    ///     (<c>HandleCloveI2NPMessage</c> takes a null session), so this was not fatal on its own —
    ///     but it leaks to every hop of the reply tunnel which destination was asked for, which is
    ///     the entire reason the field exists. The legacy ElGamal/AES reply form is <i>not</i>
    ///     implemented; that path now says so instead of silently answering in a different
    ///     encryption than the one requested.
    ///     </para>
    /// </remarks>
    internal static I2NpMessage WrapReplyForRequester(DatabaseLookupMessage lookup, I2NpMessage reply)
    {
        var replyKey = lookup.ReplyKey;
        if (replyKey is null) return reply;

        var tag = lookup.Tags.FirstOrDefault();
        if (tag is null)
        {
            // i2pd logs exactly this case and sends the reply unencrypted.
            Logging.LogWarning(
                $"FloodfillServer: encrypted reply requested for {lookup.Key.Id32Short} but no tags provided");
            return reply;
        }

        if ((lookup.LookupType & DatabaseLookupMessage.LookupTypes.Ecies) == 0)
        {
            Logging.LogWarning(
                $"FloodfillServer: ElGamal/AES reply encryption requested for {lookup.Key.Id32Short} " +
                "and is not implemented. Replying in the clear.");
            return reply;
        }

        return TunnelProvider.CreateOneTimeGarlicMessage(
            reply,
            replyKey.Key.ToByteArray(),
            tag.Value.ToByteArray());
    }

    private void SendReply(DatabaseLookupMessage lookup, DatabaseStoreMessage response)
    {
        SendToRequester(lookup, WrapReplyForRequester(lookup, response));
    }

    private void SendToRequester(DatabaseLookupMessage lookup, I2NpMessage response)
    {
        var isTunnel = (lookup.LookupType & DatabaseLookupMessage.LookupTypes.Tunnel) != 0;

        if (isTunnel && lookup.TunnelId != null)
        {
            // Prefer sending via our own outbound tunnel
            var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(
                TunnelPoolSelection.RequireExploratory);

            if (outtunnel != null)
            {
                outtunnel.Send(new TunnelMessageRouter(
                    new TunnelGatewayMessage(response, lookup.TunnelId),
                    lookup.From));
            }
            else
            {
                // No outbound tunnel available — send TunnelGateway directly via transport.
                // The remote will inject our message into their inbound tunnel.
                Logging.LogDebug(
                    $"FloodfillServer: No outbound tunnel, sending reply directly to {lookup.From?.Id32Short}");
                TransportProvider.Send(lookup.From,
                    new TunnelGatewayMessage(response, lookup.TunnelId));
            }
        }
        else
        {
            // Reply directly to the requesting router
            TransportProvider.Send(lookup.From, response);
        }
    }

    private void SendSearchReply(DatabaseLookupMessage lookup)
    {
        var closestFf = NetDb.Inst.GetClosestFloodfill(lookup.Key, 3, null);

        if (closestFf == null || !closestFf.Any()) closestFf = NetDb.Inst.GetRandomFloodfillRouter(true, 3);

        if (closestFf == null || !closestFf.Any())
        {
            Logging.LogDebug("FloodfillServer: No floodfill routers to include in search reply");
            return;
        }

        var peers = closestFf.ToArray();
        var from = RouterContext.Inst.MyRouterIdentity.IdentHash;

        // Use the proper constructor so SetBuffer is initialized correctly.
        // Constructing from raw BufRef breaks CreateHeader16 when wrapping in TunnelGatewayMessage.
        var reply = new DatabaseSearchReplyMessage(lookup.Key, peers, from);

        // A "not found" is as much of an answer as a hit, and i2pd encrypts both — NetDb.cpp wraps
        // whatever ended up in replyMsg, DatabaseStore or DatabaseSearchReply alike.
        SendToRequester(lookup, WrapReplyForRequester(lookup, reply));
    }

    private void SendDeliveryStatus(DatabaseStoreMessage store)
    {
        var deliveryStatus = new DeliveryStatusMessage(store.ReplyToken);

        if (store.ReplyTunnelId != 0 && store.ReplyGateway != null)
        {
            // Prefer sending via our own outbound tunnel
            var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(
                TunnelPoolSelection.RequireExploratory);

            if (outtunnel != null)
            {
                outtunnel.Send(new TunnelMessageRouter(
                    new TunnelGatewayMessage(
                        deliveryStatus,
                        new I2PTunnelId(store.ReplyTunnelId)),
                    store.ReplyGateway));
            }
            else
            {
                // No outbound tunnel — send TunnelGateway directly to the reply gateway.
                // The gateway router will inject the DeliveryStatus into the specified tunnel.
                Logging.LogDebug(
                    $"FloodfillServer: No outbound tunnel, sending DeliveryStatus directly to {store.ReplyGateway?.Id32Short}");
                TransportProvider.Send(store.ReplyGateway,
                    new TunnelGatewayMessage(
                        deliveryStatus,
                        new I2PTunnelId(store.ReplyTunnelId)));
            }
        }
        else if (store.ReplyGateway != null)
        {
            TransportProvider.Send(store.ReplyGateway, deliveryStatus);
        }
    }
}