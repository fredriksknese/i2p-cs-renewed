using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using I2PCore.Client;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using static I2PCore.SessionLayer.ClientDestination;

namespace I2PCore.SessionLayer;

public static class Router
{
    private static readonly object StartedLock = new();

    private static Thread _worker;

    private static bool _terminated;

    private static readonly ConcurrentDictionary<I2PDestination, ClientDestination> RunningDestinations = new();

    // ECIES router processor for modern garlic messages (lazy-initialized after RouterContext)
    private static ECIESRouterProcessor _eciesRouterProcessor;
    public static bool Started { get; private set; }

    public static ClientTunnelProvider ClientTunnelMgr { get; private set; }

    public static TunnelPoolManager ExplorationTunnelMgr { get; private set; }

    public static TransitTunnelProvider TransitTunnelMgr { get; private set; }

    public static FloodfillServer FloodfillServer { get; private set; }

    /// <summary>
    ///     Graceful shutdown timeout - how long to wait for existing tunnels to drain.
    ///     i2pd uses up to 10 minutes; we default to 2 minutes for a reasonable balance.
    /// </summary>
    public static TimeSpan GracefulShutdownTimeout { get; set; } = TimeSpan.FromMinutes(2);

    public static ECIESRouterProcessor EciesRouterProcessor
    {
        get
        {
            if (_eciesRouterProcessor == null)
                try
                {
                    var ctx = RouterContext.Inst;
                    if (ctx?.MyRouterIdentity?.IdentHash != null)
                    {
                        // Extract X25519 static key from router context
                        // Use the last 32 bytes of the private key to match RouterContext.X25519PrivateKey
                        var privKey = ctx.PrivateKey?.ToByteArray();
                        if (privKey != null && privKey.Length >= 32)
                        {
                            var x25519Priv = new byte[32];
                            Array.Copy(privKey, privKey.Length - 32, x25519Priv, 0, 32);
                            var x25519Pub = X25519.GetPublicKey(x25519Priv);
                            _eciesRouterProcessor = new ECIESRouterProcessor(
                                ctx.MyRouterIdentity.IdentHash,
                                x25519Priv,
                                x25519Pub);
                            Logging.LogDebug(
                                $"Router: Initialized ECIES processor for {ctx.MyRouterIdentity.IdentHash}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogDebug($"Router: Failed to initialize ECIES processor: {ex.Message}");
                }

            return _eciesRouterProcessor;
        }
    }

    public static event Action<Ii2NpHeader, InboundTunnel> UnhandledI2NpMessage;

    internal static event Action<DeliveryStatusMessage, InboundTunnel> DeliveryStatusReceived;

    /// <summary>
    ///     Start the router with the current RouterContext settings.
    /// </summary>
    public static void Start()
    {
        lock (StartedLock)
        {
            if (Started) return;

            try
            {
                var rci = RouterContext.Inst;
                NetDb.Start();

                // Load peer profiles from disk
                var profilesDir = Path.Combine(RouterContext.RouterPath, "peerProfiles");
                RouterProfileManager.Instance.LoadAll(profilesDir);

                Logging.Log($"I: {RouterContext.Inst.MyRouterInfo}");
                Logging.Log($"Published: {RouterContext.Inst.Published}");

                Logging.Log("Connecting...");
                TransportProvider.Start();
                TunnelProvider.Start();

                ClientTunnelMgr = new ClientTunnelProvider(TunnelProvider.Inst);
                ExplorationTunnelMgr = new TunnelPoolManager(TunnelProvider.Inst);
                TransitTunnelMgr = new TransitTunnelProvider(TunnelProvider.Inst);

                FloodfillServer = new FloodfillServer();
                FloodfillServer.DatabaseLookupReceived += (lookup, from, result) =>
                    NetDb.Inst?.InvokeDatabaseLookupReceived(lookup, from, result);

                if (rci.FloodfillEnabled) FloodfillServer.Start();

                // Start client services and tunnels
                ClientContext.Inst.Start();

                _worker = new Thread(Run)
                {
                    Name = "Router",
                    IsBackground = true
                };
                _worker.Start();

                Subscribe();

                Started = true;
            }
            catch (Exception ex)
            {
                // Start() is not atomic. If it threw after Subscribe(), leaving the handlers
                // attached would grow the invocation list on the next attempt.
                Unsubscribe();
                Logging.Log(ex);
            }
        }
    }

    /// <summary>
    ///     Reload configuration without full restart.
    ///     Applies changes to bandwidth, floodfill mode, and logging levels.
    ///     Can be triggered by SIGHUP via DaemonHelper.OnReload().
    /// </summary>
    /// <summary>
    ///     Reload configuration without full restart.
    ///     Applies changes to bandwidth, router context, and logging levels.
    ///     Can be triggered by SIGHUP via DaemonHelper.OnReload().
    /// </summary>
    public static void ReloadConfig()
    {
        if (!Started) return;

        try
        {
            Logging.LogInformation("Router: Reloading configuration...");

            // Apply router context settings (bandwidth, ports, etc.)
            if (RouterContext.Inst != null)
            {
                RouterContext.Inst.ApplyNewSettings();
                Logging.LogInformation("Router: RouterContext settings reloaded");
            }

            // Reload logging settings
            Logging.ReadAppConfig();

            Logging.LogInformation("Router: Configuration reloaded successfully");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Router: Config reload failed: {ex.Message}");
        }
    }

    /// <summary>
    ///     Gracefully stop the router and all services.
    ///     Shutdown order: client services -> destinations -> graceful drain -> tunnels -> transports -> netdb
    /// </summary>
    public static void Stop()
    {
        lock (StartedLock)
        {
            if (!Started) return;

            Logging.LogInformation("Router: Stopping...");
            _terminated = true;

            try
            {
                // 1. Stop client services first (SAM, proxies, etc.)
                try
                {
                    ClientContext.Inst?.Stop();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Router: Error stopping client services: {ex.Message}");
                }

                // 2. Save peer profiles to disk
                try
                {
                    var profilesDir = Path.Combine(RouterContext.RouterPath, "peerProfiles");
                    RouterProfileManager.Instance.SaveAll(profilesDir);
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Router: Error saving profiles: {ex.Message}");
                }

                // 3. Stop all running destinations (no new outbound traffic)
                foreach (var kvp in RunningDestinations.ToArray())
                    try
                    {
                        kvp.Value.Shutdown();
                    }
                    catch
                    {
                    }

                RunningDestinations.Clear();

                // 5. Graceful tunnel drain - wait for existing tunnels to expire
                var drainMs = (int)GracefulShutdownTimeout.TotalMilliseconds;
                if (drainMs > 0)
                {
                    Logging.LogInformation(
                        $"Router: Waiting up to {GracefulShutdownTimeout.TotalSeconds}s for tunnel drain...");

                    var drainStart = DateTime.UtcNow;
                    while (DateTime.UtcNow - drainStart < GracefulShutdownTimeout)
                    {
                        var transitCount = TransitTunnelMgr?.TransitTunnelCount ?? 0;
                        if (transitCount == 0) break;

                        Logging.LogDebug($"Router: Draining {transitCount} transit tunnels...");
                        Thread.Sleep(Math.Min(5000, drainMs));
                    }
                }

                // 6. Wait for worker thread
                _worker?.Join(10000);

                // 6b. Detach event handlers while NetDb.Inst is still alive to detach from.
                Unsubscribe();

                // 7. Stop transport layer
                try
                {
                    TransportProvider.Stop();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Router: Error stopping transports: {ex.Message}");
                }

                // 8. Stop tunnel provider
                try
                {
                    TunnelProvider.Stop();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Router: Error stopping tunnels: {ex.Message}");
                }

                // 9. Stop network database
                try
                {
                    NetDb.Stop();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Router: Error stopping NetDb: {ex.Message}");
                }

                // 9b. Stop the DH key pair precalculation thread. It is started lazily on first
                // use and used to run until process exit, so a host that embeds I2PCore could not
                // get the thread back after Stop().
                try
                {
                    I2PPrivateKey.StopPrecalculation();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Router: Error stopping key precalculation: {ex.Message}");
                }

                // 10. Reset router context for re-startability
                try
                {
                    RouterContext.Reset();
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Router: Error resetting context: {ex.Message}");
                }

                // Clear references
                ClientTunnelMgr = null;
                ExplorationTunnelMgr = null;
                TransitTunnelMgr = null;
                FloodfillServer = null;

                // Step 10 called RouterContext.Reset(), so this router has a new identity and new
                // keys. The ECIES processor is built lazily from RouterContext and cached forever;
                // left alone it survives the restart still bound to the *previous* identity, and
                // silently fails to decrypt every router-level garlic message addressed to the new
                // one. Dropping it makes the next access rebuild against the current context.
                _eciesRouterProcessor = null;

                // Callbacks registered against the old NetDb will never fire now that its lookup
                // handlers are detached; keeping them leaks one entry per unresolved lookup per
                // restart, and would deliver a stale destination if a new lookup reused the hash.
                lock (UnresolvedDestinations)
                {
                    UnresolvedDestinations.Clear();
                }

                _terminated = false;

                Started = false;
                Logging.LogInformation("Router: Stopped.");
            }
            catch (Exception ex)
            {
                Logging.Log("Router: Stop failed", ex);
            }
        }
    }

    private static readonly PeriodicAction ProfileCleanup = new(TickSpan.Minutes(10));

    // Batch 2-1 (docs/PRODUCTION-PLAN.md): every event this class subscribes to is attached here
    // and detached in Unsubscribe(), so the pairing can be checked by reading two adjacent
    // methods. Previously the subscriptions were split -- I2NpMessageReceived was attached in
    // Run() and never detached at all, while the NetDb handlers were attached in Start() and
    // detached in Run()'s finally. Router is static, so the leaked handler survived Stop() and
    // the invocation list grew by one per Start/Stop cycle, delivering every I2NP message to as
    // many stale handlers as there had been restarts.
    private static void Subscribe()
    {
        TunnelProvider.I2NpMessageReceived += HandleI2NpMessageReceived;

        var lookup = NetDb.Inst?.IdentHashLookup;
        if (lookup == null) return;

        lookup.LeaseSetReceived += IdentHashLookup_LeaseSetReceived;
        lookup.LookupFailure += IdentHashLookup_LookupFailure;
    }

    /// <summary>
    ///     Safe to call when nothing is subscribed: removing an absent delegate is a no-op.
    /// </summary>
    private static void Unsubscribe()
    {
        TunnelProvider.I2NpMessageReceived -= HandleI2NpMessageReceived;

        var lookup = NetDb.Inst?.IdentHashLookup;
        if (lookup == null) return;

        lookup.LeaseSetReceived -= IdentHashLookup_LeaseSetReceived;
        lookup.LookupFailure -= IdentHashLookup_LookupFailure;
    }

    private static void Run()
    {
        try
        {
            Thread.Sleep(2000);

            while (!_terminated)
                try
                {
                    ClientTunnelMgr.Execute();
                    ExplorationTunnelMgr.Execute();
                    TransitTunnelMgr.Execute();

                    ProfileCleanup.Do(() => RouterProfileManager.Instance.Cleanup());

                    Thread.Sleep(500);
                }
                catch (ThreadAbortException ex)
                {
                    Logging.Log(ex);
                }
                catch (Exception ex)
                {
                    Logging.Log(ex);
                }
        }
        finally
        {
            _terminated = true;
        }
    }

    /// <summary>
    ///     Create the destination. New lease sets will be automatically signed
    ///     with the key in I2PDestinationInfo.
    /// </summary>
    /// <returns>The destination.</returns>
    /// <param name="destinfo">Destinfo.</param>
    /// <param name="publish">If set to <c>true</c> publish.</param>
    /// <param name="alreadyrunning">If set to <c>true</c> alreadyrunning.</param>
    public static ClientDestination CreateDestination(
        I2PDestinationInfo destinfo,
        bool publish,
        out bool alreadyrunning)
    {
        lock (RunningDestinations)
        {
            if (RunningDestinations.TryGetValue(destinfo.Destination, out var runninginst))
            {
                alreadyrunning = true;
                return runninginst;
            }

            var newclient = new ClientDestination(destinfo, publish);
            RunningDestinations[destinfo.Destination] = newclient;
            ClientTunnelMgr.AttachClient(newclient);
            alreadyrunning = false;
            return newclient;
        }
    }

    /// <summary>
    ///     Creates the destination without a private key for signing lease sets.
    ///     Using this constructor you have to subsribe to SignLeasesRequest events
    ///     and sign new lease sets, and update PrivateKeys as needed.
    /// </summary>
    /// <returns>The destination.</returns>
    /// <param name="dest">Destination.</param>
    /// <param name="publish">If set to <c>true</c> publish.</param>
    /// <param name="alreadyrunning">If set to <c>true</c> alreadyrunning.</param>
    public static ClientDestination CreateDestination(
        I2PDestination dest,
        bool publish,
        out bool alreadyrunning)
    {
        lock (RunningDestinations)
        {
            if (RunningDestinations.TryGetValue(dest, out var runninginst))
            {
                alreadyrunning = true;
                return runninginst;
            }

            var newclient = new ClientDestination(dest, publish);
            RunningDestinations[dest] = newclient;
            ClientTunnelMgr.AttachClient(newclient);
            alreadyrunning = false;
            return newclient;
        }
    }

    internal static void ShutdownClient(ClientDestination dest)
    {
        ClientTunnelMgr.DetachClient(dest);
        RunningDestinations.TryRemove(dest.Destination, out _);
    }

    public static ClientDestination GetClientDestination(I2PIdentHash hash)
    {
        var local = ClientDestination.AllDestinations.Keys.FirstOrDefault(d => d.Destination.IdentHash == hash);
        if (local != null) return local;

        // Fallback: check if hash is a temporary IdentHash (literal X25519 static key)
        return FindLocalDestinationByStaticKey(hash.Hash.ToByteArray());
    }

    public static ClientDestination FindLocalDestinationByStaticKey(byte[] staticPublicKey)
    {
        if (staticPublicKey == null || staticPublicKey.Length != 32) return null;

        return ClientDestination.AllDestinations.Keys.FirstOrDefault(d =>
        {
            var keys = d.MySessions?.PublicKeys;
            return keys != null && keys.Any(k =>
                (k.Certificate.PublicKeyType == I2PKeyType.KeyTypes.X25519 ||
                 k.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
                 k.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
                 k.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519) &&
                k.ToByteArray().SequenceEqual(staticPublicKey));
        });
    }

    internal static void HandleI2NpMessageReceived(Ii2NpHeader msg, InboundTunnel from)
    {
        switch (msg.MessageType)
        {
            case I2NpMessage.MessageTypes.DatabaseStore:
                var ds = (DatabaseStoreMessage)msg.Message;
#if LOG_ALL_TUNNEL_TRANSFER
                    Logging.Log( $"Router: DatabaseStore : {ds.Key.Id32Short}" );
#endif
                HandleDatabaseStore(ds, from);
                break;

            case I2NpMessage.MessageTypes.DatabaseSearchReply:
                var dsr = (DatabaseSearchReplyMessage)msg.Message;
#if LOG_ALL_TUNNEL_TRANSFER
                    Logging.Log( $"Router: DatabaseSearchReply: {dsr}" );
#endif
                NetDb.Inst.AddDatabaseSearchReply(dsr);
                break;

            case I2NpMessage.MessageTypes.DeliveryStatus:
#if LOG_ALL_TUNNEL_TRANSFER || LOG_ALL_LEASE_MGMT
                    Logging.LogDebug( $"Router: DeliveryStatus: {msg.Message}" );
#endif

                var dsmsg = (DeliveryStatusMessage)msg.Message;
                DeliveryStatusReceived?.Invoke(dsmsg, from);
                break;

            case I2NpMessage.MessageTypes.Garlic:
#if LOG_ALL_TUNNEL_TRANSFER
                    Logging.LogDebug( $"Router: Garlic: {msg.Message}" );
#endif
                HandleGarlic((GarlicMessage)msg.Message, from);
                break;

            case I2NpMessage.MessageTypes.VariableTunnelBuildReply:
#if LOG_ALL_TUNNEL_TRANSFER
                    Logging.LogDebug( $"{this}: VariableTunnelBuildReply: {msg}" );
#endif
                ThreadPool.QueueUserWorkItem(cb =>
                    TunnelProvider.Inst.HandleVariableTunnelBuildReply((VariableTunnelBuildReplyMessage)msg.Message));
                break;

            case I2NpMessage.MessageTypes.ShortTunnelBuildReply:
#if LOG_ALL_TUNNEL_TRANSFER
                    Logging.LogDebug( $"{this}: ShortTunnelBuildReply: {msg}" );
#endif
                ThreadPool.QueueUserWorkItem(cb =>
                    TunnelProvider.Inst.HandleShortTunnelBuildReply((ShortTunnelBuildReplyMessage)msg.Message));
                break;

            case I2NpMessage.MessageTypes.DatabaseLookup:
                var dlm = (DatabaseLookupMessage)msg.Message;
                HandleDatabaseLookup(dlm, from);
                break;

            default:
                if (UnhandledI2NpMessage is null)
                    Logging.LogDebug($"Router: I2NPMessageReceived: Unhandled message ({msg.Message})");
                else
                    ThreadPool.QueueUserWorkItem(a => UnhandledI2NpMessage?.Invoke(msg, from));
                break;
        }
    }

    internal static void HandleDatabaseStore(DatabaseStoreMessage ds, InboundTunnel from)
    {
        if (RouterContext.Inst.FloodfillEnabled && FloodfillServer != null)
        {
            FloodfillServer.HandleDatabaseStore(ds, from?.Destination);
            return;
        }

        if (ds?.RouterInfo == null && ds?.LeaseSet == null)
        {
            Logging.LogDebug("DatabaseStore without Router or Lease info!");
            return;
        }

        if (ds.RouterInfo != null)
        {
#if LOG_ALL_TUNNEL_TRANSFER
                Logging.Log( $"HandleDatabaseStore: DatabaseStore RouterInfo {ds}" );
#endif
            // var stat = NetDb.Inst.Statistics[ds.RouterInfo.Identity.IdentHash];
            // if ( stat == null || !NetDb.Inst.Statistics.NodeInactive( stat ) )
            {
                NetDb.Inst.AddRouterInfo(ds.RouterInfo);
            }
        }
        else
        {
#if LOG_ALL_TUNNEL_TRANSFER
                Logging.Log( $"HandleDatabaseStore: DatabaseStore LeaseSet {ds}" );
#endif
            NetDb.Inst.AddLeaseSet(ds.LeaseSet);
        }

        if (ds.ReplyToken != 0 && from == null)
        {
            if (ds.ReplyTunnelId != 0)
            {
                var outtunnel =
                    TunnelProvider.Inst.GetEstablishedOutboundTunnel(TunnelPoolSelection.RequireExploratory);
                if (outtunnel != null)
                    outtunnel.Send(new TunnelMessageRouter(
                        new TunnelGatewayMessage(
                            new DeliveryStatusMessage(ds.ReplyToken),
                            ds.ReplyTunnelId),
                        ds.ReplyGateway));
            }
            else
            {
                TransportProvider.Send(ds.ReplyGateway,
                    new DeliveryStatusMessage(ds.ReplyToken));
            }
        }
    }

    /// <summary>
    ///     Handle incoming DatabaseLookup messages for non-floodfill routers.
    ///     Returns closest known floodfill routers as a DatabaseSearchReply.
    /// </summary>
    internal static void HandleDatabaseLookup(DatabaseLookupMessage dlm, InboundTunnel from)
    {
        if (RouterContext.Inst.FloodfillEnabled && FloodfillServer != null)
        {
            FloodfillServer.HandleDatabaseLookup(dlm, from?.Destination);
            return;
        }

        if (dlm?.Key == null || dlm.From == null) return;

        Logging.LogDebug($"Router: DatabaseLookup for {dlm.Key.Id32Short}");

        // For non-floodfill routers, respond with closest known floodfills
        var closestFloodfills = NetDb.Inst?.GetClosestFloodfill(
            dlm.Key, 3,
            null) ?? Array.Empty<I2PIdentHash>();

        var reply = new DatabaseSearchReplyMessage(
            dlm.Key,
            closestFloodfills,
            RouterContext.Inst.MyRouterIdentity.IdentHash);

        // Send reply back through the reply tunnel if specified (Tunnel flag set)
        if ((dlm.LookupType & DatabaseLookupMessage.LookupTypes.Tunnel) != 0
            && dlm.TunnelId != null)
        {
            var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel(
                TunnelPoolSelection.RequireExploratory);

            if (outtunnel != null)
                outtunnel.Send(new TunnelMessageRouter(
                    new TunnelGatewayMessage(reply, dlm.TunnelId),
                    dlm.From));
        }
        else
        {
            TransportProvider.Send(dlm.From, reply);
        }
    }

    private static void HandleGarlic(GarlicMessage garlicmsg, InboundTunnel from)
    {
        try
        {
            // Try tunnel build reply garlic first (matched by tag)
            if (TunnelProvider.Inst.TryHandleBuildReplyGarlic(garlicmsg, from))
                return;

            // Try ECIES decryption first (modern path)
            if (TryHandleECIESGarlic(garlicmsg, from))
                return;

            // Fallback: Try all client destinations.
            // Use suppressTunnelPageLog because most messages here are
            // router-level garlic (build replies, NetDB) that can't be
            // decrypted by a client SKM — logging every attempt is noise.
            foreach (var dest in AllDestinations.Keys)
                try
                {
                    var decr = dest.MySessions.DecryptMessage(garlicmsg, suppressTunnelPageLog: true);
                    if (decr != null)
                    {
                        var cloveTypes = string.Join(", ", decr.Cloves.Select(c => c.Message?.GetType().Name ?? "?"));
                        dest.Log("Decrypted", $"Garlic decrypted: {decr.Cloves.Count} cloves [{cloveTypes}]",
                            decr.RemoteHash?.Id32Short);
                        Logging.LogDebug(
                            $"Router: Garlic decrypted by client destination {dest.Destination.IdentHash.Id32Short}");
                        dest.HandleDecryptedGarlic(decr, from);
                        return;
                    }
                }
                catch
                {
                    /* ignore */
                }

            // Fall back to ElGamal (legacy path)
            GarlicAesBlock aesblock;
            try
            {
                (aesblock, _) = Garlic.EgDecryptGarlic(
                    garlicmsg,
                    RouterContext.Inst.PrivateKey);
            }
            catch (ChecksumFailureException)
            {
                // Expected if it was actually an unsupported ECIES message or just invalid data
                return;
            }
            catch (ArgumentException)
            {
                // Likely data length mismatch for ElGamal
                return;
            }

            if (aesblock == null) return;

            var garlic = new Garlic(new I2PBufferCursor(aesblock.Payload));
            ProcessGarlicCloves(garlic, from);
        }
        catch (Exception ex)
        {
            Logging.Log("Router: HandleGarlic", ex);
        }
    }

    private static void ProcessGarlicCloves(Garlic garlic, InboundTunnel from)
    {
#if LOG_ALL_LEASE_MGMT
            Logging.LogDebug( $"Router: ProcessGarlicCloves: {garlic}" );
#endif
        foreach (var clove in garlic.Cloves)
            try
            {
                switch (clove.Delivery.Delivery)
                {
                    case GarlicCloveDelivery.DeliveryMethod.Local:
                        Logging.LogDebug(
                            $"Router: ProcessGarlicCloves: Delivered Local: {clove.Message}");

                        TunnelProvider.Inst.HandleIncomingMessage(clove.Message.CreateHeader16, from);
                        break;

                    default:
                        Logging.LogDebug($"Router: ProcessGarlicCloves: Dropped clove ({clove})");
                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.Log("Router: ProcessGarlicCloves switch", ex);
            }
    }

    /// <summary>
    ///     Try to handle a garlic message using ECIES decryption.
    ///     Returns true if successfully handled, false if should fall back to ElGamal.
    /// </summary>
    private static bool TryHandleECIESGarlic(GarlicMessage garlicmsg, InboundTunnel from)
    {
        try
        {
            var egdata = garlicmsg.EgData;
            if (egdata.IsEmpty || egdata.Length < ECIESExistingSessionMessage.MinimumSize)
                return false;
            var data = egdata.ToByteArray();

            var ecies = EciesRouterProcessor;
            if (ecies == null) return false;

            var result = ecies.ProcessMessage(data);
            if (result == null || result.Payload == null)
                return false;

            Logging.LogDebug("Router: HandleGarlic: ECIES decryption successful");

            // Parse ECIES blocks and process garlic cloves
            // For router-level garlic, we process the payload as ECIES block format
            // which contains I2NP blocks, garlic blocks, etc.
            var blocks = ECIESBlockFormat.ParseBlocks(result.Payload);

            foreach (var block in blocks)
                try
                {
                    if (block is GarlicCloveBlock garlicClove)
                    {
                        var cloveBuf = new I2PBufferCursor(garlicClove.Data);
                        var di = GarlicCloveDelivery.CreateGarlicCloveDelivery(cloveBuf);

                        // ECIES Garlic Message format: type(1) + ID(4) + expiration(4) + payload
                        var msgType = (I2NpMessage.MessageTypes)cloveBuf.ReadByte();
                        var msgId = cloveBuf.ReadUInt32BigEndian();
                        var expirationSeconds = cloveBuf.ReadUInt32BigEndian();

                        // I2NpUtil.GetMessage requires 16 bytes of headroom in front of the payload buffer.
                        var payloadWithHeadroom = new byte[cloveBuf.Remaining + 16];
                        cloveBuf.ReadBytes(payloadWithHeadroom, 16, cloveBuf.Remaining);
                        var msg = I2NpUtil.GetMessage(msgType, new I2PBufferCursor(payloadWithHeadroom, 16), msgId);

                        if (msg != null)
                        {
                            msg.Expiration = new I2PDate((ulong)expirationSeconds * 1000);
                            TunnelProvider.Inst.HandleIncomingMessage(msg.CreateHeader16, from);
                        }
                    }
                    else if (block is NextKeyBlock nextKey)
                    {
                        Logging.LogDebug(
                            $"Router: ECIES NextKey block: keyID={nextKey.KeyID}, reverse={nextKey.IsReverseKey}, keyPresent={nextKey.IsKeyPresent}");
                        // Forward NextKey to the ECIES processor for ratchet advancement
                        ecies.HandleNextKey(nextKey);
                    }
                    else if (block is AckBlock ack)
                    {
                        Logging.LogDebug($"Router: ECIES Ack block: {ack.Acks.Count} acks");
                    }
                }
                catch (Exception ex)
                {
                    Logging.Log("Router: HandleGarlic ECIES block", ex);
                }

            return true;
        }
        catch (Exception)
        {
            // ECIES decryption failed - not an ECIES message, try EG
            return false;
        }
    }

    #region DestLookup

    private class DestinationLookupEntry
    {
        public DestinationLookupResult Callback;
        public I2PIdentHash Id;
        public object Tag;
    }

    private static readonly List<DestinationLookupEntry> UnresolvedDestinations = new();

    internal static bool StartDestLookup(
        I2PIdentHash hash,
        DestinationLookupResult cb,
        object tag,
        ClientDestination clientContext = null)
    {
        var result = NetDb.Inst.IdentHashLookup.LookupLeaseSet(hash, clientContext);

        if (result)
            lock (UnresolvedDestinations)
            {
                UnresolvedDestinations.Add(new DestinationLookupEntry
                {
                    Id = hash,
                    Callback = cb,
                    Tag = tag
                });
            }

        return result;
    }

    public static void LookupDestination(
        I2PIdentHash hash,
        DestinationLookupResult cb,
        object tag = null)
    {
        if (cb == null) return;
        StartDestLookup(hash, cb, tag);
    }

    private static void IdentHashLookup_LookupFailure(I2PIdentHash key)
    {
        lock (UnresolvedDestinations)
        {
            var cbs = UnresolvedDestinations
                .Where(e => e.Id == key)
                .ToArray();

            foreach (var cbe in cbs)
                if (UnresolvedDestinations.Remove(cbe))
                    ThreadPool.QueueUserWorkItem(a =>
                        cbe.Callback.Invoke(cbe.Id, null, cbe.Tag));
        }
    }

    private static void IdentHashLookup_LeaseSetReceived(ILeaseSet ls)
    {
        var key = ls.Destination.IdentHash;

        lock (UnresolvedDestinations)
        {
            var cbs = UnresolvedDestinations
                .Where(e => e.Id == key)
                .ToArray();

            foreach (var cbe in cbs)
                if (UnresolvedDestinations.Remove(cbe))
                    ThreadPool.QueueUserWorkItem(a =>
                        cbe.Callback.Invoke(cbe.Id, ls, cbe.Tag));
        }
    }

    #endregion
}