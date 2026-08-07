using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer.NTCP2;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using static I2PCore.Utils.BufUtils;

namespace I2PCore.TransportLayer;

public class TransportProvider
{
    protected static Thread Worker;

    public static readonly TickSpan ExeptionHistoryLifetime = TickSpan.Minutes(20);

    private static readonly object TransportSelectionLock = new();

    private readonly PeriodicAction ActiveConnectionLog = new(TickSpan.Seconds(15));

    private readonly Dictionary<IPAddress, ExceptionHistoryInstance> AddressesWithExceptions = new();

    private readonly UnknownRouterQueue CurrentlyUnknownRouters;

    private readonly UnresolvableRouters CurrentlyUnresolvableRouters = new();
    private readonly PeriodicAction DropOldExceptions = new(ExeptionHistoryLifetime);

    private readonly ITransportProtocol[] TransportProtocols;


    public ConcurrentDictionary<I2PIdentHash, EstablishedTransportInfo> EstablishedTransports = new();

    private bool Terminated;

    private TransportProvider()
    {
        CurrentlyUnknownRouters = new UnknownRouterQueue(CurrentlyUnresolvableRouters);

        TransportProtocols = GetTransportProtocols();

        Worker = new Thread(Run)
        {
            Name = "TransportProvider",
            IsBackground = true
        };
        Worker.Start();
    }

    public static TransportProvider Inst { get; protected set; }
    public int CurrentlyUnresolvableRoutersCount => CurrentlyUnresolvableRouters.Count;
    public int CurrentlyUnknownRoutersCount => CurrentlyUnknownRouters.Count;
    public int AddressesWithExceptionsCount => AddressesWithExceptions.Count;

    public int ConnectedRoutersCount
    {
        get { return EstablishedTransports.Count(t => t.Value.IsEstablished); }
    }

    public int SsuHostBlockedIpCount
    {
        get { return TransportProtocols.Sum(tp => tp.BlockedRemoteAddressesCount); }
    }

    /// <summary>Session counts by protocol for web console display.</summary>
    public int Ntcp2SessionCount
    {
        get
        {
            var counts = GetConnectionCountsByProtocol();
            return counts.TryGetValue("NTCP2", out var c) ? c : 0;
        }
    }

    public int Ntcp2ConnectingCount
    {
        get
        {
            return EstablishedTransports.Count(t =>
                t.Value.Transport?.Protocol == "NTCP2" && !t.Value.IsEstablished && !t.Value.Transport.IsTerminated);
        }
    }

    public int Ssu2SessionCount
    {
        get
        {
            var counts = GetConnectionCountsByProtocol();
            return counts.TryGetValue("SSU2", out var c) ? c : 0;
        }
    }

    public int Ssu2ConnectingCount
    {
        get
        {
            return EstablishedTransports.Count(t =>
                t.Value.Transport?.Protocol == "SSU2" && !t.Value.IsEstablished && !t.Value.Transport.IsTerminated);
        }
    }

    public int Ntcp2BlockedCount
    {
        get
        {
            return TransportProtocols
                .Where(tp => tp.GetType().Name.Contains("NTCP2"))
                .Sum(tp => tp.BlockedRemoteAddressesCount);
        }
    }

    public int Ssu2BlockedCount
    {
        get
        {
            return TransportProtocols
                .Where(tp => tp.GetType().Name.Contains("SSU2"))
                .Sum(tp => tp.BlockedRemoteAddressesCount);
        }
    }

    /// <summary>
    ///     Raised for every I2NP message arriving on any transport.
    ///     <para>
    ///         Handlers must be thread-safe and non-blocking: they are invoked concurrently from
    ///         whichever transport receive thread took the message, and anything slow here stalls
    ///         that peer's receive loop. Queue and return.
    ///     </para>
    /// </summary>
    public event Action<ITransport, Ii2NpHeader> IncomingMessage;

    public static void Start()
    {
        if (Inst != null) return;
        Inst = new TransportProvider();
    }

    /// <summary>
    ///     Signal the transport provider to stop accepting connections
    ///     and terminate its worker thread.
    /// </summary>
    public static void Stop()
    {
        var inst = Inst;
        if (inst == null) return;

        inst.Terminated = true;
        Worker?.Join(5000);

        // Batch 2-6: each protocol host owns a listener socket and a worker thread. Nothing used
        // to shut them down -- Terminate() was implemented on both hosts but absent from
        // ITransportProtocol -- so every Start/Stop cycle abandoned one live NTCP2 listener.
        foreach (var protocol in inst.TransportProtocols)
            try
            {
                protocol.Terminate();
            }
            catch (Exception ex)
            {
                Logging.LogWarning(
                    $"TransportProvider: Error terminating {protocol.GetType().Name}: {ex.Message}");
            }

        Inst = null;
    }

    public byte[] GetNTCP2StaticPrivateKey()
    {
        var ntcp2 = TransportProtocols
                .FirstOrDefault(tp => tp.GetType().Name.Contains("NTCP2"))
            as NTCP2Host;
        return ntcp2?.GetStaticPrivateKey();
    }

    public byte[] GetNTCP2StaticPublicKey()
    {
        var ntcp2 = TransportProtocols
                .FirstOrDefault(tp => tp.GetType().Name.Contains("NTCP2"))
            as NTCP2Host;
        return ntcp2?.GetStaticPublicKey();
    }

    public Dictionary<string, int> GetConnectionCountsByProtocol()
    {
        var et = EstablishedTransports.ToArray();
        var established =
            et.Where(t => t.Value?.Transport != null && t.Value.IsEstablished && !t.Value.Transport.IsTerminated)
                .ToArray();

        return established
            .GroupBy(t => t.Value.Transport.Protocol)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    public IEnumerable<I2PIdentHash> GetConnectedRouterHashes()
    {
        return EstablishedTransports
            .Where(t => t.Value?.Transport != null && t.Value.IsEstablished && !t.Value.Transport.IsTerminated)
            .Select(t => t.Key);
    }

    public bool IsRouterConnected(I2PIdentHash hash, out string protocol)
    {
        protocol = string.Empty;
        if (EstablishedTransports.TryGetValue(hash, out var info) &&
            info?.Transport != null &&
            info.IsEstablished &&
            !info.Transport.IsTerminated)
        {
            protocol = info.Transport.Protocol;
            return true;
        }

        return false;
    }

    private void Run()
    {
        try
        {
            foreach (var tp in TransportProtocols) tp.ConnectionCreated += TransportProtocol_ConnectionCreated;

            while (!Terminated)
                try
                {
                    Thread.Sleep(1000);

                    var known = CurrentlyUnknownRouters.FindKnown();
                    foreach (var found in known)
                    foreach (var msg in found.Messages)
                    {
                        Logging.LogTransport(
                            $"TransportProvider: Destination {found.Destination.Id32Short} found. Sending data.");
                        Send(found.Destination, msg);
                    }

                    // Tick all established transports every second
                    var et_all = EstablishedTransports.ToArray();
                    foreach (var info in et_all)
                        if (info.Value.IsEstablished && !info.Value.Transport.IsTerminated)
                            try
                            {
                                info.Value.Transport.Tick();
                            }
                            catch (Exception ex)
                            {
                                Logging.LogDebug(
                                    $"TransportProvider: Tick failed for {info.Value.Transport.DebugId}: {ex.Message}");
                            }

                    ActiveConnectionLog.Do(() =>
                    {
                        if (Logging.LogLevel > Logging.LogLevels.Information) return;

                        var et = EstablishedTransports.ToArray();

                        var protocols = et
                            .GroupBy(t => t.Value.Transport.Protocol)
                            .ToArray();

                        foreach (var proto in protocols)
                        {
                            var line = new StringBuilder("TransportProvider: Established out / Established in");
                            line.Append(
                                $", {proto.Key,10}: {proto.Count(t => t.Value.IsEstablished && t.Value.Transport.IsOutgoing),3} ({proto.Count(t => t.Value.Transport.IsOutgoing),3}) / " +
                                $"{proto.Count(t => t.Value.IsEstablished && !t.Value.Transport.IsOutgoing),3} ({proto.Count(t => !t.Value.Transport.IsOutgoing),3})");
#if DEBUG
                            line.Append(
                                $", send / recv " +
                                $"{BytesToReadable(proto.Sum(t => t.Value.Transport.BytesSent)),12} / " +
                                $"{BytesToReadable(proto.Sum(t => t.Value.Transport.BytesReceived)),12}");
#endif
                            Logging.LogInformation(line.ToString());
                        }
                    });

                    DropOldExceptions.Do(delegate
                    {
                        lock (AddressesWithExceptions)
                        {
                            var remove = AddressesWithExceptions.Where(eh =>
                                    eh.Value.Generated.DeltaToNow > ExeptionHistoryLifetime)
                                .Select(eh => eh.Key)
                                .ToArray();

                            foreach (var one in remove) AddressesWithExceptions.Remove(one);
                        }
                    });
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
            Terminated = true;
        }
    }

    private ITransportProtocol[] GetTransportProtocols()
    {
        var protocols = AppDomain.CurrentDomain
            .GetAssemblies()
            .SelectMany(a => a.GetTypes()
                .Where(t => t.IsDefined(
                                typeof(TransportProtocolAttribute),
                                false)
                            && typeof(ITransportProtocol).IsAssignableFrom(t)));

        return protocols
            .Select(Activator.CreateInstance)
            .Cast<ITransportProtocol>()
            .ToArray();
    }

    private void Remove(ITransport instance)
    {
        if (instance == null) return;

        var match = EstablishedTransports
            .Where(t => t.Value.Transport == instance)
            .ToArray();

        foreach (var t in match)
            if (EstablishedTransports.TryRemove(t.Key, out var removed))
                Logging.LogTransport(
                    $"TransportProvider Remove: {removed}");

        instance.Terminate("Removed from TransportProvider");
    }

    public void Disconnect(I2PIdentHash dest)
    {
        var t = GetEstablishedTransport(dest, false);
        if (t == null) return;

        t.Terminate("Manual disconnect");
    }

    // Batch 2-4 (docs/PRODUCTION-PLAN.md). This method used to hold one instance-wide lock
    // (TsSearchLock) across CreateTransport(), which connects a socket and starts a handshake.
    // Every send goes through here for its cache lookup, so a single slow or unreachable peer
    // -- a TCP connect to a dead address, a DNS lookup -- blocked *all* outbound traffic for the
    // duration, including sends to peers already connected.
    //
    // The cache lookup now takes no lock at all: EstablishedTransports is a ConcurrentDictionary.
    // The lock's only other job was stopping two threads from opening two connections to the same
    // peer, which a per-destination Lazy does better -- concurrent callers for one destination
    // share a single connect, and callers for different destinations no longer wait on each other.
    private readonly ConcurrentDictionary<I2PIdentHash, Lazy<ITransport>> PendingConnects = new();

    protected ITransport GetEstablishedTransport(I2PIdentHash dest, bool create)
    {
        if (EstablishedTransports.TryGetValue(dest, out var result))
        {
            if (result == null)
            {
                Logging.LogTransport(
                    $"TransportProvider: GetEstablishedTransport: WARNING! " +
                    $"EstablishedTransports contains null ref for {dest.Id32Short}!");
                return null;
            }

            return result.Transport;
        }

        if (!create) return null;

        // ExecutionAndPublication: exactly one thread runs the factory, the rest block on its
        // result rather than starting connects of their own.
        var pending = PendingConnects.GetOrAdd(
            dest,
            d => new Lazy<ITransport>(() => Connect(d), LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            return pending.Value;
        }
        finally
        {
            // Lazy caches a thrown exception forever, so the entry must go either way or the
            // peer would be permanently unreachable after one failed connect.
            PendingConnects.TryRemove(dest, out _);
        }
    }

    private ITransport Connect(I2PIdentHash dest)
    {
        var ri = NetDb.Inst[dest];
        if (ri == null) return null;

        if (ri.Identity.IdentHash != dest)
            throw new ArgumentException($"NetDb mismatch. Search for " +
                                        $"{dest.Id32} returns {ri.Identity.IdentHash.Id32}");

        // CreateTransport -> AddTransport puts the result in EstablishedTransports and hooks its
        // events, so nothing further is needed here.
        return CreateTransport(ri);
    }

    public ITransport GetTransport(I2PIdentHash dest)
    {
        return GetEstablishedTransport(dest, true);
    }

    public ITransport GetActiveTransport(I2PIdentHash dest)
    {
        if (EstablishedTransports.TryGetValue(dest, out var info) &&
            info?.Transport != null &&
            info.IsEstablished &&
            !info.Transport.IsTerminated)
            return info.Transport;
        return null;
    }

    private AddressFamily GetAddressFamiliy(I2PRouterAddress addr, string option)
    {
        if (!addr.Options.Contains(option)) return AddressFamily.Unknown;
        return I2PRouterAddress.IpTestHostName(addr.Options[option]);
    }

    private ITransport CreateTransport(I2PRouterInfo ri)
    {
        ITransport transport = null;

        try
        {
            var pproviders = TransportProtocols
                .Select(tp => new
                {
                    Provider = tp,
                    Capability = tp.ContactCapability(ri)
                })
                .Where(tp => tp.Capability != ProtocolCapabilities.None)
                // Filter out SSU2 if disabled
                .Where(tp => RouterContext.Inst.EnableSSU2 || tp.Provider.GetType().Name != "SSU2Host")
                .GroupBy(tp => tp.Capability)
                .OrderByDescending(cc => (int)cc.Key);

            var pprovider = pproviders.FirstOrDefault()?.Random();

            if (pprovider == null)
            {
                Logging.LogTransport(
                    $"TransportProvider: CreateTransport: No usable address found for {ri.Identity.IdentHash.Id32Short}!");

                NetDb.Inst.Statistics.FailedToConnect(ri.Identity.IdentHash);
                return null;
            }

            Logging.LogTransport($"TransportProvider: Creating new {pprovider} to {ri.Identity.IdentHash.Id32Short}");
            transport = pprovider.Provider.AddSession(ri);

            if (transport == null)
            {
                Logging.LogTransport(
                    $"TransportProvider: AddSession returned null for {ri.Identity.IdentHash.Id32Short}");
                NetDb.Inst.Statistics.FailedToConnect(ri.Identity.IdentHash);
                return null;
            }

            AddTransport(ri.Identity.IdentHash, transport);

            // i2pd does not send an I2NP DatabaseStore immediately upon NTCP2 establishment.
            // Alice already sent RouterInfo in Message 3 Part 2; Bob will send DateTime+RouterInfo
            // as a data frame via its own NTCP2 sender when appropriate (see i2pd NTCP2.cpp SendRouterInfo).
            // Therefore, avoid auto-sending DatabaseStore here; let NetDb/FloodfillUpdater manage RI propagation.

            transport.Connect();
        }
        catch (Exception ex)
        {
#if LOG_MUCH_TRANSPORT
                Logging.LogTransport( ex.Message );
                Logging.LogTransport( $"TransportProvider: CreateTransport stack trace: {System.Environment.StackTrace}" );
#else
            Logging.LogTransport($"TransportProvider: Exception [{ex.GetType()}] " +
                                 $"'{ex.Message}' to {ri.Identity.IdentHash.Id32Short}.");
#endif
            if (transport != null) Remove(transport);
            throw;
        }

        return transport;
    }

    private void AddTransport(I2PIdentHash routerid, ITransport transport)
    {
        if (routerid is null)
            throw new ArgumentNullException("TransportProvider.AddTransport: routerid cannot be null.");

        // Overwrite any older connection
        if (EstablishedTransports.TryGetValue(routerid, out var oldr))
        {
            if (!ReferenceEquals(oldr.Transport, transport))
            {
                Logging.LogTransport(
                    $"TransportProvider: old transport {transport.DebugId} terminated.");
                oldr.Transport.Terminate("Replaced by newer connection");
                EstablishedTransports.TryRemove(routerid, out _);
            }
            else
            {
                return;
            }
        }

        transport.ConnectionShutDown += Transport_ConnectionShutDown;
        transport.ConnectionEstablished += Transport_ConnectionEstablished;

        transport.DataBlockReceived += Transport_DataBlockReceived;
        transport.ConnectionException += Transport_ConnectionException;

        // If the transport was created via an outbound connection (e.g., in CreateTransport), 
        // it must be marked as Outgoing so that firewalled routers don't reject its traffic.
        var info = new EstablishedTransportInfo { Transport = transport };
        if (transport.IsOutgoing)
            info.IsEstablished = false; // It will be set to true in Transport_ConnectionEstablished
        else
            // Incoming connections are typically already established or about to be
            // by the time they reach here. We still hook the event below, but 
            // let's initialize it to true to avoid "0 Connected" during the race.
            info.IsEstablished = true;

        EstablishedTransports[routerid] = info;
    }

    public static bool Send(I2PIdentHash dest, I2NpMessage data)
    {
        return Send(dest, data, 0);
    }

    private static bool Send(I2PIdentHash dest, I2NpMessage data, int reclvl)
    {
        ITransport transp = null;
        try
        {
            if (dest == RouterContext.Inst.MyRouterIdentity.IdentHash)
            {
                Logging.LogTransport($"TransportProvider: Loopback {data}");
                Inst.DistributeIncomingMessage(null, data.CreateHeader16);
                return true;
            }

            lock (TransportSelectionLock)
            {
                if (Inst.CurrentlyUnknownRouters.Contains(dest))
                {
                    Inst.CurrentlyUnknownRouters.Add(dest, data);
                    return true;
                }

                transp = Inst.GetEstablishedTransport(dest, false);
                if (transp != null)
                {
                    if (Inst.EstablishedTransports.TryGetValue(dest, out var info) && info.IsEstablished)
                    {
                        transp.Send(data);
                        return true;
                    }

                    // Not established yet, queue it
                    if (info != null && !info.IsEstablished)
                    {
                        info.PendingMessages.Enqueue(data);
                        Logging.LogTransport(
                            $"TransportProvider.Send: Queued message for {dest.Id32Short} (transport connecting, {info.PendingMessages.Count} pending)");
                        return true;
                    }
                }

                if (NetDb.Inst.Contains(dest))
                {
                    // Check if we already have a not-yet-established transport with a pending queue
                    if (Inst.EstablishedTransports.TryGetValue(dest, out var pendingInfo)
                        && pendingInfo != null && !pendingInfo.IsEstablished)
                    {
                        pendingInfo.PendingMessages.Enqueue(data);
                        Logging.LogTransport(
                            $"TransportProvider.Send: Queued message for {dest.Id32Short} (transport connecting, {pendingInfo.PendingMessages.Count} pending)");
                        return true;
                    }

                    transp = Inst.GetTransport(dest);
                    if (transp == null)
                    {
                        // Connection failed - log and return false instead of throwing
                        if (dest != null && NetDb.Inst != null) NetDb.Inst.Statistics.FailedToConnect(dest);
                        Logging.LogTransport($"TransportProvider.Send: Unable to contact {dest}");
                        return false;
                    }

                    // Queue the message instead of sending immediately - the transport may not be established yet
                    if (Inst.EstablishedTransports.TryGetValue(dest, out var newInfo)
                        && newInfo != null && !newInfo.IsEstablished)
                    {
                        newInfo.PendingMessages.Enqueue(data);
                        Logging.LogTransport(
                            $"TransportProvider.Send: Queued message for newly created transport to {dest.Id32Short}");
                        return true;
                    }

                    transp.Send(data);
                }
                else
                {
                    if (Inst.CurrentlyUnresolvableRouters.Contains(dest))
                    {
                        Logging.LogTransport($"TransportProvider.Send: Unable to resolve {dest}");
                        return false;
                    }

                    Inst.CurrentlyUnknownRouters.Add(dest, data);
                    return false;
                }
            }
        }
        catch (EndOfStreamEncounteredException ex)
        {
            Inst.Remove(transp);

            Logging.LogTransport($"TransportProvider.Send: Connection {(transp == null ? "<>" : transp.DebugId)}" +
                                 $" closed exception: {ex.GetType()}");

            if (reclvl > 1 || !Send(dest, data, reclvl + 1))
            {
                Logging.LogTransport(
                    $"TransportProvider.Send: Recconnection failed to {dest.Id32Short}, reclvl: {reclvl}.");
                throw;
            }
        }
        catch (RouterUnresolvableException ex)
        {
            if (dest != null) NetDb.Inst?.Statistics?.DestinationInformationFaulty(dest);
            Logging.LogDebug($"TransportProvider.Send: Unresolvable router: {ex.Message}");

            return false;
        }
        catch (Exception ex)
        {
            if (transp != null) Inst?.Remove(transp);

            if (dest != null) NetDb.Inst?.Statistics?.DestinationInformationFaulty(dest);
            Logging.LogDebug($"TransportProvider.Send: Exception {ex.GetType()}, {ex.Message}");

            throw;
        }

        return true;
    }

    internal class ExceptionHistoryInstance
    {
        internal IPAddress Address;
        internal Exception Error;
        internal TickCounter Generated = new();
    }

    public class EstablishedTransportInfo
    {
        public bool IsEstablished;

        /// <summary>
        ///     Messages queued while waiting for transport to establish.
        /// </summary>
        public ConcurrentQueue<I2NpMessage> PendingMessages = new();

#if DEBUG
        public TickCounter Started = new();
#endif
        public ITransport Transport;

        public override string ToString()
        {
#if DEBUG
            return $"{Transport} {Started}";
#else
                return $"{Transport}";
#endif
        }
    }

    #region Provider events

    private void TransportProtocol_ConnectionCreated(ITransport transport, I2PIdentHash router)
    {
        Logging.LogTransport(
            $"TransportProvider: TransportProtocol_ConnectionCreated: incoming transport {transport.DebugId} added.");

        AddTransport(router, transport);
    }

    private void Transport_ConnectionException(ITransport instance, Exception exinfo)
    {
        if (instance.RemoteAddress == null) return;

        try
        {
            lock (AddressesWithExceptions)
            {
                AddressesWithExceptions[instance.RemoteAddress] = new ExceptionHistoryInstance
                {
                    Error = exinfo,
                    Address = instance.RemoteAddress
                };
            }

            if (instance.RemoteRouterIdentity != null)
                NetDb.Inst?.Statistics?.DestinationInformationFaulty(instance.RemoteRouterIdentity.IdentHash);
            instance.Terminate($"Connection exception: {exinfo.Message}");
        }
        catch (Exception ex)
        {
            Logging.LogTransport(
                $"TransportProvider: exception in {instance.DebugId} {ex.GetType().Name}");
        }
    }

    private void Transport_DataBlockReceived(ITransport instance, Ii2NpHeader msg)
    {
        ThreadPool.QueueUserWorkItem(o =>
        {
            try
            {
                DistributeIncomingMessage(instance, msg);

                if (msg.MessageType == I2NpMessage.MessageTypes.DatabaseStore)
                {
                    var dsm = (DatabaseStoreMessage)msg.Message;

                    if (dsm.RouterInfo != null &&
                        EstablishedTransports.TryGetValue(dsm.RouterInfo.Identity.IdentHash, out var ts))
                        ts.Transport.DatabaseStoreMessageReceived(dsm);
                }
            }
            catch (Exception ex)
            {
                Logging.Log(ex);
            }
        });
    }

    private void Transport_ConnectionEstablished(ITransport instance, I2PIdentHash hash)
    {
        if (hash is null) throw new ArgumentException("TransportProvider: ConnectionEstablished ID hash required!");

        if (EstablishedTransports.TryGetValue(hash, out var info))
        {
            info.IsEstablished = true;
            Logging.LogTransport(
                $"TransportProvider: Transport_ConnectionEstablished: {instance.DebugId} to {hash.Id32Short} - MARKED AS ESTABLISHED");

            // Flush any pending messages that were queued while waiting for establishment
            var flushed = 0;
            while (info.PendingMessages.TryDequeue(out var pendingMsg))
                try
                {
                    instance.Send(pendingMsg);
                    flushed++;
                }
                catch (Exception ex)
                {
                    Logging.LogWarning(
                        $"TransportProvider: Failed to send queued message to {hash.Id32Short}: {ex.Message}");
                }

            if (flushed > 0)
                Logging.LogTransport($"TransportProvider: Flushed {flushed} pending messages to {hash.Id32Short}");
        }
        else
        {
            Logging.LogWarning(
                $"TransportProvider: Transport_ConnectionEstablished: {instance.DebugId} to {hash.Id32Short} - NOT FOUND IN EstablishedTransports!");
        }
    }

    private void Transport_ConnectionShutDown(ITransport instance)
    {
        Logging.LogTransport(
            $"TransportProvider: transport_ConnectionShutDown: {instance.DebugId}");

        Remove(instance);
    }

    // Batch 2-4 (docs/PRODUCTION-PLAN.md). This was:
    //
    //     if (IncomingMessage != null)
    //         lock (IncomingMessage) { IncomingMessage(instance, msg); }
    //
    // which is broken three ways. Delegates are immutable, so every += or -= replaces the field
    // with a *different* object: two threads locking "it" across a subscription change lock two
    // different objects and exclude nothing. The field is also read three times -- null check,
    // lock, invoke -- so an unsubscribe racing the check gives lock(null) (ArgumentNullException)
    // or a null invoke (NullReferenceException). And it serialised every inbound message from
    // every peer through one monitor on the hottest path in the router.
    //
    // Capturing once into a local is the standard idiom and fixes all three. It does mean
    // handlers are now invoked concurrently, which is why IncomingMessage documents that
    // requirement. Today's only subscriber, TunnelProvider.DistributeIncomingMessage, enqueues
    // to a ConcurrentQueue and sets an event -- thread-safe by construction, and it never
    // needed the serialisation.
    internal void DistributeIncomingMessage(ITransport instance, Ii2NpHeader msg)
    {
        var handlers = IncomingMessage;
        handlers?.Invoke(instance, msg);
    }

    #endregion
}