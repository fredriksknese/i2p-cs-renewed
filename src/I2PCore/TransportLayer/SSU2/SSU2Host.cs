using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     SSU2 (Secure Semi-reliable UDP version 2) Transport Host
///     Based on Noise Protocol Framework XK pattern
///     Spec: https://geti2p.net/spec/ssu2
/// </summary>
[TransportProtocol]
public class SSU2Host : ITransportProtocol
{
    private const int MAX_INTRODUCERS = 3;
    private const long INTRODUCER_SESSION_DURATION = 3600; // 1 hour - keep in publish list
    private const long INTRODUCER_SESSION_EXPIRATION = 4800; // 80 min - total lifetime

    // SSU2 capabilities
    public static readonly bool RelaySupported = true;
    public static readonly bool PeerTestSupported = true;
    public static readonly bool PathValidationSupported = true;
    // Batch 0-4: false until SendPathResponse actually sends. It currently builds the
    // PathResponse block and then only logs "PathResponse sent" without transmitting it, so
    // advertising 'm' promises a migration we silently fail to complete. Batch 4-3 owns this.
    public static readonly bool ConnectionMigrationSupported = false;
    private readonly List<IntroducerInfo> _activeIntroducers = new();
    private readonly object _introducerLock = new();

    private readonly DecayingIpBlockFilter _ipBlockFilter = new();

    // Active introducer management (for firewalled nodes)
    private readonly PeriodicAction IntroducerUpdateAction = new(TickSpan.Seconds(70));
    private readonly TickCounter LastExternalIpProcess = TickCounter.MaxDelta;

    private readonly RouterContext MyRouterContext;

    // Periodic peer test for NAT/firewall detection
    private readonly PeriodicAction PeerTestAction = new(TickSpan.Minutes(5));

    // Batch 4-2a: SSU2 anti-DoS tokens. Per host rather than static, so two hosts can coexist
    // in one process -- the property batch 3-3 introduced and Phase 8 depends on.
    internal readonly SSU2TokenCache Tokens = new();
    private readonly PeriodicAction TokenPruneAction = new(TickSpan.Minutes(5));

    // External IP detection from peer reports
    private readonly LinkedList<IPAddress> ReportedAddresses = new();
    private readonly Dictionary<IPEndPoint, SSU2Session> Sessions = new();
    private readonly object SessionsLock = new();
    private readonly object UdpLock = new();
    private readonly Thread Worker;
    private bool _peerTestInProgress;
    private TickCounter LastIpReport;
    private byte[] StaticPrivateKey;
    private byte[] StaticPublicKey;
    private byte[] IntroKey;

    // UDP socket for sending/receiving
    private UdpClient UdpSocket;

    public SSU2Host()
    {
        if (!RouterContext.Inst.EnableSSU2)
        {
            Logging.LogInformation("SSU2Host: SSU2 is disabled");
            Terminated = true;
            return;
        }

        MyRouterContext = RouterContext.Inst;
        MyRouterContext.NetworkSettingsChanged += NetworkSettingsChanged;

        UpdateRouterContext();

        // Initialize UDP socket
        InitializeSocket();

        Worker = new Thread(Run)
        {
            Name = "SSU2Host",
            IsBackground = true
        };
        Worker.Start();
    }

    /// <summary>
    ///     Test seam, batch 3-3 (docs/PRODUCTION-PLAN.md). Builds a host that owns no UDP
    ///     socket and runs no worker thread, and whose identity and static keys are supplied
    ///     per instance instead of being taken from <see cref="RouterContext.Inst" /> and the
    ///     process-wide <see cref="TransportKeys" /> store.
    ///     <para>
    ///         That second part is the point. <see cref="InitializeStaticKeys" /> loads one
    ///         SSU2 keypair for the whole process, so two hosts built the normal way are the
    ///         same peer and cannot hand-shake with each other. Assigning the key fields here
    ///         before calling <see cref="UpdateRouterContext" /> makes InitializeStaticKeys
    ///         early-out on its "already initialized" check, so each host publishes its own
    ///         static and intro keys into its own RouterInfo.
    ///     </para>
    ///     <para>
    ///         Deliberately not a general-purpose multi-instance constructor — it exists so a
    ///         pair of sessions can be driven over an in-memory channel. Real per-instance
    ///         hosts are Phase 8.
    ///     </para>
    /// </summary>
    internal SSU2Host(RouterContext routerContext, byte[] staticPrivateKey, byte[] staticPublicKey,
        byte[] introKey)
    {
        MyRouterContext = routerContext ?? throw new ArgumentNullException(nameof(routerContext));
        StaticPrivateKey = staticPrivateKey ?? throw new ArgumentNullException(nameof(staticPrivateKey));
        StaticPublicKey = staticPublicKey ?? throw new ArgumentNullException(nameof(staticPublicKey));
        IntroKey = introKey ?? throw new ArgumentNullException(nameof(introKey));

        // Publishes the SSU2 address, carrying the keys just assigned, into routerContext.
        UpdateRouterContext();

        // No NetworkSettingsChanged subscription: it would re-enter InitializeSocket.
        // No socket, no worker thread — the channel drives this host by calling
        // DispatchPacket directly, and SendPacket is overridden to feed the peer.
    }

    /// <summary>
    ///     Maximum number of concurrent incoming SSU2 sessions.
    ///     Matches i2pd default of 2500.
    /// </summary>
    public int MaxIncomingSessions { get; set; } = 2500;

    public bool Terminated { get; protected set; }

    public event Action<ITransport, I2PIdentHash> ConnectionCreated;

    // ITransportProtocol implementation
    public ProtocolCapabilities ContactCapability(I2PRouterInfo router)
    {
        if (router == null)
            return ProtocolCapabilities.None;

        // Check if router has SSU2 address with a reachable IP (respecting IPv4/IPv6 settings)
        var ssu2Address = router.Addresses?.FirstOrDefault(a =>
            a.TransportStyle == "SSU2" && a.Options.Contains("s")
            && I2PRouterAddress.IsReachableAddress(a));

        if (ssu2Address == null)
            return ProtocolCapabilities.None;

        // Check for capabilities
        if (ssu2Address.Options.Contains("caps"))
        {
            var caps = ssu2Address.Options["caps"];

            // Check for introducers (NAT traversal support)
            if (ssu2Address.Options.Contains("ihost0"))
                return ProtocolCapabilities.NatTraversal;
        }

        // Has published address - can connect directly
        if (ssu2Address.Options.Contains("host") && ssu2Address.Options.Contains("port"))
            return ProtocolCapabilities.Incoming;

        // Unpublished address - outgoing only
        return ProtocolCapabilities.Outgoing;
    }

    public ITransport AddSession(I2PRouterInfo router)
    {
        if (router == null)
            throw new ArgumentNullException(nameof(router));

        // Create new outgoing session
        var session = new SSU2Session(this, router, true);

        lock (SessionsLock)
        {
            // Extract endpoint from router info
            var ssu2Address = router.Addresses?.FirstOrDefault(a =>
                a.TransportStyle == "SSU2" && a.Options.Contains("host"));

            if (ssu2Address != null)
            {
                var host = ssu2Address.Options["host"];
                var port = int.Parse(ssu2Address.Options["port"]);
                var ipAddress = IPAddress.Parse(host);

                // Skip IPv6 addresses if IPv6 is not enabled
                if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6 && !RouterContext.UseIpV6)
                {
                    Logging.LogDebug($"SSU2Host: Skipping IPv6 address {host} (IPv6 disabled)");
                    return null;
                }

                var endpoint = new IPEndPoint(ipAddress, port);
                Sessions[endpoint] = session;
                Logging.LogInformation(
                    $"SSU2Host: Added outgoing session to {endpoint} (router: {router.Identity.IdentHash.Id32Short})");
            }
            else
            {
                Logging.LogWarning($"SSU2Host: No SSU2 address found for router {router.Identity.IdentHash.Id32Short}");
            }
        }

        // Don't call Connect() here - TransportProvider will call it

        return session;
    }

    public int BlockedRemoteAddressesCount => _ipBlockFilter.Count;

    private void InitializeSocket()
    {
        try
        {
            var localEP = new IPEndPoint(MyRouterContext.LocalInterface, MyRouterContext.UdpPort);
            UdpSocket = new UdpClient(localEP.AddressFamily);
            if (RouterContext.UseIpV6 && localEP.AddressFamily == AddressFamily.InterNetworkV6)
                UdpSocket.Client.DualMode = true;
            UdpSocket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            UdpSocket.Client.Bind(localEP);
            Logging.LogInformation($"SSU2Host: Listening on UDP {localEP}");
        }
        catch (Exception ex)
        {
            // UdpSocket stays null and every send and receive silently no-ops from here on, so
            // the transport is dead rather than degraded. Error, not Warning.
            Logging.LogError($"SSU2Host: Failed to initialize UDP socket, SSU2 will not run: {ex}");
        }
    }

    private void Run()
    {
        try
        {
            Logging.LogInformation("SSU2Host: Starting SSU2 transport");

            while (!Terminated)
            {
                Thread.Sleep(1);

                // Process sessions, timeouts, etc.
                ProcessSessions();

                // Receive incoming packets
                ProcessIncomingPackets();

                // Periodic peer test for NAT/firewall detection
                PeerTestAction.Do(TryInitiatePeerTest);
                TokenPruneAction.Do(Tokens.Prune);

                // Periodic introducer management (for firewalled nodes)
                if (MyRouterContext.IsFirewalled) IntroducerUpdateAction.Do(UpdateIntroducers);
            }
        }
        catch (Exception ex)
        {
            // This catch wraps the entire worker loop, so reaching it ends SSU2 for the lifetime
            // of the process — no sessions, no receives, no peer tests, and nothing restarts it.
            // "Fatal" was accurate; the level was not.
            Logging.LogError($"SSU2Host: worker loop terminated, SSU2 is now dead: {ex}");
        }
        finally
        {
            Logging.LogInformation("SSU2Host: Shutting down");
            UdpSocket?.Close();
        }
    }

    /// <summary>
    ///     Periodically initiate SSU2 peer tests to detect NAT/firewall status.
    ///     Selects an established session and sends PeerTest msg 1 through it.
    ///     The result updates RouterContext.IsFirewalled.
    /// </summary>
    private void TryInitiatePeerTest()
    {
        if (_peerTestInProgress) return;

        SSU2Session selectedSession = null;

        lock (SessionsLock)
        {
            // Find an established session to a peer that supports peer testing
            selectedSession = Sessions.Values
                .FirstOrDefault(s => s.State == SessionState.Established && !s.IsTerminated);
        }

        if (selectedSession == null)
        {
            Logging.LogDebug("SSU2Host: No established session available for peer test");
            return;
        }

        _peerTestInProgress = true;

        // Subscribe to the result event
        selectedSession.RelayHandler.PeerTestCompleted += OnPeerTestCompleted;

        try
        {
            var success = selectedSession.RelayHandler.InitiatePeerTest(selectedSession);
            if (!success)
            {
                _peerTestInProgress = false;
                selectedSession.RelayHandler.PeerTestCompleted -= OnPeerTestCompleted;
            }
        }
        catch (Exception ex)
        {
            // Rate-limited by PeerTestAction, so this cannot spam. Warning because peer testing
            // is how IsFirewalled is determined, and a router that silently never completes one
            // keeps whatever reachability assumption it booted with.
            Logging.LogWarning($"SSU2Host: PeerTest initiation failed: {ex}");
            _peerTestInProgress = false;
            selectedSession.RelayHandler.PeerTestCompleted -= OnPeerTestCompleted;
        }
    }

    private void OnPeerTestCompleted(bool isReachable, IPEndPoint reportedAddress)
    {
        _peerTestInProgress = false;

        var wasFirewalled = MyRouterContext.IsFirewalled;
        MyRouterContext.IsFirewalled = !isReachable;

        if (wasFirewalled != !isReachable)
        {
            Logging.LogInformation($"SSU2Host: PeerTest result: " +
                                   $"{(isReachable ? "Reachable" : "Firewalled")}" +
                                   $"{(reportedAddress != null ? $" at {reportedAddress}" : "")}");

            // Immediately rebuild and publish new RouterInfo with correct reachability
            UpdateRouterContext();
        }

        if (isReachable && reportedAddress != null) MyRouterContext.DefaultExtAddress = reportedAddress.Address;
    }

    /// <summary>
    ///     Update active introducers for firewalled nodes.
    ///     Maintains up to 3 active introducers from established SSU2 sessions.
    ///     Publishable introducers (
    ///     < 1 hour old) are included in RouterInfo.
    ///         Matches i2pd's SSU2Server::UpdateIntroducers().
    /// 
    /// </summary>
    private void UpdateIntroducers()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        lock (_introducerLock)
        {
            // Phase 1: Validate existing introducers
            var validIntroducers = new List<IntroducerInfo>();
            var impliedIntroducers = new List<IntroducerInfo>();

            foreach (var intro in _activeIntroducers)
            {
                var age = now - intro.CreatedAt;

                // Check session still alive and established
                if (intro.Session == null || intro.Session.IsTerminated ||
                    intro.Session.State != SessionState.Established)
                    continue;

                if (age < INTRODUCER_SESSION_DURATION)
                    // Fresh enough to publish
                    validIntroducers.Add(intro);
                else if (age < INTRODUCER_SESSION_EXPIRATION)
                    // Too old to publish but still usable internally
                    impliedIntroducers.Add(intro);
                // else: expired, drop it
            }

            // Phase 2: Find new introducers if needed
            if (validIntroducers.Count < MAX_INTRODUCERS)
            {
                var needed = MAX_INTRODUCERS - validIntroducers.Count;
                var excludedHashes = new HashSet<I2PIdentHash>(
                    validIntroducers.Select(i => i.RouterHash)
                        .Concat(impliedIntroducers.Select(i => i.RouterHash)));

                lock (SessionsLock)
                {
                    var candidates = Sessions.Values
                        .Where(s => s.State == SessionState.Established
                                    && !s.IsTerminated
                                    && s.IsOutgoing
                                    && s.RemoteRouterInfo?.Identity?.IdentHash != null
                                    && !excludedHashes.Contains(s.RemoteRouterInfo.Identity.IdentHash))
                        .Take(needed)
                        .ToList();

                    foreach (var session in candidates)
                    {
                        // Request relay tag from this session
                        var relayTag = session.RelayHandler.RequestRelayTag(session);
                        if (relayTag != 0)
                        {
                            validIntroducers.Add(new IntroducerInfo
                            {
                                RouterHash = session.RemoteRouterInfo.Identity.IdentHash,
                                RelayTag = relayTag,
                                CreatedAt = now,
                                Session = session
                            });
                            Logging.LogDebug(
                                $"SSU2Host: New introducer: {session.RemoteRouterInfo.Identity.IdentHash}");
                        }
                    }
                }
            }

            // Phase 3: If still not enough, reuse implied (old but alive)
            if (validIntroducers.Count < MAX_INTRODUCERS)
                foreach (var implied in impliedIntroducers)
                {
                    if (validIntroducers.Count >= MAX_INTRODUCERS) break;
                    if (!validIntroducers.Any(v => v.RouterHash == implied.RouterHash))
                        validIntroducers.Add(implied);
                }

            _activeIntroducers.Clear();
            _activeIntroducers.AddRange(validIntroducers);

            Logging.LogDebug($"SSU2Host: Active introducers: {_activeIntroducers.Count}");
        }
    }

    /// <summary>
    ///     Get the current list of active introducers for publishing in RouterInfo.
    /// </summary>
    public List<(I2PIdentHash hash, uint relayTag, long expiration)> GetActiveIntroducers()
    {
        lock (_introducerLock)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return _activeIntroducers
                .Where(i => now - i.CreatedAt < INTRODUCER_SESSION_DURATION)
                .Select(i => (i.RouterHash, i.RelayTag, i.CreatedAt + INTRODUCER_SESSION_DURATION))
                .ToList();
        }
    }

    private void ProcessSessions()
    {
        lock (SessionsLock)
        {
            // Remove terminated sessions
            var toRemove = new List<IPEndPoint>();
            foreach (var kvp in Sessions)
                if (kvp.Value.IsTerminated)
                    toRemove.Add(kvp.Key);

            foreach (var ep in toRemove) Sessions.Remove(ep);
        }
    }

    private void ProcessIncomingPackets()
    {
        try
        {
            while (UdpSocket != null && UdpSocket.Available > 0)
            {
                IPEndPoint remoteEP = null;
                byte[] packetData = null;

                lock (UdpLock)
                {
                    if (UdpSocket != null && UdpSocket.Available > 0)
                    {
                        remoteEP = new IPEndPoint(IPAddress.Any, 0);
                        packetData = UdpSocket.Receive(ref remoteEP);
                    }
                }

                if (packetData == null || packetData.Length == 0)
                    continue;

                // Check IP block filter
                if (remoteEP != null && _ipBlockFilter.IsFiltered(remoteEP.Address))
                {
                    Logging.LogDebug($"SSU2Host: Dropping packet from blocked IP {remoteEP.Address}");
                    continue;
                }

                // Logging.LogInformation($"SSU2Host: Received {packetData.Length} bytes from {remoteEP}");

                // Route packet to session
                DispatchPacket(remoteEP, packetData);
            }
        }
        catch (SocketException ex)
        {
            // Shutdown closes the socket out from under a blocked Receive, so this is routine
            // once Terminated is set and stays at Debug. At any other time it is not routine:
            // this catch sits outside the receive loop, so a SocketException abandons the whole
            // batch of pending datagrams, and "SSU2 quietly stops receiving" is precisely the
            // failure mode Phase 4 must be able to see.
            if (Terminated)
                Logging.LogDebug($"SSU2Host: receive socket closed during shutdown: {ex.Message}");
            else
                Logging.LogWarning($"SSU2Host: ProcessIncomingPackets socket error: {ex}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"SSU2Host: ProcessIncomingPackets error: {ex}");
        }
    }

    /// <summary>
    ///     Route one received datagram: to its existing session, or into a new inbound session
    ///     if it trial-decrypts as a SessionRequest. Internal rather than private as of batch
    ///     3-3 so a test channel can deliver packets through the same path the socket uses —
    ///     a fixture that hand-built its inbound session would be testing its own wiring.
    /// </summary>
    internal void DispatchPacket(IPEndPoint remoteEP, byte[] packetData)
    {
        try
        {
            SSU2Session session;

            lock (SessionsLock)
            {
                // Try to find existing session by endpoint
                if (Sessions.TryGetValue(remoteEP, out session))
                {
                    // Route to existing session
                    session.ProcessReceivedPacket(packetData);
                    return;
                }
            }

            // Parse header to determine packet type. Batch 4-2a raised this from 32: the
            // trial decrypt below derives its IVs from the last 24 bytes, so anything under 64
            // reads its own header as an IV and throws into the outer catch.
            if (packetData.Length < 64)
            {
                Logging.LogDebug($"SSU2Host: Packet from {remoteEP} too short ({packetData.Length} bytes)");
                return;
            }

            // For packets from unknown endpoints, we must try to decrypt the header first
            // to see if it's a SessionRequest or PeerTest.
            // SSU2 spec: k_header_1 = k_header_2 = Bob's Intro Key (our intro key)
            var trialDecrypted = (byte[])packetData.Clone();
            var myIntroKey = IntroKey;
            SSU2HeaderEncryption.DecryptLongHeaderComplete(trialDecrypted, 0, myIntroKey, myIntroKey);

            var reader = new I2PBufferCursor(trialDecrypted);
            var header = SSU2Header.ParseLongHeader(reader);

            // Only accept SessionRequest or PeerTest for new incoming packets
            if (header.Type == SSU2Header.TYPE_SESSION_REQUEST)
            {
                // Connection limit check
                int currentCount;
                lock (SessionsLock)
                {
                    currentCount = Sessions.Count;
                }

                if (currentCount >= MaxIncomingSessions)
                {
                    Logging.LogWarning(
                        $"SSU2Host: Connection limit ({MaxIncomingSessions}) reached, dropping SessionRequest from {remoteEP}");
                    return;
                }

                // Create new incoming session
                session = new SSU2Session(this, remoteEP);

                lock (SessionsLock)
                {
                    Sessions[remoteEP] = session;
                }

                // Process the SessionRequest (using the original packet, the session will decrypt it again)
                session.ProcessReceivedPacket(packetData);

                Logging.LogDebug($"SSU2Host: Created incoming session from {remoteEP}");
            }
            else if (header.Type == SSU2Header.TYPE_PEER_TEST)
            {
                HandleIncomingPeerTestPacket(remoteEP, packetData);
            }
            else if (header.Type == SSU2Header.TYPE_TOKEN_REQUEST)
            {
                HandleIncomingTokenRequest(remoteEP, packetData);
            }
            else
            {
                Logging.LogWarning(
                    $"SSU2Host: Received packet type {header.Type} from unknown endpoint {remoteEP} (Trial Decryption Type: {header.Type})");
            }
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"SSU2Host: DispatchPacket error for {remoteEP}: {ex}");
        }
    }

    /// <summary>
    ///     Answer a TokenRequest with a Retry carrying a freshly issued token.
    ///
    ///     <para>
    ///         Batch 4-2a (docs/PRODUCTION-PLAN.md). Type 10 used to fall through DispatchPacket's
    ///         final else to "Received packet type 10 from unknown endpoint", and since a
    ///         TokenRequest is i2pd's <b>first</b> packet to any peer it holds no token for, an
    ///         inbound SSU2 session from i2pd could not begin at all.
    ///     </para>
    ///     <para>
    ///         <b>No session is created here, deliberately.</b> A TokenRequest is stateless
    ///         anti-DoS — that is its entire purpose — and registering a session would leave a
    ///         half-live entry in Sessions[remoteEP] that the real Session Request would then be
    ///         routed into.
    ///     </para>
    /// </summary>
    private void HandleIncomingTokenRequest(IPEndPoint remoteEP, byte[] packetData)
    {
        try
        {
            if (!Retry.TryOpen(packetData, IntroKey, SSU2Header.TYPE_TOKEN_REQUEST,
                    out var header, out _))
            {
                Logging.LogDebug(
                    $"SSU2Host: TokenRequest from {remoteEP} did not authenticate; ignoring");
                return;
            }

            var token = Tokens.Issue(remoteEP);
            if (token == 0)
            {
                Logging.LogDebug($"SSU2Host: no token available for {remoteEP}; not answering");
                return;
            }

            SendPacket(remoteEP, Retry.Build(header, token, IntroKey, remoteEP));

            Logging.LogDebug($"SSU2Host: answered TokenRequest from {remoteEP} with a Retry");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"SSU2Host: HandleIncomingTokenRequest error for {remoteEP}: {ex}");
        }
    }

    private void HandleIncomingPeerTestPacket(IPEndPoint remoteEP, byte[] packetData)
    {
        try
        {
            // PeerTest DIRECT packets (type 7) are encrypted with OUR intro key
            var myIntroKey = IntroKey;

            // 1. Decrypt header (first 16 bytes are obfuscated)
            var decryptedHeader = (byte[])packetData.Clone();
            SSU2HeaderEncryption.DecryptLongHeaderComplete(decryptedHeader, 0, myIntroKey, myIntroKey);

            // 2. Parse header
            var header = SSU2Header.ParseLongHeader(new I2PBufferCursor(decryptedHeader));
            if (header.Type != SSU2Header.TYPE_PEER_TEST)
            {
                Logging.LogDebug($"SSU2Host: PeerTest packet decryption failed from {remoteEP} (wrong type)");
                return;
            }

            // 3. Decrypt payload using AEAD
            // AD = header (32 bytes)
            // IV = derived from packet end (IV2)
            var packetLen = packetData.Length;
            if (packetLen < 32 + 16 + 24)
            {
                Logging.LogDebug($"SSU2Host: PeerTest packet too short ({packetLen} bytes)");
                return;
            }

            var iv2 = new byte[12];
            Array.Copy(packetData, packetLen - 12, iv2, 0, 12);

            // Ciphertext with tag starts at 32 and ends at packetLen - 24
            var ciphertextWithTag = new byte[packetLen - 32 - 24];
            Array.Copy(packetData, 32, ciphertextWithTag, 0, ciphertextWithTag.Length);

            var decryptedPayload = ChaCha20Poly1305.Decrypt(
                myIntroKey,
                iv2,
                ciphertextWithTag,
                decryptedHeader);

            if (decryptedPayload == null)
            {
                Logging.LogDebug($"SSU2Host: PeerTest packet AEAD decryption failed from {remoteEP}");
                return;
            }

            // 4. Dispatch to RelayHandler
            // We create a dummy session for the handler to use for replies if needed
            // Actually RelayHandler can handle null session for direct packets
            var relayHandler = new SSU2RelayHandler(this);
            relayHandler.HandlePeerTest(null, decryptedPayload);

            Logging.LogDebug($"SSU2Host: Handled direct PeerTest packet from {remoteEP}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"SSU2Host: HandleIncomingPeerTestPacket error for {remoteEP}: {ex}");
        }
    }

    /// <summary>
    ///     Every outbound SSU2 datagram leaves through here. Virtual as of batch 3-3 so a test
    ///     host can divert the wire into an in-memory channel instead of a socket; production
    ///     behaviour is unchanged.
    /// </summary>
    public virtual void SendPacket(IPEndPoint destination, byte[] data)
    {
        try
        {
            lock (UdpLock)
            {
                UdpSocket?.Send(data, data.Length, destination);
            }
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"SSU2Host: Send packet failed: {ex}");
        }
    }

    /// <summary>
    ///     Report a problem with a remote address for rate limiting/blocking.
    ///     After enough problems within the decay window, the IP is blocked.
    /// </summary>
    public void ReportConnectionProblem(IPAddress addr)
    {
        if (addr != null) _ipBlockFilter.ReportProblem(addr);
    }

    private void NetworkSettingsChanged()
    {
        UpdateRouterContext();

        // Reinitialize socket with new settings
        UdpSocket?.Close();
        InitializeSocket();
    }

    private void UpdateRouterContext()
    {
        // Update configuration from router context
        InitializeStaticKeys();

        // Build SSU2 router address with the EXTERNAL address (not the listen address).
        // LocalInterface (0.0.0.0) is for binding; the published address must be routable.
        var publishedAddress = MyRouterContext.ExtIpv4Address
                               ?? MyRouterContext.DefaultExtAddress
                               ?? MyRouterContext.LocalInterface;

        var addr = new I2PRouterAddress(
            publishedAddress,
            MyRouterContext.UdpPort,
            5, // SSU2 cost (lower than NTCP2, preferred)
            "SSU2"
        );

        // Add SSU2-specific options per spec
        // s = base64 of static key (32 bytes) - Bob's static public key
        // i = base64 of intro key (32 bytes)
        // v = version (2 for SSU2)
        // caps = capabilities string
        // CRITICAL: Use I2P Base64 encoding (FreenetBase64), not standard .NET Base64!
        // I2P Base64 uses '-' and '~' instead of '+' and '/'
        addr.Options["s"] = FreenetBase64.Encode(new I2PByteBlock(StaticPublicKey));
        addr.Options["i"] = FreenetBase64.Encode(new I2PByteBlock(IntroKey));
        addr.Options["v"] = "2";

        // If firewalled, include introducers
        if (MyRouterContext.IsFirewalled)
        {
            var intros = GetActiveIntroducers();
            for (var i = 0; i < intros.Count; i++)
            {
                var (hash, tag, exp) = intros[i];
                addr.Options[$"i{i}"] = FreenetBase64.Encode(hash.Hash);
                addr.Options[$"t{i}"] = tag.ToString();
                addr.Options[$"exp{i}"] = exp.ToString();
            }
        }

        // Capabilities: f=firewall status, r=relay, t=peer test, p=path validation, m=migration
        var caps = new StringBuilder();
        if (RelaySupported) caps.Append('r');
        if (PeerTestSupported) caps.Append('t');
        if (PathValidationSupported) caps.Append('p');
        if (ConnectionMigrationSupported) caps.Append('m');
        if (caps.Length > 0)
            addr.Options["caps"] = caps.ToString();

        // Publish to RouterContext
        var addresses = new List<I2PRouterAddress> { addr };
        MyRouterContext.UpdateAddress(this, addresses);

        Logging.LogInformation($"SSU2Host: Published address to RouterInfo (port {MyRouterContext.UdpPort})");
    }

    private void InitializeStaticKeys()
    {
        // Skip if already initialized
        if (StaticPrivateKey != null)
            return;

        // Try to load existing keys from persistent storage
        var loadedKeys = TransportKeys.LoadSSU2Keys();

        if (loadedKeys.HasValue)
        {
            // Use existing keys
            StaticPrivateKey = loadedKeys.Value.privateKey;
            StaticPublicKey = loadedKeys.Value.publicKey;
            IntroKey = loadedKeys.Value.introKey;

            // Generate intro key if missing (upgrade from old format)
            if (IntroKey == null)
            {
                IntroKey = BufUtils.RandomBytes(32);
                TransportKeys.SaveSSU2Keys(StaticPrivateKey, StaticPublicKey, IntroKey);
                Logging.LogInformation("SSU2Host: Generated missing intro key during upgrade");
            }
            else
            {
                Logging.LogInformation("SSU2Host: Loaded keys from persistent storage");
            }
        }
        else
        {
            // Generate new keys
            var (priv, pub) = X25519.GenerateKeyPair();
            StaticPrivateKey = priv;
            StaticPublicKey = pub;

            IntroKey = BufUtils.RandomBytes(32);

            // Save to persistent storage
            TransportKeys.SaveSSU2Keys(StaticPrivateKey, StaticPublicKey, IntroKey);
            Logging.LogInformation("SSU2Host: Generated and saved new SSU2 keys");
        }
    }

    internal byte[] GetStaticPublicKey()
    {
        return StaticPublicKey;
    }

    internal byte[] GetStaticPrivateKey()
    {
        return StaticPrivateKey;
    }

    internal byte[] GetMyStaticKey()
    {
        return StaticPublicKey;
    }

    internal byte[] GetMyIntroKey()
    {
        return IntroKey;
    }

    internal I2PRouterInfo GetMyRouterInfo()
    {
        return MyRouterContext?.MyRouterInfo;
    }

    public IEnumerable<SSU2Session> GetEstablishedSessions()
    {
        lock (SessionsLock)
        {
            return Sessions.Values
                .Where(s => s.State == SessionState.Established && !s.IsTerminated)
                .ToArray();
        }
    }

    /// <summary>
    ///     Fire ConnectionCreated event for incoming connections
    ///     Called when remote identity is established
    /// </summary>
    internal void FireConnectionCreated(ITransport transport, I2PIdentHash hash)
    {
        ConnectionCreated?.Invoke(transport, hash);
    }

    /// <summary>
    ///     Report external IP address as observed by remote peer
    ///     Collects reports and updates RouterContext when consensus is reached
    /// </summary>
    internal void ReportedAddress(IPAddress ipaddr)
    {
        if (LastExternalIpProcess.DeltaToNowSeconds < (LastIpReport == null ? 1 : 60)) return;
        if (ipaddr.AddressFamily != AddressFamily.InterNetwork) return;
        LastExternalIpProcess.SetNow();

        Logging.LogTransport($"SSU2 My IP: My external IP {ipaddr}");

        lock (ReportedAddresses)
        {
            ReportedAddresses.AddLast(ipaddr);
            while (ReportedAddresses.Count > 200) ReportedAddresses.RemoveFirst();

            var first = ReportedAddresses.First.Value;
            var firstbytes = first.GetAddressBytes();
            if (ReportedAddresses.Count() > 10 &&
                ReportedAddresses.All(a => BufUtils.Equal(a.GetAddressBytes(), firstbytes)))
            {
                Logging.LogTransport($"SSU2 My IP: Start using unanimous remote reported external IP {ipaddr}");
                UpdateSsu2ReportedAddr(ipaddr);
            }
            else
            {
                var freq = ReportedAddresses.GroupBy(a => a.GetAddressBytes()).OrderBy(g => g.Count());
                if (freq.First().Count() > 15)
                {
                    Logging.LogTransport(
                        $"SSU2 My IP: Start using most frequently reported remote external IP {ipaddr}");
                    UpdateSsu2ReportedAddr(ipaddr);
                }
            }
        }
    }

    private void UpdateSsu2ReportedAddr(IPAddress ipaddr)
    {
        if (LastIpReport?.DeltaToNow.ToMinutes < 30) return;
        if (LastIpReport == null) LastIpReport = new TickCounter();
        LastIpReport.SetNow();

        MyRouterContext.SsuReportedAddr(ipaddr);
        UpdateRouterContext();
    }

    public void Terminate()
    {
        Terminated = true;

        // Terminate all sessions
        lock (SessionsLock)
        {
            foreach (var session in Sessions.Values) session.Terminate("Transport host shutting down");
            Sessions.Clear();
        }
    }

    private class IntroducerInfo
    {
        public I2PIdentHash RouterHash { get; set; }
        public uint RelayTag { get; set; }
        public long CreatedAt { get; set; }
        public SSU2Session Session { get; set; }
    }
}