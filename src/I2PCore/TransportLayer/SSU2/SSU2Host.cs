using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Crypto;

namespace I2PCore.TransportLayer.SSU2
{
    /// <summary>
    /// SSU2 (Secure Semi-reliable UDP version 2) Transport Host
    /// Based on Noise Protocol Framework XK pattern
    /// Spec: https://geti2p.net/spec/ssu2
    /// </summary>
    [TransportProtocol]
    public partial class SSU2Host : ITransportProtocol
    {
        private Thread Worker;
        public bool Terminated { get; protected set; }

        public event Action<ITransport, I2PIdentHash> ConnectionCreated;

        // SSU2 capabilities
        public static readonly bool RelaySupported = true;
        public static readonly bool PeerTestSupported = true;
        public static readonly bool PathValidationSupported = true;
        public static readonly bool ConnectionMigrationSupported = true;

        private RouterContext MyRouterContext;
        private readonly object SessionsLock = new();
        private Dictionary<IPEndPoint, SSU2Session> Sessions = new();

        /// <summary>
        /// Maximum number of concurrent incoming SSU2 sessions.
        /// Matches i2pd default of 2500.
        /// </summary>
        public int MaxIncomingSessions { get; set; } = 2500;

        // UDP socket for sending/receiving
        private UdpClient UdpSocket;
        private readonly object UdpLock = new();

        // External IP detection from peer reports
        private LinkedList<IPAddress> ReportedAddresses = new();
        private TickCounter LastIpReport = null;
        private TickCounter LastExternalIpProcess = TickCounter.MaxDelta;

        // Periodic peer test for NAT/firewall detection
        private readonly PeriodicAction PeerTestAction = new( TickSpan.Minutes( 5 ), false );
        private bool _peerTestInProgress;

        // Active introducer management (for firewalled nodes)
        private readonly PeriodicAction IntroducerUpdateAction = new( TickSpan.Seconds( 70 ), false );
        private const int MAX_INTRODUCERS = 3;
        private const long INTRODUCER_SESSION_DURATION = 3600;    // 1 hour - keep in publish list
        private const long INTRODUCER_SESSION_EXPIRATION = 4800;  // 80 min - total lifetime
        private readonly List<IntroducerInfo> _activeIntroducers = new();
        private readonly object _introducerLock = new();

        private class IntroducerInfo
        {
            public I2PIdentHash RouterHash { get; set; }
            public uint RelayTag { get; set; }
            public long CreatedAt { get; set; }
            public SSU2Session Session { get; set; }
        }

        public SSU2Host()
        {
            if ( !RouterContext.Inst.EnableSSU2 )
            {
                Logging.LogInformation( "SSU2Host: SSU2 is disabled" );
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

        private void InitializeSocket()
        {
            try
            {
                var localEP = new IPEndPoint(MyRouterContext.LocalInterface, MyRouterContext.UdpPort);
                UdpSocket = new UdpClient(localEP.AddressFamily);
                if (RouterContext.UseIpV6 && localEP.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    UdpSocket.Client.DualMode = true;
                }
                UdpSocket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                UdpSocket.Client.Bind(localEP);
                Logging.LogInformation($"SSU2Host: Listening on UDP {localEP}");
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"SSU2Host: Failed to initialize UDP socket: {ex}");
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
                    PeerTestAction.Do( TryInitiatePeerTest );

                    // Periodic introducer management (for firewalled nodes)
                    if ( MyRouterContext.IsFirewalled )
                    {
                        IntroducerUpdateAction.Do( UpdateIntroducers );
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"SSU2Host: Fatal error: {ex}");
            }
            finally
            {
                Logging.LogInformation("SSU2Host: Shutting down");
                UdpSocket?.Close();
            }
        }

        /// <summary>
        /// Periodically initiate SSU2 peer tests to detect NAT/firewall status.
        /// Selects an established session and sends PeerTest msg 1 through it.
        /// The result updates RouterContext.IsFirewalled.
        /// </summary>
        private void TryInitiatePeerTest()
        {
            if ( _peerTestInProgress ) return;

            SSU2Session selectedSession = null;

            lock ( SessionsLock )
            {
                // Find an established session to a peer that supports peer testing
                selectedSession = Sessions.Values
                    .FirstOrDefault( s => s.State == SessionState.Established && !s.IsTerminated );
            }

            if ( selectedSession == null )
            {
                Logging.LogDebug( "SSU2Host: No established session available for peer test" );
                return;
            }

            _peerTestInProgress = true;

            // Subscribe to the result event
            selectedSession.RelayHandler.PeerTestCompleted += OnPeerTestCompleted;

            try
            {
                var success = selectedSession.RelayHandler.InitiatePeerTest( selectedSession );
                if ( !success )
                {
                    _peerTestInProgress = false;
                    selectedSession.RelayHandler.PeerTestCompleted -= OnPeerTestCompleted;
                }
            }
            catch ( Exception ex )
            {
                Logging.LogDebug( $"SSU2Host: PeerTest initiation failed: {ex.Message}" );
                _peerTestInProgress = false;
                selectedSession.RelayHandler.PeerTestCompleted -= OnPeerTestCompleted;
            }
        }

        private void OnPeerTestCompleted( bool isReachable, IPEndPoint reportedAddress )
        {
            _peerTestInProgress = false;

            var wasFirewalled = MyRouterContext.IsFirewalled;
            MyRouterContext.IsFirewalled = !isReachable;

            if ( wasFirewalled != !isReachable )
            {
                Logging.LogInformation( $"SSU2Host: PeerTest result: " +
                    $"{( isReachable ? "Reachable" : "Firewalled" )}" +
                    $"{( reportedAddress != null ? $" at {reportedAddress}" : "" )}" );
                
                // Immediately rebuild and publish new RouterInfo with correct reachability
                UpdateRouterContext();
            }

            if ( isReachable && reportedAddress != null )
            {
                MyRouterContext.DefaultExtAddress = reportedAddress.Address;
            }
        }

        /// <summary>
        /// Update active introducers for firewalled nodes.
        /// Maintains up to 3 active introducers from established SSU2 sessions.
        /// Publishable introducers (< 1 hour old) are included in RouterInfo.
        /// Matches i2pd's SSU2Server::UpdateIntroducers().
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
                    {
                        // Fresh enough to publish
                        validIntroducers.Add(intro);
                    }
                    else if (age < INTRODUCER_SESSION_EXPIRATION)
                    {
                        // Too old to publish but still usable internally
                        impliedIntroducers.Add(intro);
                    }
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
                                Logging.LogDebug($"SSU2Host: New introducer: {session.RemoteRouterInfo.Identity.IdentHash}");
                            }
                        }
                    }
                }

                // Phase 3: If still not enough, reuse implied (old but alive)
                if (validIntroducers.Count < MAX_INTRODUCERS)
                {
                    foreach (var implied in impliedIntroducers)
                    {
                        if (validIntroducers.Count >= MAX_INTRODUCERS) break;
                        if (!validIntroducers.Any(v => v.RouterHash == implied.RouterHash))
                            validIntroducers.Add(implied);
                    }
                }

                _activeIntroducers.Clear();
                _activeIntroducers.AddRange(validIntroducers);

                Logging.LogDebug($"SSU2Host: Active introducers: {_activeIntroducers.Count}");
            }
        }

        /// <summary>
        /// Get the current list of active introducers for publishing in RouterInfo.
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
                {
                    if (kvp.Value.IsTerminated)
                    {
                        toRemove.Add(kvp.Key);
                    }
                }

                foreach (var ep in toRemove)
                {
                    Sessions.Remove(ep);
                }
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
                    if ( remoteEP != null && _ipBlockFilter.IsFiltered( remoteEP.Address ) )
                    {
                        Logging.LogDebug($"SSU2Host: Dropping packet from blocked IP {remoteEP.Address}");
                        continue;
                    }

                    // Logging.LogInformation($"SSU2Host: Received {packetData.Length} bytes from {remoteEP}");

                    // Route packet to session
                    DispatchPacket(remoteEP, packetData);
                }
            }
            catch (SocketException)
            {
                // Socket closed or network error - ignore
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"SSU2Host: ProcessIncomingPackets error: {ex}");
            }
        }

        private void DispatchPacket(IPEndPoint remoteEP, byte[] packetData)
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

                // Parse header to determine packet type
                if (packetData.Length < 32)
                {
                    Logging.LogDebug($"SSU2Host: Packet from {remoteEP} too short ({packetData.Length} bytes)");
                    return;
                }

                var reader = new I2PBufferCursor(packetData);
                var header = SSU2Header.ParseLongHeader(reader);

                // Only accept SessionRequest or PeerTest for new incoming packets
                if (header.Type == SSU2Header.TYPE_SESSION_REQUEST)
                {
                    // Connection limit check
                    int currentCount;
                    lock ( SessionsLock ) { currentCount = Sessions.Count; }
                    if ( currentCount >= MaxIncomingSessions )
                    {
                        Logging.LogWarning($"SSU2Host: Connection limit ({MaxIncomingSessions}) reached, dropping SessionRequest from {remoteEP}");
                        return;
                    }

                    // Create new incoming session
                    session = new SSU2Session(this, remoteEP);

                    lock (SessionsLock)
                    {
                        Sessions[remoteEP] = session;
                    }

                    // Process the SessionRequest
                    session.ProcessReceivedPacket(packetData);

                    Logging.LogDebug($"SSU2Host: Created incoming session from {remoteEP}");
                }
                else if (header.Type == SSU2Header.TYPE_PEER_TEST)
                {
                    HandleIncomingPeerTestPacket(remoteEP, packetData);
                }
                else
                {
                    Logging.LogWarning($"SSU2Host: Received packet type {header.Type} from unknown endpoint {remoteEP}, have {Sessions.Count} sessions");
                    lock (SessionsLock)
                    {
                        Logging.LogWarning($"SSU2Host: Known endpoints: {string.Join(", ", Sessions.Keys)}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"SSU2Host: DispatchPacket error for {remoteEP}: {ex}");
            }
        }

        private void HandleIncomingPeerTestPacket(IPEndPoint remoteEP, byte[] packetData)
        {
            try
            {
                // PeerTest DIRECT packets (type 7) are encrypted with OUR intro key
                var myIntroKey = StaticPublicKey;

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
                Logging.LogWarning($"SSU2Host: HandleIncomingPeerTestPacket error for {remoteEP}: {ex.Message}");
            }
        }

        public void SendPacket(IPEndPoint destination, byte[] data)
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

        // ITransportProtocol implementation
        public ProtocolCapabilities ContactCapability(I2PRouterInfo router)
        {
            if (router == null)
                return ProtocolCapabilities.None;

            // Check if router has SSU2 address
            var ssu2Address = router.Addresses?.FirstOrDefault(a =>
                a.TransportStyle == "SSU2" && a.Options.Contains("s"));

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
                    Logging.LogInformation($"SSU2Host: Added outgoing session to {endpoint} (router: {router.Identity.IdentHash.Id32Short})");
                }
                else
                {
                    Logging.LogWarning($"SSU2Host: No SSU2 address found for router {router.Identity.IdentHash.Id32Short}");
                }
            }

            // Don't call Connect() here - TransportProvider will call it

            return session;
        }

        private readonly DecayingIpBlockFilter _ipBlockFilter = new();
        public int BlockedRemoteAddressesCount => _ipBlockFilter.Count;

        /// <summary>
        /// Report a problem with a remote address for rate limiting/blocking.
        /// After enough problems within the decay window, the IP is blocked.
        /// </summary>
        public void ReportConnectionProblem( IPAddress addr )
        {
            if ( addr != null ) _ipBlockFilter.ReportProblem( addr );
        }

        private void NetworkSettingsChanged()
        {
            UpdateRouterContext();

            // Reinitialize socket with new settings
            UdpSocket?.Close();
            InitializeSocket();
        }

        // SSU2 static keys (persistent across restarts)
        private byte[] StaticPublicKey;
        private byte[] StaticPrivateKey;

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
                cost: 5, // SSU2 cost (lower than NTCP2, preferred)
                transportstyle: "SSU2"
            );

            // Add SSU2-specific options per spec
            // s = base64 of intro key (32 bytes) - Bob's static public key
            // i = base64 of intro key (same as 's' for SSU2)
            // v = version (2 for SSU2)
            // caps = capabilities string
            // CRITICAL: Use I2P Base64 encoding (FreenetBase64), not standard .NET Base64!
            // I2P Base64 uses '-' and '~' instead of '+' and '/'
            addr.Options["s"] = FreenetBase64.Encode(new I2PByteBlock(StaticPublicKey));
            addr.Options["i"] = FreenetBase64.Encode(new I2PByteBlock(StaticPublicKey)); // intro key = static key
            addr.Options["v"] = "2";

            // If firewalled, include introducers
            if ( MyRouterContext.IsFirewalled )
            {
                var intros = GetActiveIntroducers();
                for ( int i = 0; i < intros.Count; i++ )
                {
                    var (hash, tag, exp) = intros[i];
                    addr.Options[$"i{i}"] = FreenetBase64.Encode( hash.Hash );
                    addr.Options[$"t{i}"] = tag.ToString();
                    addr.Options[$"exp{i}"] = exp.ToString();
                }
            }

            // Capabilities: f=firewall status, r=relay, t=peer test, p=path validation, m=migration
            var caps = new System.Text.StringBuilder();
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
            var loadedKeys = TransportKeys.LoadSSU2IntroKey();

            if (loadedKeys.HasValue)
            {
                // Use existing keys
                StaticPrivateKey = loadedKeys.Value.privateKey;
                StaticPublicKey = loadedKeys.Value.publicKey;
                Logging.LogInformation("SSU2Host: Loaded intro key from persistent storage");
            }
            else
            {
                // Generate new keys
                var (priv, pub) = X25519.GenerateKeyPair();
                StaticPrivateKey = priv;
                StaticPublicKey = pub;

                // Save to persistent storage
                TransportKeys.SaveSSU2IntroKey(StaticPrivateKey, StaticPublicKey);
                Logging.LogInformation("SSU2Host: Generated and saved new intro key");
            }
        }

        internal byte[] GetStaticPublicKey() => StaticPublicKey;
        internal byte[] GetStaticPrivateKey() => StaticPrivateKey;
        internal byte[] GetMyStaticKey() => StaticPublicKey; // Alias for intro key
        internal I2PRouterInfo GetMyRouterInfo() => MyRouterContext?.MyRouterInfo;

        public IEnumerable<SSU2Session> GetEstablishedSessions()
        {
            lock ( SessionsLock )
            {
                return Sessions.Values
                    .Where( s => s.State == SessionState.Established && !s.IsTerminated )
                    .ToArray();
            }
        }

        /// <summary>
        /// Fire ConnectionCreated event for incoming connections
        /// Called when remote identity is established
        /// </summary>
        internal void FireConnectionCreated(ITransport transport, I2PIdentHash hash)
        {
            ConnectionCreated?.Invoke(transport, hash);
        }

        /// <summary>
        /// Report external IP address as observed by remote peer
        /// Collects reports and updates RouterContext when consensus is reached
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
                if (ReportedAddresses.Count() > 10 && ReportedAddresses.All(a => BufUtils.Equal(a.GetAddressBytes(), firstbytes)))
                {
                    Logging.LogTransport($"SSU2 My IP: Start using unanimous remote reported external IP {ipaddr}");
                    UpdateSsu2ReportedAddr(ipaddr);
                }
                else
                {
                    var freq = ReportedAddresses.GroupBy(a => a.GetAddressBytes()).OrderBy(g => g.Count());
                    if (freq.First().Count() > 15)
                    {
                        Logging.LogTransport($"SSU2 My IP: Start using most frequently reported remote external IP {ipaddr}");
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
                foreach (var session in Sessions.Values)
                {
                    session.Terminate();
                }
                Sessions.Clear();
            }
        }
    }
}
