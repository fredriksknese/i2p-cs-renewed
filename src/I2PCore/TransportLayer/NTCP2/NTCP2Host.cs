using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.NTCP2
{
    /// <summary>
    /// NTCP2 (NIO-based TCP version 2) Transport Host
    /// Based on Noise Protocol Framework XK pattern
    /// Spec: https://geti2p.net/spec/ntcp2
    /// </summary>
    [TransportProtocol]
    public class NTCP2Host : ITransportProtocol
    {
        private Thread Worker;
        private readonly CancellationTokenSource MyCancellationTokenSource;
        private readonly CancellationToken MyCancellationToken;

        public bool Terminated { get; private set; }

        public event Action<ITransport, I2PIdentHash> ConnectionCreated;

        private List<NTCP2Session> Sessions = new();
        private readonly object SessionsLock = new();

        // NTCP2 static keys (persistent across restarts)
        private byte[] StaticPublicKey;
        private byte[] StaticPrivateKey;
        private byte[] IV;

        public NTCP2Host()
        {
            MyCancellationTokenSource = new CancellationTokenSource();
            MyCancellationToken = MyCancellationTokenSource.Token;

            RouterContext.Inst.NetworkSettingsChanged += NetworkSettingsChanged;

            // Load or generate static keys
            InitializeStaticKeys();

            UpdateRouterContext();

            Worker = new Thread( () => RunAsync().GetAwaiter().GetResult() )
            {
                Name = "NTCP2Host",
                IsBackground = true
            };
            Worker.Start();

            // Background task for periodic session cleanup and handshaking timeouts
            Task.Run(PeriodicCleanupLoop);
        }

        private async Task PeriodicCleanupLoop()
        {
            while (!MyCancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, MyCancellationToken);
                    CleanupSessions();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logging.LogWarning($"NTCP2Host: PeriodicCleanupLoop error: {ex.Message}");
                }
            }
        }

        private void CleanupSessions()
        {
            lock (SessionsLock)
            {
                var allSessions = Sessions.ToArray();
                foreach (var session in allSessions)
                {
                    try
                    {
                        // Tick handles both inactivity and handshake timeouts
                        session.Tick();

                        if (session.IsTerminated)
                        {
                            Sessions.Remove(session);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logging.LogDebug($"NTCP2Host: Error ticking session {session.DebugId}: {ex.Message}");
                        session.Terminate("Tick error");
                        Sessions.Remove(session);
                    }
                }
            }
        }

        private void InitializeStaticKeys()
        {
            // Try to load existing keys from persistent storage
            var loadedKeys = TransportKeys.LoadNTCP2Keys();

            if (loadedKeys.HasValue)
            {
                // Use existing keys
                StaticPrivateKey = loadedKeys.Value.privateKey;
                StaticPublicKey = loadedKeys.Value.publicKey;
                IV = loadedKeys.Value.iv;
                // DIAG: verify loaded key pair
                var derivedPub = X25519.GetPublicKey(StaticPrivateKey);
                var match = derivedPub.SequenceEqual(StaticPublicKey);
                Logging.LogInformation($"NTCP2Host: Loaded static keys. pub[0:4]={BitConverter.ToString(StaticPublicKey, 0, 4).Replace("-","")} derivedPub[0:4]={BitConverter.ToString(derivedPub, 0, 4).Replace("-","")} keyPairMatch={match}");
            }
            else
            {
                // Generate new keys with MSB check
                // CRITICAL: Static public key MUST NOT have MSB set (bit 7 of byte 31)
                // Per NTCP2 spec and i2pd RouterInfo.cpp lines 286-290:
                // If static key has MSB set, routers mark the address as invalid
                byte[] priv, pub;
                int attempts = 0;
                const int maxAttempts = 100;

                do
                {
                    attempts++;
                    (priv, pub) = X25519.GenerateKeyPair();

                    if ((pub[31] & 0x80) == 0)
                    {
                        // Valid key found
                        break;
                    }

                    if (attempts >= maxAttempts)
                    {
                        throw new InvalidOperationException("Failed to generate valid NTCP2 static key after 100 attempts");
                    }
                } while (true);

                StaticPrivateKey = priv;
                StaticPublicKey = pub;

                // DIAG: verify generated key pair
                var derivedPub2 = X25519.GetPublicKey(StaticPrivateKey);
                var match2 = derivedPub2.SequenceEqual(StaticPublicKey);
                Logging.LogInformation($"NTCP2Host: Generated valid static key (MSB clear) after {attempts} attempt(s). pub[0:4]={BitConverter.ToString(StaticPublicKey, 0, 4).Replace("-","")} keyPairMatch={match2}");

                // Generate IV for address obfuscation
                IV = BufUtils.RandomBytes(16);

                // Save to persistent storage
                TransportKeys.SaveNTCP2Keys(StaticPrivateKey, StaticPublicKey, IV);
                Logging.LogInformation("NTCP2Host: Saved new static keys to persistent storage");
            }
        }

        private async Task RunAsync()
        {
            try
            {
                Logging.LogInformation("NTCP2Host: Starting NTCP2 transport");

                while (!MyCancellationToken.IsCancellationRequested)
                {
                    var listener = CreateListener();

                    try
                    {
                        // Accept connections asynchronously
                        while (!MyCancellationToken.IsCancellationRequested && !_listenerRestartRequested)
                        {
                            TcpClient client;
                            try
                            {
                                // Use AcceptTcpClientAsync with cancellation instead of polling
                                client = await listener.AcceptTcpClientAsync( MyCancellationToken );
                            }
                            catch ( OperationCanceledException )
                            {
                                break;
                            }
                            catch ( ObjectDisposedException )
                            {
                                break;
                            }

                            var remoteEP = client.Client.RemoteEndPoint as IPEndPoint;

                            // IP blocking check
                            if (remoteEP != null && _ipBlockFilter.IsFiltered(remoteEP.Address))
                            {
                                Logging.LogWarning($"NTCP2Host: TERMINATION REASON [C#-BOB]: IP BLOCKED - rejecting connection from {remoteEP} (DecayingIpBlockFilter triggered)");
                                client.Close();
                                continue;
                            }

                            // Inbound connection limit check
                            int inboundCount;
                            lock (SessionsLock) { inboundCount = Sessions.Count(s => !s.IsOutgoing); }
                            var maxInbound = RouterContext.Inst.MaxNtcp2InboundConnections;
                            if (inboundCount >= maxInbound)
                            {
                                Logging.LogWarning($"NTCP2Host: TERMINATION REASON [C#-BOB]: Inbound connection limit reached ({maxInbound}), rejecting {remoteEP}");
                                client.Close();
                                continue;
                            }

                            // Create incoming session
                            var session = new NTCP2Session(this, client);

                            lock (SessionsLock)
                            {
                                Sessions.Add(session);
                            }

                            Logging.LogInformation($"NTCP2Host: [C#-BOB] Accepted incoming connection from {remoteEP}, session={session.DebugId}");

                            // Start async receive for handshake
                            StartAsyncReceive(session);
                        }
                    }
                    catch (Exception ex)
                    {
                        if ( !MyCancellationToken.IsCancellationRequested )
                            Logging.LogWarning($"NTCP2Host: Error: {ex}");
                    }

                    _listenerRestartRequested = false;
                    CloseListener(listener);
                    if ( !MyCancellationToken.IsCancellationRequested )
                    {
                        Logging.LogWarning( "NTCP2Host: [C#-BOB] Accept loop exited - RESTARTING listener. This gap means i2pd connections during restart will get EOF." );
                    }
                }
            }
            finally
            {
                Logging.LogInformation("NTCP2Host: Shutting down");
                Worker = null;
            }
        }

        private void CleanupTerminatedSessions()
        {
            CleanupSessions();
        }

        private TcpListener CreateListener()
        {
            var localEP = new IPEndPoint(RouterContext.Inst.LocalInterface, RouterContext.Inst.TcpPort);
            var listener = new TcpListener(localEP);
            listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Start();
            _currentListener = listener;
            Logging.LogInformation($"NTCP2Host: Listening on TCP {localEP}");
            return listener;
        }

        private void CloseListener(TcpListener listener)
        {
            try
            {
                listener?.Stop();
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"NTCP2Host: Error closing listener: {ex.Message}");
            }
        }

        private void StartAsyncReceive(NTCP2Session session)
        {
            try
            {
                var stream = session.TcpClient.GetStream();
                var buffer = new byte[8192];

                stream.BeginRead(buffer, 0, buffer.Length, (ar) =>
                {
                    try
                    {
                        var bytesRead = stream.EndRead(ar);

                        if (bytesRead > 0)
                        {
                            var data = new byte[bytesRead];
                            Array.Copy(buffer, 0, data, 0, bytesRead);

                            // Process received data
                            session.ProcessReceivedData(data);

                            // Continue receiving if session not terminated
                            if (!session.IsTerminated)
                            {
                                StartAsyncReceive(session);
                            }
                        }
                        else
                        {
                            // Connection closed
                            session.Terminate();
                        }
                    }
                    catch (Exception ex)
                    {
                        Logging.LogDebug($"NTCP2Host: Receive error for {session.DebugId}: {ex.Message}");
                        session.Terminate();
                    }
                }, null);
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"NTCP2Host: StartAsyncReceive error for {session.DebugId}: {ex}");
                session.Terminate();
            }
        }

        // ITransportProtocol implementation
        public ProtocolCapabilities ContactCapability(I2PRouterInfo router)
        {
            if (router == null)
                return ProtocolCapabilities.None;

            // Check if router has NTCP2 address
            var ntcp2Address = router.Addresses?.FirstOrDefault(a =>
                a.TransportStyle == "NTCP2" && a.Options.Contains("s"));

            if (ntcp2Address == null)
                return ProtocolCapabilities.None;

            // Has published address - can connect directly
            if (ntcp2Address.Options.Contains("host") && ntcp2Address.Options.Contains("port"))
                return ProtocolCapabilities.Incoming;

            // Unpublished address - outgoing only
            return ProtocolCapabilities.Outgoing;
        }

        public ITransport AddSession(I2PRouterInfo router)
        {
            if (router == null)
                throw new ArgumentNullException(nameof(router));

            // Outbound connection limit check
            int outboundCount;
            lock (SessionsLock) { outboundCount = Sessions.Count(s => s.IsOutgoing); }
            var maxOutbound = RouterContext.Inst.MaxNtcp2OutboundConnections;
            if (outboundCount >= maxOutbound)
            {
                Logging.LogWarning($"NTCP2Host: TERMINATION REASON [C#-BOB]: Outbound connection limit reached ({maxOutbound}), rejecting outbound to {router.Identity?.IdentHash?.Id32Short}");
                return null;
            }

            // Create new outgoing session
            var session = new NTCP2Session(this, router, true);

            lock (SessionsLock)
            {
                Sessions.Add(session);
            }

            // Don't call Connect() here - TransportProvider will call it

            return session;
        }

        // IP blocking
        private readonly DecayingIpBlockFilter _ipBlockFilter = new();
        public int BlockedRemoteAddressesCount => _ipBlockFilter.Count;

        /// <summary>
        /// Report a problem with a remote address for potential blocking
        /// </summary>
        public void ReportProblem(System.Net.IPAddress addr)
        {
            _ipBlockFilter.ReportProblem(addr);
        }

        private volatile bool _listenerRestartRequested;

        private TcpListener _currentListener;

        private void NetworkSettingsChanged()
        {
            UpdateRouterContext();
            // Signal the listener loop to close and re-create with new settings
            _listenerRestartRequested = true;
            // Stop the current listener to unblock AcceptTcpClientAsync
            try { _currentListener?.Stop(); } catch { }
        }

        private void UpdateRouterContext()
        {
            // Build NTCP2 router address with the EXTERNAL address (not the listen address).
            // LocalInterface (0.0.0.0) is for binding; the published address must be routable.
            var publishedAddress = RouterContext.Inst.ExtIpv4Address
                                ?? RouterContext.Inst.DefaultExtAddress;

            if (publishedAddress == null || publishedAddress.Equals(IPAddress.Any) || publishedAddress.Equals(IPAddress.IPv6Any))
            {
                Logging.LogWarning("NTCP2Host: No external IP address available yet. Skipping NTCP2 address publication.");
                RouterContext.Inst.UpdateAddress(this, null);
                return;
            }

            var addr = new I2PRouterAddress(
                publishedAddress,
                RouterContext.Inst.TcpPort,
                cost: 10, // NTCP2 cost
                transportstyle: "NTCP2"
            );

            // Add NTCP2-specific options per spec
            // s = base64 of static public key (32 bytes)
            // i = base64 of IV (16 bytes)
            // v = version (2 for NTCP2)
            // CRITICAL: Use I2P Base64 encoding (FreenetBase64) not standard Base64!
            // I2P Base64 uses '-' and '~' instead of '+' and '/'
            addr.Options["s"] = FreenetBase64.Encode(new I2PByteBlock(StaticPublicKey));
            addr.Options["i"] = FreenetBase64.Encode(new I2PByteBlock(IV));
            // v = version: MUST be "2" per i2pd RouterInfo.cpp line 310
            // i2pd marks the address as invalid if v != "2"
            // Post-quantum is indicated via separate "pq" option, not "v"
            addr.Options["v"] = "2";

            // Publish to RouterContext
            var addresses = new List<I2PRouterAddress> { addr };
            RouterContext.Inst.UpdateAddress(this, addresses);

            Logging.LogInformation($"NTCP2Host: Published address to RouterInfo (port {RouterContext.Inst.TcpPort})");
        }

        public void Terminate()
        {
            Terminated = true;
            MyCancellationTokenSource.Cancel();

            // Terminate all sessions
            lock (SessionsLock)
            {
                foreach (var session in Sessions)
                {
                    session.Terminate();
                }
                Sessions.Clear();
            }
        }

        internal byte[] GetStaticPublicKey() => StaticPublicKey;
        internal byte[] GetStaticPrivateKey() => StaticPrivateKey;
        internal byte[] GetIV() => IV;
        internal I2PRouterInfo GetMyRouterInfo() => RouterContext.Inst?.MyRouterInfo;

        /// <summary>
        /// Fire ConnectionCreated event for incoming connections
        /// Called when remote identity is established
        /// </summary>
        internal void FireConnectionCreated(ITransport transport, I2PIdentHash hash)
        {
            ConnectionCreated?.Invoke(transport, hash);
        }

        /// <summary>
        /// Get router hash (32 bytes) - This is the SHA-256 hash of our RouterIdentity
        /// Used as the AES key for ephemeral key obfuscation in NTCP2
        /// Per spec lines 366-383: key = router hash
        /// </summary>
        internal byte[] GetRouterHash()
        {
            var myRouterInfo = RouterContext.Inst?.MyRouterInfo;
            if (myRouterInfo?.Identity?.IdentHash?.Hash != null)
            {
                return myRouterInfo.Identity.IdentHash.Hash.ToByteArray();
            }

            // Fallback: Use SHA-256 of static public key if RouterInfo not available
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                return sha256.ComputeHash(StaticPublicKey);
            }
        }

        internal int GetPublishedPQVersion()
        {
            var myRI = GetMyRouterInfo();
            var ntcp2Addr = myRI?.Addresses?.FirstOrDefault( a => a.TransportStyle == "NTCP2" );
            if ( ntcp2Addr != null && ntcp2Addr.Options.Contains( "pq" ) && int.TryParse( ntcp2Addr.Options["pq"], out var pq ) )
                return pq;

            return 0; // PQ not advertised
        }
    }
}
