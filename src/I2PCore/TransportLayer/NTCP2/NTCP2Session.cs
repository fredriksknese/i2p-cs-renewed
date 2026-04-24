using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TransportLayer.Crypto;
using I2PCore.TransportLayer.NTCP2.Messages;
using I2PCore.TransportLayer.Log;

namespace I2PCore.TransportLayer.NTCP2
{
    /// <summary>
    /// NTCP2 Session State
    /// Tracks the handshake and data phase state
    /// </summary>
    public enum NTCP2SessionState
    {
        Initial,
        SessionRequestSent,
        SessionRequestReceived,
        SessionCreatedSent,
        SessionCreatedReceived,
        SessionConfirmedSent,
        SessionConfirmedReceived,
        Established,
        Terminated
    }

    /// <summary>
    /// Represents an NTCP2 session
    /// Implements Noise XK handshake pattern over TCP and ITransport interface
    /// </summary>
    public class NTCP2Session : ITransport
    {
        // ITransport events
        public event Action<ITransport, Exception> ConnectionException;
        public event Action<ITransport> ConnectionShutDown;
        public event Action<ITransport, I2PIdentHash> ConnectionEstablished;
        public event Action<ITransport, Ii2NpHeader> DataBlockReceived;

        public TcpClient TcpClient { get; private set; }
        public NTCP2SessionState State { get; private set; }
        public bool IsTerminated { get; private set; }
        public bool IsOutgoing { get; private set; }

        // ITransport properties
        public IPAddress RemoteAddress => (TcpClient?.Client?.RemoteEndPoint as IPEndPoint)?.Address;
        public I2PKeysAndCert RemoteRouterIdentity => RemoteRouterInfo?.Identity;
        public long BytesSent { get; private set; }
        public long BytesReceived { get; private set; }
        public string DebugId { get; private set; }
        public string Protocol => "NTCP2";
        public bool IsPQ => IsPQSession;
        
        private readonly NTCP2Host Host;
        public I2PRouterInfo RemoteRouterInfo { get; private set; }

        // Noise protocol state
        private NoiseXK NoiseState;
        
        // AES state (last 16 bytes of obfuscated X) for Message 2 continuation
        private byte[] AESStateAfterMsg1;

        // ML-KEM post-quantum hybrid state
        private bool IsPQSession;
        private int PQVersion; // 3=MLKEM512, 4=MLKEM768, 5=MLKEM1024
        private byte[] LocalKemPublicKey;
        private byte[] LocalKemSecretKey;
        private byte[] RemoteKemPublicKey;

        // Session keys (after handshake)
        private byte[] SendKey;
        private byte[] ReceiveKey;

        // Saved Noise state before Split() clears the chaining key.
        // Needed for SipHash key derivation which uses the original CK.
        private byte[] PreSplitChainingKey;
        private byte[] PreSplitHash;

        // Saved RouterInfo for SessionConfirmed consistency
        private byte[] CachedMyRouterInfoBytes;
        private ushort CachedM3P2Len;
        private ushort RemoteM3P2Len;
        private byte RemoteNetworkId;
        private byte RemoteVersion;
        private bool ClockSkewDetected;

        private bool HandshakeDecrypted = false;
        private byte[] HandshakeDecryptedOptions;
        private int HandshakePaddingLen;

        // SipHash keys for frame length obfuscation
        private NTCP2SipHash SendSipHash;
        private NTCP2SipHash ReceiveSipHash;

        // Frame counters
        private ulong SendNonce = 0;
        private ulong ReceiveNonce = 0;
        private bool DateTimeBlockSent = false;
        private long NextRouterInfoResendTime = 0;
        private long LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        private PeriodicAction KeepAlive = new PeriodicAction(TickSpan.Minutes(2));

        // Receive buffer for assembling frames
        private byte[] ReceiveBuffer = new byte[131072]; // 128KB to handle max frames (64KB payload + 2B len)
        private int ReceiveBufferPos = 0;

        // Constructor for outgoing connections
        public NTCP2Session(NTCP2Host host, I2PRouterInfo remoteRouter, bool isOutgoing)
        {
            Host = host;
            RemoteRouterInfo = remoteRouter;
            IsOutgoing = isOutgoing;
            State = NTCP2SessionState.Initial;
            DebugId = $"NTCP2-{(isOutgoing ? "Out" : "In")}-{BufUtils.RandomUint():X8}";

            TransportConnectionLogger.Inst.Log($"Created outbound NTCP2 session to {RemoteRouterInfo?.Identity?.IdentHash?.Id32Short}", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
        }

        // Constructor for incoming connections
        public NTCP2Session(NTCP2Host host, TcpClient client)
        {
            Host = host;
            TcpClient = client;
            IsOutgoing = false;
            State = NTCP2SessionState.Initial;
            DebugId = $"NTCP2-In-{BufUtils.RandomUint():X8}";

            TransportConnectionLogger.Inst.Log("Accepted inbound NTCP2 connection", null, "NTCP2", "Inbound");
        }

        public void Connect()
        {
            if (!IsOutgoing)
                throw new InvalidOperationException("Cannot call Connect on incoming session");

            if (State != NTCP2SessionState.Initial)
                throw new InvalidOperationException($"Cannot connect from state {State}");

            try
            {
                // Extract endpoint from RouterInfo
                var endpoint = ExtractRemoteEndpoint();

                // Create TCP connection (optionally through SOCKS5 proxy)
                TcpClient = new TcpClient();

                if ( Socks5Client.UsingProxy )
                {
                    Socks5Client.ConnectThroughProxy( TcpClient, endpoint );
                    Logging.LogDebug( $"{DebugId}: TCP connected to {endpoint} via SOCKS5 proxy" );
                    TransportConnectionLogger.Inst.Log($"TCP connected to {endpoint} via SOCKS5 proxy", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
                }
                else
                {
                    TcpClient.Connect( endpoint );
                    Logging.LogDebug( $"{DebugId}: TCP connected to {endpoint}" );
                    TransportConnectionLogger.Inst.Log($"TCP connected to {endpoint}", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
                }

                // Initialize Noise protocol as Alice (initiator)
                InitializeNoiseAsAlice();

                // Send SessionRequest
                SendSessionRequest();

                State = NTCP2SessionState.SessionRequestSent;

                // Start receiving responses
                StartReceiveLoop();
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{DebugId}: Connect failed: {ex}");
                TransportConnectionLogger.Inst.Log($"Connect failed: {ex.Message}", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
                ConnectionException?.Invoke(this, ex);
                Terminate();
            }
        }

        public void Send(I2NpMessage msg)
        {
            if (State != NTCP2SessionState.Established)
            {
                Logging.LogWarning($"{DebugId}: Cannot send, session not established");
                return;
            }

            try
            {
                // Build data frame with I2NP message
                var encrypted = BuildDataFrame(msg);

                Logging.LogDebug($"{DebugId}: Sending data frame ({encrypted.Length} bytes) with {msg.MessageType}");

                // Send via TCP
                var stream = TcpClient.GetStream();
                stream.Write(encrypted, 0, encrypted.Length);

                BytesSent += encrypted.Length;
                LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{DebugId}: Send failed: {ex}");
                ConnectionException?.Invoke(this, ex);
            }
        }

        public void DatabaseStoreMessageReceived(DatabaseStoreMessage dsm)
        {
            // NTCP2 doesn't use DatabaseStore messages in handshake
            // Pass to higher layers if needed
        }

        private void StartReceiveLoop()
        {
            Task.Run(async () =>
            {
                try
                {
                    var stream = TcpClient.GetStream();
                    var buffer = new byte[8192];

                    // No socket-level read timeout — rely on Tick() inactivity detection (5 min)
                    // and keep-alive sends (every 2 min) to handle unresponsive peers.
                    // Must use -1 (Timeout.Infinite); 0 is invalid for NetworkStream.ReadTimeout.
                    stream.ReadTimeout = System.Threading.Timeout.Infinite;

                    Logging.LogDebug($"{DebugId}: Receive loop started, waiting for response...");

                    while (!IsTerminated && TcpClient.Connected)
                    {
                        int bytesRead;
                        try
                        {
                            bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                        }
                        catch (System.IO.IOException ex) when (ex.InnerException is System.Net.Sockets.SocketException socketEx && socketEx.SocketErrorCode == System.Net.Sockets.SocketError.TimedOut)
                        {
                            Logging.LogWarning($"{DebugId}: Read timeout, no response from remote - terminating");
                            Terminate("Read timeout");
                            break;
                        }
                        catch (System.IO.IOException ex)
                        {
                            Logging.LogWarning($"{DebugId}: Read I/O error: {ex.Message}");
                            Terminate($"Read I/O error: {ex.Message}");
                            break;
                        }
                        if (bytesRead == 0)
                        {
                            // Connection closed
                            Logging.LogDebug($"{DebugId}: Connection closed by remote (0 bytes read)");
                            Terminate("EOF");
                            break;
                        }

                        BytesReceived += bytesRead;
                        LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                        // Log received data
                        var dataPreview = bytesRead <= 64 
                            ? BitConverter.ToString(buffer, 0, bytesRead).Replace("-", " ")
                            : BitConverter.ToString(buffer, 0, 64).Replace("-", " ") + "...";
                        
                        Logging.LogDebug($"{DebugId}: Received {bytesRead} bytes in state {State}: {dataPreview}");

                        // Process received data
                        var data = new byte[bytesRead];
                        Array.Copy(buffer, data, bytesRead);
                        ProcessReceivedData(data);
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"{DebugId}: Receive loop error: {ex.Message}");
                    Terminate();
                }
            });
        }

        public void Tick()
        {
            if (IsTerminated || State != NTCP2SessionState.Established) return;

            // Inactivity timeout (5 minutes)
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now - LastActivityTime > 300)
            {
                Logging.LogInformation($"{DebugId}: Inactivity timeout (5 minutes)");
                Terminate("Inactivity timeout (5m)");
                return;
            }

            // Keep-alive (DateTime block)
            KeepAlive.Do(() =>
            {
                if (IsTerminated) return;
                Logging.LogDebug($"{DebugId}: Sending keep-alive (DateTime block)");
                var frame = new NTCP2DataFrame();
                frame.AddBlock(new NTCP2DateTimeBlock());
                // Add some random padding to keep frame sizes varied
                frame.AddBlock(new NTCP2PaddingBlock(16 + (int)BufUtils.RandomInt(48)));
                
                var encrypted = frame.BuildEncryptedFrame(NoiseState, SendSipHash);
                try {
                    var stream = TcpClient.GetStream();
                    stream.Write(encrypted, 0, encrypted.Length);
                    BytesSent += encrypted.Length;
                    LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                } catch (Exception ex) {
                    Logging.LogDebug($"{DebugId}: Keep-alive send failed: {ex.Message}");
                }
            });

            // RouterInfo resend
            if (NextRouterInfoResendTime > 0 && now > NextRouterInfoResendTime)
            {
                SendRouterInfo();
            }
        }

        public void Terminate(string reason = null)
        {
            if (IsTerminated)
                return;

            IsTerminated = true;
            State = NTCP2SessionState.Terminated;

            var logMsg = string.IsNullOrEmpty(reason) ? "Session terminated" : $"Session terminated: {reason}";
            Logging.LogDebug($"{DebugId}: {logMsg}");
            TransportConnectionLogger.Inst.Log(logMsg, RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", IsOutgoing ? "Outbound" : "Inbound");

            try
            {
                TcpClient?.Close();
            }
            catch { }

            ClearSensitiveData();

            ConnectionShutDown?.Invoke(this);
        }

        private IPEndPoint ExtractRemoteEndpoint()
        {
            // Find NTCP2 address in router info
            var ntcp2Address = RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
                a.TransportStyle == "NTCP2" && a.Options.Contains("host") &&
                (RouterContext.UseIpV6 || !IPAddress.TryParse(a.Options["host"], out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6));

            if (ntcp2Address == null)
                throw new ArgumentException("No suitable NTCP2 address found in RouterInfo (IPv6 might be disabled)");

            var host = ntcp2Address.Options["host"];
            var port = int.Parse(ntcp2Address.Options["port"]);
            var ipAddress = IPAddress.Parse(host);

            return new IPEndPoint(ipAddress, port);
        }

        /// <summary>
        /// Check if the remote peer supports ML-KEM post-quantum in NTCP2.
        /// Returns version 3/4/5 for ML-KEM-512/768/1024, or 0 for no PQ.
        /// </summary>
        private int DetectRemotePQVersion()
        {
            var ntcp2Address = RemoteRouterInfo?.Addresses?.FirstOrDefault( a =>
                a.TransportStyle == "NTCP2" && a.Options.Contains( "v" ) );

            if ( ntcp2Address == null ) return 0;

            // Spec lines 664-665: v=2 and pq=[3|4|5]
            if ( ntcp2Address.Options.Contains( "pq" ) && int.TryParse( ntcp2Address.Options["pq"], out var pq ) )
                return pq;

            // Spec lines 673-677: v=[3|4|5] (future)
            if ( int.TryParse( ntcp2Address.Options["v"], out var version ) && version >= 3 && version <= 5 )
                return version;

            return 0;
        }

        private void GenerateMLKEMKeyPair( int pqVersion )
        {
            switch ( pqVersion )
            {
                case 3:
                    (LocalKemPublicKey, LocalKemSecretKey) = I2PCore.Crypto.MLKEM.MLKEM512.GenerateKeyPair();
                    break;
                case 4:
                    (LocalKemPublicKey, LocalKemSecretKey) = I2PCore.Crypto.MLKEM.MLKEM768.GenerateKeyPair();
                    break;
                case 5:
                    (LocalKemPublicKey, LocalKemSecretKey) = I2PCore.Crypto.MLKEM.MLKEM1024.GenerateKeyPair();
                    break;
            }
        }

        private (byte[] ciphertext, byte[] sharedSecret) EncapsulateMLKEM( byte[] publicKey, int pqVersion )
        {
            return pqVersion switch
            {
                3 => I2PCore.Crypto.MLKEM.MLKEM512.Encapsulate( publicKey ),
                4 => I2PCore.Crypto.MLKEM.MLKEM768.Encapsulate( publicKey ),
                5 => I2PCore.Crypto.MLKEM.MLKEM1024.Encapsulate( publicKey ),
                _ => throw new ArgumentException( $"Invalid PQ version: {pqVersion}" )
            };
        }

        private byte[] DecapsulateMLKEM( byte[] ciphertext, byte[] secretKey, int pqVersion )
        {
            return pqVersion switch
            {
                3 => I2PCore.Crypto.MLKEM.MLKEM512.Decapsulate( ciphertext, secretKey ),
                4 => I2PCore.Crypto.MLKEM.MLKEM768.Decapsulate( ciphertext, secretKey ),
                5 => I2PCore.Crypto.MLKEM.MLKEM1024.Decapsulate( ciphertext, secretKey ),
                _ => throw new ArgumentException( $"Invalid PQ version: {pqVersion}" )
            };
        }

        private void InitializeNoiseAsAlice()
        {
            // Get Bob's static key from RouterInfo
            var bobStaticKey = GetRemoteStaticKey();

            // Check for PQ support: only use PQ if BOTH remote AND we support it.
            // i2pd rejects PQ sessions from routers without an ML-KEM crypto type
            // (see i2pd NTCP2.cpp ProcessSessionRequestMessage: m_CryptoType check).
            PQVersion = DetectRemotePQVersion();
            int ourPQVersion = Host.GetPublishedPQVersion();
            IsPQSession = ourPQVersion >= 3 && PQVersion >= 3 && PQVersion <= 5;
            Logging.LogDebug( $"{DebugId}: InitializeNoiseAsAlice: remotePQVersion={PQVersion}, ourPQVersion={ourPQVersion}, IsPQSession={IsPQSession}" );

            var protocolName = NoiseXK.PROTOCOL_NAME_NTCP2;
            if ( IsPQSession )
            {
                protocolName = PQVersion switch
                {
                    3 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM512,
                    4 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM768,
                    5 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM1024,
                    _ => NoiseXK.PROTOCOL_NAME_NTCP2
                };
            }

            // Initialize Noise XK as Alice
            NoiseState = new NoiseXK(protocolName);

            // Use our persistent static keys from NTCP2Host (NOT random keys!)
            var alicePriv = Host.GetStaticPrivateKey();
            var alicePub = Host.GetStaticPublicKey();

            NoiseState.InitializeAsAlice(alicePriv, alicePub, bobStaticKey);
        }

        private byte[] GetRemoteStaticKey()
        {
            // Extract static key from RouterInfo address.
            // Spec line 1348: can be published as "NTCP" or "NTCP2".
            var address = RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
                (a.TransportStyle == "NTCP2" || a.TransportStyle == "NTCP") && a.Options.Contains("s"));

            if (address == null || !address.Options.Contains("s"))
                throw new ArgumentException("No NTCP2 static key in RouterInfo");

            var base64Key = address.Options["s"];
            return FreenetBase64.Decode(base64Key);
        }

        private byte[] GetRemoteIV()
        {
            // Extract IV from RouterInfo address.
            // Spec line 1348: can be published as "NTCP" or "NTCP2".
            var address = RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
                (a.TransportStyle == "NTCP2" || a.TransportStyle == "NTCP") && a.Options.Contains("i"));

            if (address == null || !address.Options.Contains("i"))
                throw new ArgumentException("No NTCP2 IV in RouterInfo");

            var base64IV = address.Options["i"];
            return FreenetBase64.Decode(base64IV);
        }

        private void SendSessionRequest()
        {
            // Build options block for SessionRequest payload
            // Choose a random padding length. 
            // 0.9.69 allows up to 880 bytes for SessionRequest.
            // i2pd picks padding based on handshake size; we keep it reasonable (0-256)
            var rng = new Random();
            var paddingLen = rng.Next(0, 257);

            // NTCP2 Spec line 392: limit to 287 bytes total for NTCP style addresses.
            // (32 bytes X + 32 bytes encrypted options/MAC = 64 bytes)
            if (!IsPQSession && RemoteRouterInfo?.Addresses.Any(a => a.TransportStyle == "NTCP") == true)
            {
                paddingLen = Math.Min(paddingLen, 287 - 64);
            }

            var payload = BuildRequestPayload(paddingLen);

            Logging.LogDebug($"{DebugId}: Built SessionRequest payload: {BitConverter.ToString(payload).Replace("-", " ")}");

            // Get Bob's router hash and IV for AES obfuscation
            var bobRouterHash = RemoteRouterInfo.Identity.IdentHash.Hash.ToByteArray();
            var bobIV = GetRemoteIV();

            // DIAG: Log keys used to obfuscate (should match i2pd's DIAG-Bob log)
            var remoteStaticKey = GetRemoteStaticKey();
            Logging.LogInformation( $"{DebugId}: DIAG-Alice SendSR bobHash[0:4]={BitConverter.ToString(bobRouterHash, 0, 4).Replace("-","")} bobIV[0:4]={BitConverter.ToString(bobIV, 0, 4).Replace("-","")} bobS[0:4]={BitConverter.ToString(remoteStaticKey, 0, 4).Replace("-","")} IsPQ={IsPQSession}" );

            // Generate ephemeral keys for Alice with MSB check loop (probing resistance)
            byte[] ephKey;
            byte[] obfuscatedKey;
            int attempts = 0;
            do {
                ephKey = NoiseState.GenerateAliceEphemeralKeys();

                // Signal PQ via MSB of X (spec line 363 in ntcp2-hybrid.md)
                if ( IsPQSession ) ephKey[31] |= 0x80;
                else ephKey[31] &= 0x7f;

                obfuscatedKey = AESObfuscation.Encrypt(ephKey, bobRouterHash, bobIV);
                attempts++;
                // Probing resistance: MSB of *obfuscated* key must be 0
            } while (!NTCP2ProbingResistance.CheckMSB(obfuscatedKey));

            if (attempts > 1)
            {
                Logging.LogDebug($"{DebugId}: Generated valid obfuscated key after {attempts} attempts");
            }

            // Create message 1 with these keys
            byte[] encryptedPQFrame = null;
            byte[] encryptedPayload;

            if ( IsPQSession )
            {
                // Hybrid Handshake Message 1: -> e, es, e1, p
                var cipherKey = NoiseState.PerformMessage1EphemeralAndES();
                
                GenerateMLKEMKeyPair( PQVersion );
                encryptedPQFrame = NoiseState.EncryptHandshakeBlock( cipherKey, LocalKemPublicKey );
                
                // Payload (options) uses n=1
                encryptedPayload = NoiseState.EncryptHandshakeBlock( cipherKey, payload );
            }
            else
            {
                // Standard Handshake Message 1: -> e, es, p
                (var key, encryptedPayload) = NoiseState.CreateMessage1WithCurrentKeys(payload);
            }

            // Add padding
            var padding = paddingLen > 0 ? new byte[paddingLen] : Array.Empty<byte>();
            if (paddingLen > 0)
            {
                rng.NextBytes(padding);
            }

            // Send to TCP stream
            var stream = TcpClient.GetStream();
            stream.Write(obfuscatedKey, 0, obfuscatedKey.Length);

            // Store AES state for Message 2 deobfuscation
            AESStateAfterMsg1 = new byte[16];
            Array.Copy(obfuscatedKey, 16, AESStateAfterMsg1, 0, 16);

            if ( IsPQSession && encryptedPQFrame != null )
            {
                stream.Write(encryptedPQFrame, 0, encryptedPQFrame.Length);
            }
            stream.Write(encryptedPayload, 0, encryptedPayload.Length);
            
            if (paddingLen > 0)
            {
                stream.Write(padding, 0, padding.Length);
            }
            // Per NTCP2 spec lines 586-596: Alice must MixHash padding after sending Message 1
            NoiseState.MixHashPadding(padding);

            stream.Flush();

            BytesSent += obfuscatedKey.Length + (encryptedPQFrame?.Length ?? 0) + encryptedPayload.Length + paddingLen;

            Logging.LogInformation($"{DebugId}: SessionRequest sent ({BytesSent} total bytes) to {TcpClient.Client.RemoteEndPoint}");
        }

        private byte[] BuildRequestPayload(int paddingLen)
        {
            // Build options block for SessionRequest
            var payload = new byte[16];
            var writer = new BufRefLen(payload);

            // Per i2pd, timestamp is rounded to seconds with +500ms bias
            var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var timestamp = (uint)((nowMs + 500) / 1000);

            // Calculate m3p2len - the length of message 3 part 2 (encrypted)
            // Per NTCP2 spec and Java implementation:
            // Message 3 part 2 contains NTCP2 payload blocks:
            // 1. RouterInfo block: BLOCK_HEADER (3) + flood flag (1) + RouterInfo data
            // 2. Options block: BLOCK_HEADER (3) + options data (12)
            // 3. AEAD MAC (16 bytes)

            var myRouterInfo = Host.GetMyRouterInfo();
            var riStream = new BufRefStream();
            myRouterInfo.Write(riStream);
            CachedMyRouterInfoBytes = riStream.ToArray();

            // Calculate total payload size (without MAC - that's added by Noise)
            // RI Format: type (1) + length (2) + flood flag (1) + RouterInfo data
            int totalPart2PayloadSize = (1 + 2 + 1 + CachedMyRouterInfoBytes.Length);
            
            // Options Format: type (1) + length (2) + options data (12)
            totalPart2PayloadSize += (1 + 2 + 12);

            // i2pd compatibility: m3p2len in options block must INCLUDE the 16-byte MAC.
            // Spec says including, and i2pd's m3p2Len = bufLen + 4 + 16.
            CachedM3P2Len = (ushort)(totalPart2PayloadSize + 16); 

            writer.Write8((byte)I2PCore.Data.I2PConstants.I2PNetworkId);  // NetworkId (byte 0)
            writer.Write8(2);  // Version (byte 1)
            writer.WriteFlip16((ushort)paddingLen);  // Padding length (bytes 2-3)
            writer.WriteFlip16(CachedM3P2Len);  // m3p2len (bytes 4-5, 16-bit per i2pd)
            writer.WriteFlip16(0);  // Reserved (bytes 6-7)
            writer.WriteFlip32(timestamp);  // tsA (bytes 8-11)
            writer.WriteFlip32(0);  // Reserved (bytes 12-15)

            Logging.LogDebug($"{DebugId}: BuildRequestPayload - NetworkId={I2PCore.Data.I2PConstants.I2PNetworkId}, Version=2, PaddingLen={paddingLen}, m3p2len={CachedM3P2Len}, timestamp={timestamp}");

            return payload;
        }

        private void UpdateNextRouterInfoResendTime()
        {
            var random = new Random();
            NextRouterInfoResendTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 
                                       1500 + random.Next(1500); // 25-50 minutes
        }

        public void SendRouterInfo()
        {
            if (State != NTCP2SessionState.Established) return;

            var myRouterInfo = Host.GetMyRouterInfo();
            if (myRouterInfo == null) return;

            // i2pd NTCP2.cpp SendRouterInfo() implementation:
            // 1. DateTime block
            // 2. RouterInfo block
            // 3. Padding block (optional but recommended)
            var frame = new NTCP2DataFrame();
            frame.AddBlock(new NTCP2DateTimeBlock());
            DateTimeBlockSent = true;

            // RouterInfo block (Type 2)
            byte flags = 0;
            if (RouterContext.Inst.FloodfillEnabled) flags |= 0x01; // bit 0: flood

            var riBlock = new NTCP2RouterInfoBlock { RouterInfo = myRouterInfo, Flags = flags };
            frame.AddBlock(riBlock);

            // Add some padding per i2pd: random length up to 32 bytes
            var random = new Random();
            frame.AddBlock(new NTCP2PaddingBlock(random.Next(32)));

            Logging.LogInformation($"{DebugId}: Sending RouterInfo as data frame");
            SendDataFrame(frame);

            // Update resend time
            UpdateNextRouterInfoResendTime();
        }

        private void SendDataFrame(NTCP2DataFrame dataFrame)
        {
            if (State != NTCP2SessionState.Established)
            {
                Logging.LogWarning($"{DebugId}: Cannot send data frame, session not established");
                return;
            }

            try
            {
                // Encrypt and build complete frame with SipHash obfuscation
                var frame = dataFrame.BuildEncryptedFrame(
                    NoiseState,
                    SendSipHash
                );

                // Send via TCP
                var stream = TcpClient.GetStream();
                if (stream != null && stream.CanWrite)
                {
                    stream.Write(frame, 0, frame.Length);
                    stream.Flush();
                }

                BytesSent += frame.Length;
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{DebugId}: SendDataFrame failed: {ex}");
                ConnectionException?.Invoke(this, ex);
            }
        }

        private byte[] BuildDataFrame(I2NpMessage msg)
        {
            // Build NTCP2 data frame with I2NP message using NTCP2DataFrame
            // The first frame MUST contain a DateTime block
            var dataFrame = NTCP2DataFrame.BuildWithI2NPMessage(msg, !DateTimeBlockSent);
            DateTimeBlockSent = true;

            // Encrypt and build complete frame with SipHash obfuscation
            return dataFrame.BuildEncryptedFrame(
                NoiseState,
                SendSipHash
            );
        }

        public void ProcessReceivedData(byte[] data)
        {
            try
            {
                // Append to receive buffer
                Array.Copy(data, 0, ReceiveBuffer, ReceiveBufferPos, data.Length);
                ReceiveBufferPos += data.Length;

                // Process based on current state
                switch (State)
                {
                    case NTCP2SessionState.Initial:
                        // Waiting for SessionRequest (obfuscated key + encrypted payload)
                        if (ReceiveBufferPos >= 32 + 16) // Min size: 32 key + 16 MAC
                        {
                            ProcessSessionRequest();
                        }
                        break;

                    case NTCP2SessionState.SessionRequestSent:
                        // Waiting for SessionCreated (obfuscated key + encrypted payload)
                        if (ReceiveBufferPos >= 32 + 16)
                        {
                            ProcessSessionCreated();
                        }
                        break;

                    case NTCP2SessionState.SessionCreatedSent:
                        // Waiting for SessionConfirmed (encrypted static key + encrypted payload)
                        if (ReceiveBufferPos >= 48 + 16) // 48 encrypted key + payload
                        {
                            ProcessSessionConfirmed();
                        }
                        break;

                    case NTCP2SessionState.Established:
                        // Data phase - process frames
                        ProcessDataFrames();
                        break;
                }

                BytesReceived += data.Length;
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{DebugId}: ProcessReceivedData failed: {ex}");
                ConnectionException?.Invoke(this, ex);
                Terminate();
            }
        }

        private void ProcessSessionRequest()
        {
            if (ReceiveBufferPos < 32 + 32) // Minimum: 32-byte obfuscated X + 32-byte encrypted options
                return;

            // Deobfuscate ephemeral key with AES-256-CBC
            var ourRouterHash = Host.GetRouterHash(); // Our router's hash (32 bytes)
            var ourIV = Host.GetIV(); // Our published IV (16 bytes)

            var obfuscatedKey = new byte[32];
            Array.Copy(ReceiveBuffer, 0, obfuscatedKey, 0, 32);

            // DIAG: Log keys used for deobfuscation (should match i2pd's DIAG-Alice log)
            Logging.LogInformation( $"{DebugId}: DIAG-Bob ProcessSR ourHash[0:4]={BitConverter.ToString(ourRouterHash, 0, 4).Replace("-","")} ourIV[0:4]={BitConverter.ToString(ourIV, 0, 4).Replace("-","")} ourS[0:4]={BitConverter.ToString(Host.GetStaticPublicKey(), 0, 4).Replace("-","")} rcvdBuf[0:4]={BitConverter.ToString(obfuscatedKey, 0, 4).Replace("-","")}" );

            // Replay protection (spec line 505)
            if (!NTCP2SecurityValidator.CheckAndAddEncryptedToReplayCache(obfuscatedKey))
            {
                Logging.LogWarning($"{DebugId}: TERMINATION REASON [C#-BOB]: SessionRequest replay detected - same obfuscated key seen before (possible reconnect within 240s window)");
                Terminate();
                return;
            }

            var ephemeralKey = AESObfuscation.Decrypt(obfuscatedKey, ourRouterHash, ourIV);

            // Store AES state for Message 2 obfuscation
            AESStateAfterMsg1 = new byte[16];
            Array.Copy(obfuscatedKey, 16, AESStateAfterMsg1, 0, 16);

            // PQ detection via MSB of X (spec lines 365-367 in ntcp2-hybrid.md)
            bool isPQ = (ephemeralKey[31] & 0x80) != 0;

            // Only accept PQ if we support it and have a version published
            int ourPQVersion = Host.GetPublishedPQVersion();
            bool acceptPQ = isPQ && ourPQVersion != 0;

            if ( acceptPQ )
            {
                ephemeralKey[31] &= 0x7f; // Clear for Noise/X25519
            }

            int pqKeyLen = acceptPQ ? ourPQVersion switch
            {
                3 => 800,
                4 => 1184,
                5 => 1568,
                _ => 0
            } : 0;

            // payloadOffset uses acceptPQ (not raw isPQ) to avoid reading wrong offset
            // when a non-PQ router's key happens to have bit 7 set
            int payloadOffset = 32 + (acceptPQ ? (pqKeyLen + 16) : 0);
            int minSize = payloadOffset + 32;

            if (ReceiveBufferPos < minSize) return;

            if (!HandshakeDecrypted)
            {
                IsPQSession = acceptPQ;
                if (IsPQSession) PQVersion = ourPQVersion;

                var protocolName = IsPQSession ? PQVersion switch
                {
                    3 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM512,
                    4 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM768,
                    5 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM1024,
                    _ => NoiseXK.PROTOCOL_NAME_NTCP2
                } : NoiseXK.PROTOCOL_NAME_NTCP2;

                InitializeNoiseAsBob( protocolName );

                byte[] cipherKey = null;
                if ( IsPQSession )
                {
                    cipherKey = NoiseState.PerformProcessMessage1EphemeralAndES( ephemeralKey );
                    
                    var encryptedPQFrame = new byte[pqKeyLen + 16];
                    Array.Copy( ReceiveBuffer, 32, encryptedPQFrame, 0, encryptedPQFrame.Length );
                    RemoteKemPublicKey = NoiseState.DecryptHandshakeBlock( cipherKey, encryptedPQFrame );
                }

                var encryptedPayloadWithMac = new byte[32];
                Array.Copy(ReceiveBuffer, payloadOffset, encryptedPayloadWithMac, 0, 32);

                if ( IsPQSession )
                {
                    HandshakeDecryptedOptions = NoiseState.DecryptHandshakeBlock( cipherKey, encryptedPayloadWithMac );
                }
                else
                {
                    HandshakeDecryptedOptions = NoiseState.ProcessMessage1(ephemeralKey, encryptedPayloadWithMac);
                }

                if (HandshakeDecryptedOptions == null)
                {
                    Logging.LogWarning($"{DebugId}: TERMINATION REASON [C#-BOB]: SessionRequest AEAD verification failed - i2pd Alice used wrong Noise key (static key mismatch or wrong router hash/IV for AES deobfuscation)");
                    Terminate();
                    return;
                }

                var readerOpts = new BufRef(HandshakeDecryptedOptions);
                readerOpts.Read8(); // networkId
                readerOpts.Read8(); // version
                HandshakePaddingLen = readerOpts.ReadFlip16();
                HandshakeDecrypted = true;
            }

            // Now we know HandshakePaddingLen
            var totalMsgSize = payloadOffset + 32 + HandshakePaddingLen;
            if (ReceiveBufferPos < totalMsgSize) return;

            // Parse options from already decrypted payload
            var reader = new BufRef(HandshakeDecryptedOptions);
            RemoteNetworkId = reader.Read8();
            RemoteVersion = reader.Read8();
            var paddingLen = reader.ReadFlip16();
            var m3p2len = reader.ReadFlip16();
            RemoteM3P2Len = m3p2len;

            // Spec line 876: part 2 max frame length is 65487
            if (m3p2len > 65487)
            {
                Logging.LogWarning($"{DebugId}: TERMINATION REASON [C#-BOB]: SessionRequest m3p2len={m3p2len} exceeds max 65487");
                Terminate();
                return;
            }
            reader.ReadFlip16(); // Reserved
            var timestamp = reader.ReadFlip32();

            // Log options for debugging
            Logging.LogDebug($"{DebugId}: SessionRequest options: networkId={RemoteNetworkId}, version={RemoteVersion}, paddingLen={paddingLen}, m3p2len={m3p2len}, timestamp={timestamp}");

            // Validate version (i2pd responder ignores networkId)
            if (RemoteVersion < 2)
            {
                Logging.LogWarning($"{DebugId}: TERMINATION REASON [C#-BOB]: SessionRequest invalid version={RemoteVersion} (expected >=2)");
                Terminate();
                return;
            }

            // Validate padding length
            if (paddingLen > 880) // 880 is the new max for 0.9.69
            {
                Logging.LogWarning($"{DebugId}: TERMINATION REASON [C#-BOB]: SessionRequest excessive padding={paddingLen} (max 880)");
                Terminate();
                return;
            }

            // Validate timestamp
            if (!NTCP2SecurityValidator.ValidateTimestamp(timestamp))
            {
                Logging.LogWarning($"{DebugId}: SessionRequest timestamp validation failed (Clock Skew)");
                // NTCP2 Spec line 1420: Bob should reply with SessionCreated even if skew is exceeded.
                // This allows Alice to calculate the skew.
                ClockSkewDetected = true;
            }

            // MixHash padding if present (spec lines 586-596)
            var paddingOffset = payloadOffset + 32;
            if (ReceiveBufferPos < paddingOffset + paddingLen)
            {
                Logging.LogDebug($"{DebugId}: Not enough data for padding ({ReceiveBufferPos}/{paddingOffset + paddingLen})");
                return; // Wait for more data
            }

            var padding = new byte[paddingLen];
            if (paddingLen > 0)
            {
                Array.Copy(ReceiveBuffer, paddingOffset, padding, 0, paddingLen);
            }
            NoiseState.MixHashPadding(padding);

            // Validate no extra data after message 1
            var totalProcessed = payloadOffset + 32 + paddingLen; // X + PQ + payload + padding
            var remaining = ReceiveBufferPos - totalProcessed;
            if (remaining > 0)
            {
                Logging.LogWarning($"{DebugId}: TERMINATION REASON [C#-BOB]: Extra data after SessionRequest: {remaining} bytes (totalProcessed={totalProcessed}, bufPos={ReceiveBufferPos}, payloadOffset={payloadOffset}, paddingLen={paddingLen})");
                Terminate();
                return;
            }

            // Clear processed data from buffer
            ReceiveBufferPos = 0;

            State = NTCP2SessionState.SessionRequestReceived;

            HandshakeDecrypted = false;
            HandshakeDecryptedOptions = null;
            HandshakePaddingLen = 0;

            Logging.LogDebug($"{DebugId}: SessionRequest received and validated");

            // Send SessionCreated
            SendSessionCreated();
        }

        private void ProcessSessionCreated()
        {
            // SessionCreated structure (NTCP2 spec lines 797-835):
            // - 32 bytes: Obfuscated ephemeral key Y
            // - (PQ ONLY) ML-KEM ciphertext frame (784/1104/1584 bytes)
            // - 32 bytes: AEAD encrypted payload (16 bytes options + 16 bytes MAC)
            // - 0-n bytes: Padding

            if (ReceiveBufferPos < 64) return;

            int pqCTLen = IsPQSession ? PQVersion switch
            {
                3 => 768,
                4 => 1088,
                5 => 1568,
                _ => 0
            } : 0;

            int payloadOffset = 32 + (IsPQSession ? (pqCTLen + 16) : 0);
            int minSize = payloadOffset + 32;

            if (ReceiveBufferPos < minSize) return;

            if (!HandshakeDecrypted)
            {
                // Extract obfuscated ephemeral key Y
                var obfuscatedKey = new byte[32];
                Array.Copy(ReceiveBuffer, 0, obfuscatedKey, 0, 32);

                // Replay protection (spec line 818)
                if (!NTCP2SecurityValidator.CheckAndAddEncryptedToReplayCache(obfuscatedKey))
                {
                    Logging.LogWarning($"{DebugId}: SessionCreated replay detected - terminating");
                    Terminate();
                    return;
                }

                // Get Bob's router hash and IV for deobfuscation
                var bobRouterHash = RemoteRouterInfo.Identity.IdentHash.Hash.ToByteArray();

                // Deobfuscate ephemeral key Y with continued AES state (IV = last 16 bytes of X_obf)
                var ephemeralKey = AESObfuscation.Decrypt(obfuscatedKey, bobRouterHash, AESStateAfterMsg1);

                // Check Bob's response: did he accept hybrid? (ntcp2-hybrid.md line 367)
                bool bobSupportsPQ = (ephemeralKey[31] & 0x80) != 0;
                if (IsPQSession && !bobSupportsPQ)
                {
                    Logging.LogInformation($"{DebugId}: Bob rejected/downgraded PQ hybrid session. Falling back to standard NTCP2.");
                    IsPQSession = false;
                    
                    // Re-initialize Noise with standard protocol
                    InitializeNoiseAsAlice(); 
                    
                    // Recalculate everything with new Noise state
                    // This is complex because we already sent SessionRequest with hybrid hash.
                    // Actually, Proposal 165 says initiator MUST proceed with standard NTCP2.
                    // But standard NTCP2 uses a different initial hash.
                    // If Bob downgraded, he didn't know about hybrid, so he used standard hash.
                    // Alice must now match Bob's state.
                    
                    ephemeralKey[31] &= 0x7f;
                }
                else if (bobSupportsPQ)
                {
                    ephemeralKey[31] &= 0x7f;
                }

                byte[] cipherKey;
                if ( IsPQSession )
                {
                    cipherKey = NoiseState.PerformProcessMessage2EphemeralAndEE( ephemeralKey );
                    
                    var encryptedPQFrame = new byte[pqCTLen + 16];
                    Array.Copy( ReceiveBuffer, 32, encryptedPQFrame, 0, encryptedPQFrame.Length );
                    var kemCiphertext = NoiseState.DecryptHandshakeBlock( cipherKey, encryptedPQFrame );
                    
                    var sharedSecret = DecapsulateMLKEM( kemCiphertext, LocalKemSecretKey, PQVersion );
                    cipherKey = NoiseState.MixKeyPQ( sharedSecret );
                }
                else
                {
                    cipherKey = null;
                }

                var encryptedPayload = new byte[32];
                Array.Copy(ReceiveBuffer, payloadOffset, encryptedPayload, 0, 32);

                try
                {
                    if ( IsPQSession )
                    {
                        HandshakeDecryptedOptions = NoiseState.DecryptHandshakeBlock( cipherKey, encryptedPayload );
                    }
                    else
                    {
                        HandshakeDecryptedOptions = NoiseState.ProcessMessage2(ephemeralKey, encryptedPayload);
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"{DebugId}: SessionCreated AEAD verification failed: {ex.Message}");
                    Terminate();
                    return;
                }

                if (HandshakeDecryptedOptions == null || HandshakeDecryptedOptions.Length != 16)
                {
                    Logging.LogWarning($"{DebugId}: SessionCreated decryption failed - invalid options size");
                    Terminate();
                    return;
                }

                var readerOpts = new BufRef(HandshakeDecryptedOptions);
                readerOpts.ReadFlip16(); // Reserved (bytes 0-1)
                HandshakePaddingLen = readerOpts.ReadFlip16(); // padLen (bytes 2-3)
                HandshakeDecrypted = true;
            }

            // Now we know HandshakePaddingLen
            var totalMsgSize = payloadOffset + 32 + HandshakePaddingLen;
            if (ReceiveBufferPos < totalMsgSize) return;

            // Parse options (16 bytes)
            var reader = new BufRef(HandshakeDecryptedOptions);
            reader.ReadFlip16(); // Reserved (bytes 0-1)
            var paddingLen = reader.ReadFlip16(); // padLen (bytes 2-3)
            
            // Spec line 640: max padding is 848 bytes for SessionCreated
            if (paddingLen > 848)
            {
                Logging.LogWarning($"{DebugId}: SessionCreated padding length too large: {paddingLen}");
                Terminate();
                return;
            }

            reader.ReadFlip32(); // Reserved (bytes 4-7)
            var timestamp = reader.ReadFlip32(); // tsB (bytes 8-11)
            reader.ReadFlip32(); // Reserved (bytes 12-15)

            // Spec line 635: Alice must reject bad timestamp.
            if (!NTCP2SecurityValidator.ValidateTimestamp(timestamp))
            {
                Logging.LogWarning($"{DebugId}: SessionCreated timestamp validation failed (Clock Skew)");
                Terminate();
                return;
            }

            // Alice MUST NOT update CachedM3P2Len based on Message 2.
            // Message 2 contains Reserved fields, not an echo of m3p2len.
            // Per 0.9.69 spec, Bob should not echo it here.
            // CachedM3P2Len remains what Alice sent in SessionRequest.

            // Padding handling
            var paddingOffset = payloadOffset + 32;
            if (ReceiveBufferPos < paddingOffset + paddingLen)
            {
                Logging.LogDebug($"{DebugId}: Waiting for padding ({ReceiveBufferPos}/{paddingOffset + paddingLen})");
                return; // Wait for more data
            }
            
            var padding = new byte[paddingLen];
            if (paddingLen > 0)
            {
                Array.Copy(ReceiveBuffer, paddingOffset, padding, 0, paddingLen);
            }
            NoiseState.MixHashPadding(padding);

            // Clear processed data from buffer
            var totalProcessed = paddingOffset + paddingLen;
            if (ReceiveBufferPos > totalProcessed)
            {
                var remaining = ReceiveBufferPos - totalProcessed;
                Array.Copy(ReceiveBuffer, totalProcessed, ReceiveBuffer, 0, remaining);
                ReceiveBufferPos = remaining;
            }
            else
            {
                ReceiveBufferPos = 0;
            }

            State = NTCP2SessionState.SessionCreatedReceived;

            HandshakeDecrypted = false;
            HandshakeDecryptedOptions = null;
            HandshakePaddingLen = 0;

            Logging.LogDebug($"{DebugId}: SessionCreated received and validated");

            // Send SessionConfirmed
            SendSessionConfirmed();
        }

        private void ProcessSessionConfirmed()
        {
            // SessionConfirmed structure:
            // - Part 1: 48 bytes (32 bytes encrypted static key + 16 bytes MAC)
            // - Part 2: RemoteM3P2Len (RI block + optional blocks + MAC)
            
            // Per i2pd, RemoteM3P2Len from options block ALREADY includes the 16-byte MAC.
            if (ReceiveBufferPos < 48 + RemoteM3P2Len)
            {
                Logging.LogDebug($"{DebugId}: Waiting for more SessionConfirmed data ({ReceiveBufferPos}/{48 + RemoteM3P2Len} bytes)");
                return;
            }

            // Extract encrypted static key (Part 1: 48 bytes)
            var encryptedStaticKey = new byte[48];
            Array.Copy(ReceiveBuffer, 0, encryptedStaticKey, 0, 48);

            // Extract encrypted payload (Part 2: RemoteM3P2Len)
            var encryptedPayload = new byte[RemoteM3P2Len];
            Array.Copy(ReceiveBuffer, 48, encryptedPayload, 0, RemoteM3P2Len);

            // Process Noise message 3
            var staticKey = NoiseState.ProcessMessage3Part1(encryptedStaticKey);
            var payload = NoiseState.ProcessMessage3Part2(encryptedPayload);

            // Get pre-Split CK/hash for SipHash key derivation (Bob side)
            PreSplitChainingKey = NoiseState.GetPreSplitChainingKey();
            PreSplitHash = NoiseState.GetPreSplitHash();

            // Parse payload to get RouterInfo and other blocks
            var reader = new BufRefLen(payload);
            try
            {
                while (reader.Length >= 3)
                {
                    var blockType = reader.Read8();
                    var blockLen = reader.ReadFlip16();
                    
                    if (reader.Length < blockLen)
                    {
                        Logging.LogWarning($"{DebugId}: SessionConfirmed block length {blockLen} exceeds remaining payload {reader.Length}");
                        break;
                    }

                    var blockData = reader.Read(blockLen);

                    switch ((NTCP2BlockType)blockType)
                    {
                        case NTCP2BlockType.RouterInfo:
                            var floodFlag = blockData[0];
                            var riData = new byte[blockLen - 1];
                            Array.Copy(blockData, 1, riData, 0, blockLen - 1);
                            RemoteRouterInfo = new I2PRouterInfo(new BufRefLen(riData), false);

                            // Verify Alice's static key matches (spec line 853)
                            var riStaticKey = RemoteRouterInfo.Addresses
                                .FirstOrDefault(a => a.Options.Contains("s"))
                                ?.Options["s"]?.ToString();
                            
                            if (riStaticKey != null)
                            {
                                var riStaticKeyBytes = FreenetBase64.Decode(riStaticKey);
                                bool match = true;
                                if (riStaticKeyBytes.Length == staticKey.Length)
                                {
                                    for(int i=0; i<staticKey.Length; i++) if(riStaticKeyBytes[i] != staticKey[i]) { match = false; break; }
                                }
                                else match = false;

                                if (!match)
                                {
                                    Logging.LogWarning($"{DebugId}: Static key mismatch between Message 3 and RouterInfo");
                                    Terminate("Static key mismatch");
                                    return;
                                }
                            }

                            NetDb.Inst.AddRouterInfo(RemoteRouterInfo);
                            Logging.LogDebug($"{DebugId}: Received RouterInfo block in SessionConfirmed (flood={floodFlag})");
                            break;

                        case NTCP2BlockType.Options:
                            Logging.LogDebug($"{DebugId}: Received Options block in SessionConfirmed");
                            // We don't act on options for now, but we parse them
                            var opts = new NTCP2OptionsBlock();
                            opts.Parse(new BufRefLen(blockData));
                            break;

                        case NTCP2BlockType.Padding:
                            Logging.LogDebug($"{DebugId}: Received Padding block in SessionConfirmed ({blockLen} bytes)");
                            break;

                        default:
                            Logging.LogInformation($"{DebugId}: Received unknown block type {blockType} in SessionConfirmed");
                            break;
                    }
                }

                if (RemoteRouterInfo == null)
                {
                    Logging.LogWarning($"{DebugId}: SessionConfirmed part 2 did not contain a RouterInfo block");
                    Terminate();
                    return;
                }
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{DebugId}: Failed to parse blocks in SessionConfirmed: {ex.Message}");
                Terminate();
                return;
            }

            // Clear processed data from buffer
            var totalProcessed = 48 + RemoteM3P2Len;
            if (ReceiveBufferPos > totalProcessed)
            {
                var remaining = ReceiveBufferPos - totalProcessed;
                Array.Copy(ReceiveBuffer, totalProcessed, ReceiveBuffer, 0, remaining);
                ReceiveBufferPos = remaining;
            }
            else
            {
                ReceiveBufferPos = 0;
            }

            if (ClockSkewDetected)
            {
                Logging.LogWarning($"{DebugId}: Session established but clock skew still exceeds limit. Terminating.");
                SendTermination(NTCP2TerminationReason.ClockSkew);
                Terminate("Clock skew exceeds limit");
                return;
            }

            State = NTCP2SessionState.Established;

            // Initialize SipHash keys for data phase
            InitializeSipHashKeys();
            UpdateNextRouterInfoResendTime();

            Logging.LogInformation($"{DebugId}: Session established with {RemoteRouterInfo?.Identity?.IdentHash}");
            TransportConnectionLogger.Inst.Log("Session established", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", IsOutgoing ? "Outbound" : "Inbound");

            // Fire ConnectionCreated event for incoming connection
            if (!IsOutgoing && RemoteRouterInfo?.Identity?.IdentHash != null)
            {
                Host.FireConnectionCreated(this, RemoteRouterInfo.Identity.IdentHash);
            }

            // Notify connection established
            ConnectionEstablished?.Invoke(this, RemoteRouterInfo?.Identity?.IdentHash);

            // Replicate i2pd behaviour: Bob sends his RouterInfo immediately after establishment
            // See i2pd NTCP2.cpp SendLocalRouterInfo and Transports.cpp PeerConnected.
            if (!IsOutgoing)
            {
                SendRouterInfo();
            }
        }

        // Cached deobfuscated frame length - prevents SipHash counter desync
        // when we don't have enough data for a full frame
        private ushort? _pendingFrameLength = null;

        private void ProcessDataFrames()
        {
            // Data phase - extract and process frames
            while (ReceiveBufferPos >= 2)
            {
                ushort frameLength;

                if (_pendingFrameLength.HasValue)
                {
                    // We already deobfuscated this length but didn't have enough data
                    frameLength = _pendingFrameLength.Value;
                }
                else
                {
                    // Read and deobfuscate new length
                    var obfuscatedLength = BitConverter.ToUInt16(ReceiveBuffer, 0);
                    if (BitConverter.IsLittleEndian)
                        obfuscatedLength = (ushort)IPAddress.NetworkToHostOrder((short)obfuscatedLength);

                    frameLength = ReceiveSipHash.DeobfuscateLength(obfuscatedLength);
                    _pendingFrameLength = frameLength;
                }

                // Check if we have full frame
                if (ReceiveBufferPos < 2 + frameLength)
                    break;

                // Extract frame data
                var frameData = new byte[frameLength];
                Array.Copy(ReceiveBuffer, 2, frameData, 0, frameLength);

                // Parse and process frame with AEAD error handling (spec lines 234-243)
                NTCP2DataFrame dataFrame;
                try
                {
                    var reader = new BufRef(frameData);
                    dataFrame = NTCP2DataFrame.Parse(
                        reader,
                        NoiseState,
                        frameLength
                    );
                }
                catch (Exception ex)
                {
                    // AEAD failure in data phase (spec lines 234-243)
                    Logging.LogWarning($"{DebugId}: Data phase AEAD failure: {ex.Message}");

                    // Probing resistance: random delay + read
                    if (TcpClient != null)
                    {
                        var stream = TcpClient.GetStream();
                        var remoteAddress = RemoteAddress?.ToString() ?? "unknown";
                        NTCP2ProbingResistance.HandleAEADFailure(stream, remoteAddress, false);
                    }

                    // Send termination with DataPhaseAeadFailure reason
                    SendTermination(NTCP2TerminationReason.DataPhaseAeadFailure);

                    // Close connection
                    Terminate($"Data phase AEAD failure: {ex.Message}");
                    return;
                }

                // Process blocks
                foreach (var block in dataFrame.Blocks)
                {
                    switch (block.BlockType)
                    {
                        case NTCP2BlockType.I2NP:
                            // Parse and deliver I2NP message
                            var header = block.ParseAsI2NPHeader();
                            if (header != null)
                            {
                                Logging.LogInformation($"{DebugId}: Received I2NP {header.MessageType} ({block.Data.Length} bytes)");
                                DataBlockReceived?.Invoke(this, header);
                            }
                            break;

                        case NTCP2BlockType.RouterInfo:
                            try
                            {
                                var riBlock = new NTCP2RouterInfoBlock();
                                riBlock.Parse(new BufRefLen(block.Data));
                                if (riBlock.RouterInfo != null)
                                {
                                    Logging.LogDebug($"{DebugId}: Received RouterInfo block for {riBlock.RouterInfo.Identity.IdentHash}");
                                    NetDb.Inst.AddRouterInfo(riBlock.RouterInfo);

                                    // If this is our peer's RI, update our local record
                                    if (RemoteRouterInfo != null && 
                                        RemoteRouterInfo.Identity.IdentHash == riBlock.RouterInfo.Identity.IdentHash)
                                    {
                                        RemoteRouterInfo = riBlock.RouterInfo;
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Logging.LogWarning($"{DebugId}: Failed to parse RouterInfo block: {ex.Message}");
                            }
                            break;

                        case NTCP2BlockType.DateTime:
                            try
                            {
                                var dtBlock = new NTCP2DateTimeBlock();
                                dtBlock.Parse(new BufRefLen(block.Data));
                                var now = (uint)((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 500) / 1000);
                                var skew = (long)now - dtBlock.Timestamp;
                                
                                if (Math.Abs(skew) > 60)
                                {
                                    Logging.LogWarning($"{DebugId}: Clock skew detected ({skew}s). Terminating session.");
                                    SendTermination(NTCP2TerminationReason.ClockSkew);
                                    Terminate();
                                    return;
                                }
                                Logging.LogDebug($"{DebugId}: DateTime block received. Skew: {skew}s");
                            }
                            catch (Exception ex)
                            {
                                Logging.LogWarning($"{DebugId}: Failed to parse DateTime block: {ex.Message}");
                            }
                            break;

                        case NTCP2BlockType.Termination:
                            try
                            {
                                var termBlock = new NTCP2TerminationBlock();
                                termBlock.Parse(new BufRefLen(block.Data));
                                Logging.LogInformation($"{DebugId}: Received termination block (reason={termBlock.Reason}, ValidPackets={termBlock.ValidPacketsReceived})");
                                Terminate();
                                return;
                            }
                            catch (Exception ex)
                            {
                                Logging.LogInformation($"{DebugId}: Received termination block (parse failed: {ex.Message})");
                                Terminate();
                                return;
                            }

                        case NTCP2BlockType.Padding:
                            Logging.LogDebug($"{DebugId}: Received padding block ({block.Data.Length} bytes)");
                            break;

                        default:
                            Logging.LogDebug($"{DebugId}: Ignoring unknown block type {block.BlockType}");
                            break;
                    }
                }

                // Frame successfully processed - clear pending length
                _pendingFrameLength = null;

                // Remove processed frame from buffer
                var remainingBytes = ReceiveBufferPos - (2 + frameLength);
                if (remainingBytes > 0)
                {
                    Array.Copy(ReceiveBuffer, 2 + frameLength, ReceiveBuffer, 0, remainingBytes);
                }
                ReceiveBufferPos = remainingBytes;
            }
        }

        private void InitializeNoiseAsBob(string protocolName)
        {
            // Initialize Noise XK as Bob (responder)
            NoiseState = new NoiseXK(protocolName);

            // Get our static keys from Host
            var bobPriv = Host.GetStaticPrivateKey();
            var bobPub = Host.GetStaticPublicKey();

            // DIAG: verify private key matches public key
            var derivedPub = Crypto.X25519.GetPublicKey(bobPriv);
            var match = derivedPub.SequenceEqual(bobPub);
            Logging.LogInformation($"{DebugId}: DIAG-KeyPairCheck: bobPub[0:4]={BitConverter.ToString(bobPub, 0, 4).Replace("-","")} derivedPub[0:4]={BitConverter.ToString(derivedPub, 0, 4).Replace("-","")} match={match}");

            NoiseState.InitializeAsBob(bobPriv, bobPub);
        }

        private void SendSessionCreated()
        {
            // Choose a small random padding length (0-64)
            var rng = new Random();
            var paddingLen = rng.Next(0, 65);

            var payload = BuildSessionCreatedPayload(paddingLen);

            // Get Bob's router hash
            var ourRouterHash = Host.GetRouterHash();

            // Generate ephemeral keys for Bob with MSB check loop (probing resistance)
            byte[] ephKey;
            byte[] obfuscatedKey;
            int attempts = 0;
            do {
                ephKey = NoiseState.GenerateBobEphemeralKeys();

                // Signal PQ via MSB of Y (spec line 363 in ntcp2-hybrid.md)
                if ( IsPQSession ) ephKey[31] |= 0x80;
                else ephKey[31] &= 0x7f;

                obfuscatedKey = AESObfuscation.Encrypt(ephKey, ourRouterHash, AESStateAfterMsg1);
                attempts++;
            } while (!NTCP2ProbingResistance.CheckMSB(obfuscatedKey));

            if (attempts > 1)
            {
                Logging.LogDebug($"{DebugId}: Generated valid obfuscated key after {attempts} attempts");
            }

            byte[] encryptedPQFrame = null;
            byte[] encryptedPayload;

            if ( IsPQSession )
            {
                // Hybrid Handshake Message 2: <- e, ee, ekem1, p
                var cipherKey = NoiseState.PerformMessage2EphemeralAndEE();
                
                var (ciphertext, sharedSecret) = EncapsulateMLKEM( RemoteKemPublicKey, PQVersion );
                encryptedPQFrame = NoiseState.EncryptHandshakeBlock( cipherKey, ciphertext );
                
                // MixKey(kem_shared_key) - This also resets nonce for options
                var newCipherKey = NoiseState.MixKeyPQ( sharedSecret );
                
                // Payload (options) uses n=0 (reset by MixKeyPQ)
                encryptedPayload = NoiseState.EncryptHandshakeBlock( newCipherKey, payload );
            }
            else
            {
                // Standard Handshake Message 2: <- e, ee, p
                (_, encryptedPayload) = NoiseState.CreateMessage2WithCurrentKeys(payload);
            }

            // Add optional padding - must match paddingLen in options block
            var padding = paddingLen > 0 ? new byte[paddingLen] : Array.Empty<byte>();
            if (paddingLen > 0) rng.NextBytes(padding);

            // Build complete message 2: obfuscated Y + encrypted payload + padding
            // Per NTCP2 spec line 611: Bob MUST buffer and then flush the entire contents
            var totalLen = obfuscatedKey.Length + (encryptedPQFrame?.Length ?? 0) + encryptedPayload.Length + paddingLen;
            var totalMsg2 = new byte[totalLen];
            var writer = new BufRefLen(totalMsg2);

            writer.Write(obfuscatedKey);
            if (IsPQSession && encryptedPQFrame != null)
            {
                writer.Write(encryptedPQFrame);
            }
            writer.Write(encryptedPayload);
            if (paddingLen > 0)
            {
                writer.Write(padding);
            }

            // Per NTCP2 spec lines 829-835: Bob must MixHash padding after sending Message 2
            NoiseState.MixHashPadding(padding);
            Logging.LogDebug($"{DebugId}: MixHashed Message 2 padding ({paddingLen} bytes)");

            // Send to TCP stream
            var stream = TcpClient.GetStream();
            stream.Write(totalMsg2, 0, totalMsg2.Length);
            stream.Flush();

            BytesSent += totalMsg2.Length;

            State = NTCP2SessionState.SessionCreatedSent;

            Logging.LogDebug($"{DebugId}: SessionCreated sent ({totalMsg2.Length} bytes)");
        }

        private void SendSessionConfirmed()
        {
            // Build complete message 3
            var part2Payload = BuildMessage3Part2Payload();
            var encryptedPart1 = NoiseState.CreateMessage3Part1();
            var encryptedPart2 = NoiseState.CreateMessage3Part2(part2Payload);

            // Per NTCP2 spec line 863: Alice MUST buffer and then flush both frames together
            var totalMsg3 = new byte[encryptedPart1.Length + encryptedPart2.Length];
            Buffer.BlockCopy(encryptedPart1, 0, totalMsg3, 0, encryptedPart1.Length);
            Buffer.BlockCopy(encryptedPart2, 0, totalMsg3, encryptedPart1.Length, encryptedPart2.Length);

            // Get the CK and hash saved inside CreateMessage3Part2 right before Split()
            // cleared the CK. These are needed for SipHash key derivation.
            PreSplitChainingKey = NoiseState.GetPreSplitChainingKey();
            PreSplitHash = NoiseState.GetPreSplitHash();

            // Send to TCP stream
            var stream = TcpClient.GetStream();
            stream.Write(totalMsg3, 0, totalMsg3.Length);
            stream.Flush();

            BytesSent += totalMsg3.Length;

            Logging.LogDebug($"{DebugId}: SessionConfirmed sent: part1={encryptedPart1.Length}B, part2={encryptedPart2.Length}B, totalMsg3={totalMsg3.Length}B, promisedM3P2Len={CachedM3P2Len}");

            State = NTCP2SessionState.Established;

            // Initialize SipHash keys for data phase using the pre-Split CK
            InitializeSipHashKeys();
            UpdateNextRouterInfoResendTime();

            Logging.LogDebug($"{DebugId}: SessionConfirmed sent");
            Logging.LogInformation($"{DebugId}: Session established");

            // Send RouterInfo as first data frame for peer database update
            SendRouterInfo();

            // Notify connection established
            ConnectionEstablished?.Invoke(this, RemoteRouterInfo?.Identity?.IdentHash);
        }

        private byte[] BuildMessage3Part2Payload()
        {
            // Message 3 part 2 MUST contain:
            // - RouterInfo block (Type 2)
            // - Options block (Type 1)
            // And SHOULD contain:
            // - Padding block (Type 254)

            // Use cached RouterInfo bytes if available
            var routerInfoBytes = CachedMyRouterInfoBytes;
            if (routerInfoBytes == null)
            {
                var myRouterInfo = Host.GetMyRouterInfo();
                var riStream = new BufRefStream();
                myRouterInfo.Write(riStream);
                routerInfoBytes = riStream.ToArray();
            }

            // Options block (12 bytes fixed part)
            var optionsBlock = new NTCP2OptionsBlock();
            var optionsBytes = optionsBlock.Serialize();

            // Calculate how much space we have in Message 3 Part 2.
            // CachedM3P2Len includes the 16-byte MAC.
            int availableSize = CachedM3P2Len - 16;
            int requiredSize = (1 + 2 + 1 + routerInfoBytes.Length) + (1 + 2 + optionsBytes.Length);

            int paddingSize = 0;
            if (availableSize > requiredSize)
            {
                // We have room for padding. Must be at least 3 bytes for the block header.
                if (availableSize - requiredSize >= 3)
                {
                    paddingSize = availableSize - requiredSize - 3;
                }
                else
                {
                    // Too small for a padding block, but we MUST match CachedM3P2Len.
                    // This should not happen if CachedM3P2Len was calculated correctly.
                    Logging.LogWarning($"{DebugId}: M3P2 available size ({availableSize}) is slightly larger than required ({requiredSize}) but too small for padding block header.");
                }
            }

            var payload = new byte[availableSize];
            var writer = new BufRefLen(payload);

            // RouterInfo block
            writer.Write8((byte)NTCP2BlockType.RouterInfo);
            writer.WriteFlip16((ushort)(1 + routerInfoBytes.Length));  // Length: flood flag + RI
            
            byte flags = 0;
            if (RouterContext.Inst.FloodfillEnabled) flags |= 0x01; // bit 0: flood
            writer.Write8(flags);
            writer.Write(routerInfoBytes);

            // Options block
            writer.Write8((byte)NTCP2BlockType.Options);
            writer.WriteFlip16((ushort)optionsBytes.Length);
            writer.Write(optionsBytes);

            // Padding block if needed
            if (availableSize > requiredSize && availableSize - requiredSize >= 3)
            {
                writer.Write8((byte)NTCP2BlockType.Padding);
                writer.WriteFlip16((ushort)paddingSize);
                if (paddingSize > 0)
                {
                    var padding = new byte[paddingSize];
                    new Random().NextBytes(padding);
                    writer.Write(padding);
                }
            }

            Logging.LogDebug($"{DebugId}: Built message 3 part 2 payload: " +
                $"RI block ({1 + routerInfoBytes.Length} bytes, flood={flags}), " +
                $"Options block ({optionsBytes.Length} bytes), " +
                $"Padding block ({paddingSize} bytes), " +
                $"Total payload: {payload.Length} bytes (will be {payload.Length + 16} with MAC)");

            return payload;
        }

        private byte[] BuildSessionCreatedPayload(int paddingLen)
        {
            // NTCP2 spec lines 617-621 (accurate for 0.9.69):
            // Row 1: 2 bytes Rsvd (0), 2 bytes padLen, 4 bytes Reserved (0)
            // Row 2: 4 bytes tsB, 4 bytes Reserved (0)
            // Total: 16 bytes. Note: NO echoed networkId, version or m3p2len here.
            var payload = new byte[16];
            var writer = new BufRefLen(payload);

            writer.WriteFlip16(0);  // Rsvd (0)
            writer.WriteFlip16((ushort)paddingLen);  // padLen
            writer.WriteFlip32(0);  // Reserved (0)
            writer.WriteFlip32((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());  // tsB
            writer.WriteFlip32(0);  // Reserved (0)

            return payload;
        }

        private void InitializeSipHashKeys()
        {
            // Derive SipHash keys according to NTCP2 spec (lines 1094-1160)
            // Use pre-Split CK/hash if available (Alice side saves them before Split clears CK).
            // For Bob side, the CK is still intact when this is called.
            var chainingKey = PreSplitChainingKey ?? NoiseState.GetChainingKey();
            var handshakeHash = PreSplitHash ?? NoiseState.GetHandshakeHash();

            var sipHashKeys = NTCP2KDF.DeriveSipHashKeys(chainingKey, handshakeHash);

            // Alice is the initiator, Bob is the responder
            if (IsOutgoing)
            {
                // We are Alice - use Alice to Bob keys for sending
                SendSipHash = new NTCP2SipHash(sipHashKeys.AliceToBobK1, sipHashKeys.AliceToBobK2, sipHashKeys.AliceToBobIV);
                // Use Bob to Alice keys for receiving
                ReceiveSipHash = new NTCP2SipHash(sipHashKeys.BobToAliceK1, sipHashKeys.BobToAliceK2, sipHashKeys.BobToAliceIV);
            }
            else
            {
                // We are Bob - use Bob to Alice keys for sending
                SendSipHash = new NTCP2SipHash(sipHashKeys.BobToAliceK1, sipHashKeys.BobToAliceK2, sipHashKeys.BobToAliceIV);
                // Use Alice to Bob keys for receiving
                ReceiveSipHash = new NTCP2SipHash(sipHashKeys.AliceToBobK1, sipHashKeys.AliceToBobK2, sipHashKeys.AliceToBobIV);
            }
        }

        private void SendTermination(NTCP2TerminationReason reason, byte[] additionalData = null)
        {
            try
            {
                if (NoiseState == null || State < NTCP2SessionState.Established || TcpClient == null)
                {
                    // Can't send termination before data phase
                    return;
                }

                // Build termination block (spec lines 1458-1490)
                var block = new NTCP2TerminationBlock
                {
                    Reason = reason,
                    AdditionalData = additionalData ?? Array.Empty<byte>()
                };

                // Serialize block
                var blockData = block.Serialize();

                // Create DataFrame with termination block
                var frame = new NTCP2DataFrame();
                frame.Blocks.Add(new NTCP2BlockWrapper
                {
                    BlockType = NTCP2BlockType.Termination,
                    Data = blockData
                });

                // Serialize frame
                var frameBytes = frame.ToByteArray();

                // Encrypt frame
                var encryptedFrame = NoiseState.EncryptData(frameBytes);

                // Obfuscate length
                var frameLength = (ushort)encryptedFrame.Length;
                var obfuscatedLength = SendSipHash.ObfuscateLength(frameLength);

                // Build complete frame: obfuscated length + encrypted payload
                var completeFrame = new byte[2 + encryptedFrame.Length];
                completeFrame[0] = (byte)(obfuscatedLength >> 8);
                completeFrame[1] = (byte)(obfuscatedLength & 0xFF);
                Array.Copy(encryptedFrame, 0, completeFrame, 2, encryptedFrame.Length);

                // Send
                var stream = TcpClient.GetStream();
                if (stream != null && stream.CanWrite)
                {
                    stream.Write(completeFrame, 0, completeFrame.Length);
                    stream.Flush();
                }

                Logging.LogDebug($"{DebugId}: Sent termination with reason {reason}");
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"{DebugId}: Failed to send termination: {ex.Message}");
            }
        }

        private void ClearSensitiveData()
        {
            // Zero out all sensitive key material
            NoiseState?.Clear();
            ClearArray(SendKey);
            ClearArray(ReceiveKey);
        }

        private void ClearArray(byte[] array)
        {
            if (array != null)
            {
                Array.Clear(array, 0, array.Length);
            }
        }
    }
}
