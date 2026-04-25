using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.Streaming;
using I2PCore.Utils;

namespace I2PCore.Client
{
    /// <summary>
    /// SOCKS4a/SOCKS5 proxy for routing TCP connections to .i2p destinations.
    /// Listens on a local TCP port and tunnels connections through the I2P
    /// streaming layer.
    /// </summary>
    public class SOCKSProxy : IDisposable
    {
        public const int DefaultPort = 4447;
        public const int ForwardBufferSize = 8192;

        // SOCKS protocol constants
        private const byte SOCKS4_VERSION = 0x04;
        private const byte SOCKS5_VERSION = 0x05;
        private const byte SOCKS4_CMD_CONNECT = 0x01;
        private const byte SOCKS5_CMD_CONNECT = 0x01;
        private const byte SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

        // SOCKS5 auth methods
        private const byte SOCKS5_AUTH_NONE = 0x00;
        private const byte SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF;

        // SOCKS5 address types
        private const byte SOCKS5_ATYP_IPV4 = 0x01;
        private const byte SOCKS5_ATYP_DOMAIN = 0x03;
        private const byte SOCKS5_ATYP_IPV6 = 0x04;

        // SOCKS4 reply codes
        private const byte SOCKS4_REPLY_GRANTED = 0x5A;
        private const byte SOCKS4_REPLY_REJECTED = 0x5B;

        // SOCKS5 reply codes
        private const byte SOCKS5_REP_SUCCESS = 0x00;
        private const byte SOCKS5_REP_GENERAL_FAILURE = 0x01;
        private const byte SOCKS5_REP_NOT_ALLOWED = 0x02;
        private const byte SOCKS5_REP_HOST_UNREACHABLE = 0x04;
        private const byte SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07;
        private const byte SOCKS5_REP_ATYP_NOT_SUPPORTED = 0x08;

        private readonly int _listenPort;
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private readonly ClientDestination _clientDestination;
        private readonly StreamingDestination _streamingDestination;
        private readonly DatagramDestination _datagramDestination;

        /// <summary>
        /// Optional resolver callback: given an .i2p hostname, return the I2PDestination.
        /// If not set, only base64 destinations in the hostname field are supported.
        /// </summary>
        public Func<string, I2PDestination> ResolveHostname { get; set; }

        public bool IsRunning { get; private set; }

        /// <summary>
        /// Create a SOCKS proxy using the given I2P client infrastructure.
        /// </summary>
        /// <param name="clientDestination">I2P client destination for connectivity.</param>
        /// <param name="streamingDestination">Streaming destination for creating streams.</param>
        /// <param name="listenPort">Local TCP port (default 4447).</param>
        public SOCKSProxy(
            ClientDestination clientDestination,
            StreamingDestination streamingDestination,
            int listenPort = DefaultPort,
            DatagramDestination datagramDestination = null)
        {
            _clientDestination = clientDestination ?? throw new ArgumentNullException(nameof(clientDestination));
            _streamingDestination = streamingDestination ?? throw new ArgumentNullException(nameof(streamingDestination));
            _datagramDestination = datagramDestination;
            _listenPort = listenPort;
        }

        /// <summary>
        /// Start accepting SOCKS proxy connections.
        /// </summary>
        public void Start()
        {
            if (IsRunning) return;

            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, _listenPort);
            _listener.Start();
            IsRunning = true;

            Logging.LogInformation($"SOCKSProxy: Listening on 127.0.0.1:{_listenPort}");

            Task.Run(() => AcceptLoop(_cts.Token));
        }

        /// <summary>
        /// Stop the proxy.
        /// </summary>
        public void Stop()
        {
            if (!IsRunning) return;

            IsRunning = false;
            _cts?.Cancel();

            try { _listener?.Stop(); }
            catch (Exception) { /* ignore */ }

            Logging.LogInformation("SOCKSProxy: Stopped");
        }

        private async Task AcceptLoop(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleClient(tcpClient, ct), ct);
                }
            }
            catch (ObjectDisposedException) { /* listener stopped */ }
            catch (Exception ex)
            {
                Logging.LogWarning($"SOCKSProxy: Accept loop error: {ex.Message}");
            }
        }

        private async Task HandleClient(TcpClient tcpClient, CancellationToken ct)
        {
            try
            {
                using (tcpClient)
                {
                    tcpClient.NoDelay = true;
                    var stream = tcpClient.GetStream();

                    // Read the first byte to determine SOCKS version
                    var versionBuf = new byte[1];
                    if (await ReadExact(stream, versionBuf, 0, 1, ct) != 1)
                        return;

                    switch (versionBuf[0])
                    {
                        case SOCKS4_VERSION:
                            await HandleSocks4(stream, ct);
                            break;

                        case SOCKS5_VERSION:
                            await HandleSocks5(stream, ct);
                            break;

                        default:
                            Logging.LogDebug($"SOCKSProxy: Unsupported SOCKS version: {versionBuf[0]}");
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"SOCKSProxy: Client handler error: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle a SOCKS4a connection request.
        /// SOCKS4a format:
        ///   VN(1) CD(1) DSTPORT(2) DSTIP(4) USERID(variable,null-terminated)
        ///   If DSTIP is 0.0.0.x (x != 0), read domain after USERID null.
        /// </summary>
        private async Task HandleSocks4(NetworkStream stream, CancellationToken ct)
        {
            // Already read version byte. Read: CMD(1) + PORT(2) + IP(4) = 7 bytes
            var header = new byte[7];
            if (await ReadExact(stream, header, 0, 7, ct) != 7)
                return;

            byte cmd = header[0];
            ushort port = (ushort)((header[1] << 8) | header[2]);
            byte ip1 = header[3], ip2 = header[4], ip3 = header[5], ip4 = header[6];

            if (cmd != SOCKS4_CMD_CONNECT)
            {
                await SendSocks4Reply(stream, SOCKS4_REPLY_REJECTED, 0, 0);
                return;
            }

            // Read USERID (null-terminated)
            await ReadNullTerminatedString(stream, ct);

            string hostname;

            // SOCKS4a: if IP is 0.0.0.x where x != 0, the domain follows
            if (ip1 == 0 && ip2 == 0 && ip3 == 0 && ip4 != 0)
            {
                hostname = await ReadNullTerminatedString(stream, ct);
            }
            else
            {
                // Standard SOCKS4 with an IP - not useful for I2P
                await SendSocks4Reply(stream, SOCKS4_REPLY_REJECTED, 0, 0);
                return;
            }

            if (string.IsNullOrEmpty(hostname) || !hostname.ToLowerInvariant().EndsWith(".i2p"))
            {
                Logging.LogDebug($"SOCKSProxy: SOCKS4a non-.i2p host rejected: {hostname}");
                await SendSocks4Reply(stream, SOCKS4_REPLY_REJECTED, 0, 0);
                return;
            }

            // Resolve and connect
            var destination = ResolveI2PHostname(hostname);
            if (destination == null)
            {
                Logging.LogDebug($"SOCKSProxy: Cannot resolve {hostname}");
                await SendSocks4Reply(stream, SOCKS4_REPLY_REJECTED, 0, 0);
                return;
            }

            I2PStream i2pStream;
            try
            {
                i2pStream = _streamingDestination.CreateStream(destination);
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"SOCKSProxy: SOCKS4a connect failed to {hostname}: {ex.Message}");
                await SendSocks4Reply(stream, SOCKS4_REPLY_REJECTED, 0, 0);
                return;
            }

            // Success
            await SendSocks4Reply(stream, SOCKS4_REPLY_GRANTED, port, 0x01000000);
            Logging.LogDebug($"SOCKSProxy: SOCKS4a connected to {hostname}");

            await ForwardBidirectional(stream, i2pStream, ct);
        }

        /// <summary>
        /// Handle a SOCKS5 connection request.
        /// </summary>
        private async Task HandleSocks5(NetworkStream stream, CancellationToken ct)
        {
            // Already read version byte. Read auth method negotiation.
            // NMETHODS(1) + METHODS(NMETHODS)
            var nmethodsBuf = new byte[1];
            if (await ReadExact(stream, nmethodsBuf, 0, 1, ct) != 1)
                return;

            int nmethods = nmethodsBuf[0];
            var methods = new byte[nmethods];
            if (await ReadExact(stream, methods, 0, nmethods, ct) != nmethods)
                return;

            // Check if no-auth is offered
            bool hasNoAuth = false;
            for (int i = 0; i < nmethods; i++)
            {
                if (methods[i] == SOCKS5_AUTH_NONE)
                {
                    hasNoAuth = true;
                    break;
                }
            }

            if (!hasNoAuth)
            {
                // No acceptable method
                await stream.WriteAsync(new byte[] { SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE }, 0, 2, ct);
                return;
            }

            // Select no-auth
            await stream.WriteAsync(new byte[] { SOCKS5_VERSION, SOCKS5_AUTH_NONE }, 0, 2, ct);

            // Read the connection request: VER(1) CMD(1) RSV(1) ATYP(1)
            var reqHeader = new byte[4];
            if (await ReadExact(stream, reqHeader, 0, 4, ct) != 4)
                return;

            if (reqHeader[0] != SOCKS5_VERSION)
                return;

            byte cmd = reqHeader[1];
            byte atyp = reqHeader[3];

            if (cmd == SOCKS5_CMD_UDP_ASSOCIATE)
            {
                await HandleSocks5UdpAssociate(stream, atyp, ct);
                return;
            }

            if (cmd != SOCKS5_CMD_CONNECT)
            {
                await SendSocks5Reply(stream, SOCKS5_REP_CMD_NOT_SUPPORTED, ct);
                return;
            }

            string hostname;
            ushort port;

            switch (atyp)
            {
                case SOCKS5_ATYP_DOMAIN:
                {
                    // Read domain length (1 byte) + domain + port (2 bytes)
                    var lenBuf = new byte[1];
                    if (await ReadExact(stream, lenBuf, 0, 1, ct) != 1) return;

                    int domainLen = lenBuf[0];
                    var domainBuf = new byte[domainLen];
                    if (await ReadExact(stream, domainBuf, 0, domainLen, ct) != domainLen) return;

                    hostname = Encoding.ASCII.GetString(domainBuf);

                    var portBuf = new byte[2];
                    if (await ReadExact(stream, portBuf, 0, 2, ct) != 2) return;
                    port = (ushort)((portBuf[0] << 8) | portBuf[1]);
                    break;
                }

                case SOCKS5_ATYP_IPV4:
                {
                    // Read 4 bytes IP + 2 bytes port - not useful for I2P
                    var skip = new byte[6];
                    await ReadExact(stream, skip, 0, 6, ct);
                    await SendSocks5Reply(stream, SOCKS5_REP_ATYP_NOT_SUPPORTED, ct);
                    return;
                }

                case SOCKS5_ATYP_IPV6:
                {
                    // Read 16 bytes IP + 2 bytes port - not useful for I2P
                    var skip = new byte[18];
                    await ReadExact(stream, skip, 0, 18, ct);
                    await SendSocks5Reply(stream, SOCKS5_REP_ATYP_NOT_SUPPORTED, ct);
                    return;
                }

                default:
                    await SendSocks5Reply(stream, SOCKS5_REP_ATYP_NOT_SUPPORTED, ct);
                    return;
            }

            if (!hostname.ToLowerInvariant().EndsWith(".i2p"))
            {
                Logging.LogDebug($"SOCKSProxy: SOCKS5 non-.i2p host rejected: {hostname}");
                await SendSocks5Reply(stream, SOCKS5_REP_NOT_ALLOWED, ct);
                return;
            }

            var destination = ResolveI2PHostname(hostname);
            if (destination == null)
            {
                Logging.LogDebug($"SOCKSProxy: Cannot resolve {hostname}");
                await SendSocks5Reply(stream, SOCKS5_REP_HOST_UNREACHABLE, ct);
                return;
            }

            I2PStream i2pStream;
            try
            {
                i2pStream = _streamingDestination.CreateStream(destination);
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"SOCKSProxy: SOCKS5 connect failed to {hostname}: {ex.Message}");
                await SendSocks5Reply(stream, SOCKS5_REP_GENERAL_FAILURE, ct);
                return;
            }

            // Success reply
            await SendSocks5Reply(stream, SOCKS5_REP_SUCCESS, ct);
            Logging.LogDebug($"SOCKSProxy: SOCKS5 connected to {hostname}:{port}");

            await ForwardBidirectional(stream, i2pStream, ct);
        }

        /// <summary>
        /// Resolve an .i2p hostname to an I2PDestination using the configured resolver.
        /// </summary>
        private I2PDestination ResolveI2PHostname(string hostname)
        {
            if (ResolveHostname != null)
            {
                try
                {
                    return ResolveHostname(hostname);
                }
                catch (Exception ex)
                {
                    Logging.LogDebug($"SOCKSProxy: Resolver failed for {hostname}: {ex.Message}");
                }
            }

            // Try interpreting the hostname prefix as a base64 destination
            // (some clients pass the full base64 as the "hostname")
            if (hostname.Length > 256 && hostname.EndsWith(".i2p"))
            {
                var b64 = hostname.Substring(0, hostname.Length - ".i2p".Length);
                try
                {
                    var destBytes = FreenetBase64.Decode(b64);
                    return new I2PDestination(new I2PBufferCursor(destBytes));
                }
                catch (Exception)
                {
                    // Not valid base64
                }
            }

            return null;
        }

        private static async Task SendSocks4Reply(NetworkStream stream, byte status, ushort port, uint ip)
        {
            var reply = new byte[8];
            reply[0] = 0x00; // VN (reply)
            reply[1] = status;
            reply[2] = (byte)(port >> 8);
            reply[3] = (byte)(port & 0xFF);
            reply[4] = (byte)(ip & 0xFF);
            reply[5] = (byte)((ip >> 8) & 0xFF);
            reply[6] = (byte)((ip >> 16) & 0xFF);
            reply[7] = (byte)((ip >> 24) & 0xFF);
            await stream.WriteAsync(reply, 0, 8);
        }

        private static async Task SendSocks5Reply(NetworkStream stream, byte replyCode, CancellationToken ct)
        {
            // VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(4) BND.PORT(2)
            var reply = new byte[10];
            reply[0] = SOCKS5_VERSION;
            reply[1] = replyCode;
            reply[2] = 0x00; // RSV
            reply[3] = SOCKS5_ATYP_IPV4;
            // BND.ADDR = 0.0.0.0, BND.PORT = 0
            await stream.WriteAsync(reply, 0, reply.Length, ct);
        }

        /// <summary>
        /// Forward data bidirectionally between a TCP NetworkStream and an I2PStream.
        /// </summary>
        private static async Task ForwardBidirectional(NetworkStream tcpStream, I2PStream i2pStream, CancellationToken ct)
        {
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            // TCP -> I2P
            var tcpToI2p = Task.Run(async () =>
            {
                try
                {
                    var buf = new byte[ForwardBufferSize];
                    while (!linkedCts.Token.IsCancellationRequested)
                    {
                        var n = await tcpStream.ReadAsync(buf, 0, buf.Length, linkedCts.Token);
                        if (n == 0) break;

                        var data = new byte[n];
                        Array.Copy(buf, data, n);
                        i2pStream.Send(data);
                    }
                }
                catch (Exception) { /* connection closed */ }
                finally
                {
                    try { linkedCts.Cancel(); } catch { }
                }
            }, linkedCts.Token);

            // I2P -> TCP worker
            var i2pDataQueue = System.Threading.Channels.Channel.CreateUnbounded<byte[]>();
            var i2pToTcpWorker = Task.Run(async () =>
            {
                try
                {
                    await foreach (var data in i2pDataQueue.Reader.ReadAllAsync(linkedCts.Token))
                    {
                        await tcpStream.WriteAsync(data, 0, data.Length, linkedCts.Token);
                    }
                }
                catch (Exception) { /* closed */ }
                finally
                {
                    try { linkedCts.Cancel(); } catch { }
                }
            });

            var i2pToTcpFinished = new TaskCompletionSource<bool>();
            
            Action<I2PStream, byte[]> dataReceivedHandler = (stream, data) =>
            {
                i2pDataQueue.Writer.TryWrite(data);
            };
            
            Action<I2PStream> streamClosedHandler = (stream) =>
            {
                i2pDataQueue.Writer.TryComplete();
                i2pToTcpFinished.TrySetResult(true);
            };

            i2pStream.DataReceived += dataReceivedHandler;
            i2pStream.StreamClosed += streamClosedHandler;

            try
            {
                // Wait for either direction to finish
                await Task.WhenAny(tcpToI2p, i2pToTcpWorker, i2pToTcpFinished.Task);
            }
            finally
            {
                try { linkedCts.Cancel(); } catch { }
                i2pDataQueue.Writer.TryComplete();

                i2pStream.DataReceived -= dataReceivedHandler;
                i2pStream.StreamClosed -= streamClosedHandler;

                // Ensure worker tasks are really finished
                try { await Task.WhenAll(tcpToI2p, i2pToTcpWorker); } catch { }
                
                i2pStream.Close();
            }
        }

        /// <summary>
        /// Read a null-terminated string from the stream.
        /// </summary>
        private static async Task<string> ReadNullTerminatedString(NetworkStream stream, CancellationToken ct)
        {
            var sb = new StringBuilder();
            var buf = new byte[1];

            while (true)
            {
                if (await ReadExact(stream, buf, 0, 1, ct) != 1)
                    return sb.ToString();

                if (buf[0] == 0x00)
                    return sb.ToString();

                sb.Append((char)buf[0]);

                if (sb.Length > 4096) // Safety limit
                    return sb.ToString();
            }
        }

        /// <summary>
        /// Read exactly count bytes from the stream.
        /// </summary>
        private static async Task<int> ReadExact(NetworkStream stream, byte[] buffer, int offset, int count, CancellationToken ct)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                var n = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, ct);
                if (n == 0) return totalRead;
                totalRead += n;
            }
            return totalRead;
        }

        /// <summary>
        /// Handle SOCKS5 UDP ASSOCIATE command.
        /// Creates a local UDP relay socket and forwards datagrams through I2P.
        /// The client sends/receives UDP datagrams encapsulated in the SOCKS5 UDP format.
        /// </summary>
        private async Task HandleSocks5UdpAssociate(NetworkStream tcpStream, byte atyp, CancellationToken ct)
        {
            // Consume the address and port from the request
            switch (atyp)
            {
                case SOCKS5_ATYP_IPV4:
                    var skip4 = new byte[6];
                    await ReadExact(tcpStream, skip4, 0, 6, ct);
                    break;
                case SOCKS5_ATYP_IPV6:
                    var skip6 = new byte[18];
                    await ReadExact(tcpStream, skip6, 0, 18, ct);
                    break;
                case SOCKS5_ATYP_DOMAIN:
                    var lenBuf = new byte[1];
                    await ReadExact(tcpStream, lenBuf, 0, 1, ct);
                    var domainSkip = new byte[lenBuf[0] + 2];
                    await ReadExact(tcpStream, domainSkip, 0, domainSkip.Length, ct);
                    break;
            }

            if (_datagramDestination == null)
            {
                Logging.LogDebug("SOCKSProxy: UDP ASSOCIATE requested but no DatagramDestination configured");
                await SendSocks5Reply(tcpStream, SOCKS5_REP_CMD_NOT_SUPPORTED, ct);
                return;
            }

            UdpClient udpRelay = null;
            try
            {
                // Create local UDP relay socket
                udpRelay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                var localEndpoint = (IPEndPoint)udpRelay.Client.LocalEndPoint;

                // Reply with the UDP relay address
                var reply = new byte[10];
                reply[0] = SOCKS5_VERSION;
                reply[1] = SOCKS5_REP_SUCCESS;
                reply[2] = 0x00;
                reply[3] = SOCKS5_ATYP_IPV4;
                // BND.ADDR = 127.0.0.1
                reply[4] = 127; reply[5] = 0; reply[6] = 0; reply[7] = 1;
                reply[8] = (byte)(localEndpoint.Port >> 8);
                reply[9] = (byte)(localEndpoint.Port & 0xFF);
                await tcpStream.WriteAsync(reply, 0, reply.Length, ct);

                Logging.LogDebug($"SOCKSProxy: UDP ASSOCIATE relay on port {localEndpoint.Port}");

                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

                // Monitor TCP for closure (terminates the UDP association)
                var tcpMonitor = Task.Run(async () =>
                {
                    try
                    {
                        var buf = new byte[1];
                        while (!linkedCts.Token.IsCancellationRequested)
                        {
                            var n = await tcpStream.ReadAsync(buf, 0, 1, linkedCts.Token);
                            if (n == 0) break;
                        }
                    }
                    catch { }
                    finally { linkedCts.Cancel(); }
                }, linkedCts.Token);

                // Forward outbound UDP: client -> I2P datagram
                IPEndPoint clientEndpoint = null;
                var udpForwarder = Task.Run(async () =>
                {
                    try
                    {
                        while (!linkedCts.Token.IsCancellationRequested)
                        {
                            var result = await udpRelay.ReceiveAsync(linkedCts.Token);
                            clientEndpoint ??= result.RemoteEndPoint;

                            // Parse SOCKS5 UDP header:
                            // RSV(2) FRAG(1) ATYP(1) DST.ADDR(variable) DST.PORT(2) DATA
                            var data = result.Buffer;
                            if (data.Length < 10) continue;

                            byte frag = data[2];
                            if (frag != 0) continue;

                            byte udpAtyp = data[3];
                            int dataOffset;
                            string destHost;
                            ushort destPort = 0;

                            if (udpAtyp == SOCKS5_ATYP_DOMAIN)
                            {
                                int dlen = data[4];
                                destHost = Encoding.ASCII.GetString(data, 5, dlen);
                                destPort = (ushort)((data[5 + dlen] << 8) | data[5 + dlen + 1]);
                                dataOffset = 5 + dlen + 2;
                            }
                            else continue;

                            if (!destHost.EndsWith(".i2p")) continue;

                            var dest = ResolveI2PHostname(destHost);
                            if (dest == null) continue;

                            var payload = new byte[data.Length - dataOffset];
                            Array.Copy(data, dataOffset, payload, 0, payload.Length);

                            _datagramDestination.SendRepliableDatagram(
                                dest.IdentHash, payload, 0, destPort);
                        }
                    }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        Logging.LogDebug($"SOCKSProxy: UDP relay error: {ex.Message}");
                    }
                }, linkedCts.Token);

                // Forward inbound: I2P datagram -> client
                var localUdpRelay = udpRelay;
                void OnDatagramReceived(object sender, DatagramDestination.DatagramReceivedEventArgs args)
                {
                    if (clientEndpoint == null || linkedCts.Token.IsCancellationRequested)
                        return;

                    try
                    {
                        var sourceHashBuf = args.Sender?.IdentHash?.Hash;
                        if (sourceHashBuf == null) return;

                        var b32 = FreenetBase64.Encode(new I2PByteBlock(sourceHashBuf.Value.ToByteArray())) + ".b32.i2p";
                        var bBytes = Encoding.ASCII.GetBytes(b32);

                        var udpReplyBuf = new byte[4 + 1 + bBytes.Length + 2 + args.Payload.Length];
                        udpReplyBuf[0] = 0; udpReplyBuf[1] = 0; // RSV
                        udpReplyBuf[2] = 0; // FRAG
                        udpReplyBuf[3] = SOCKS5_ATYP_DOMAIN;
                        udpReplyBuf[4] = (byte)bBytes.Length;
                        Array.Copy(bBytes, 0, udpReplyBuf, 5, bBytes.Length);
                        int pOff = 5 + bBytes.Length + 2;
                        Array.Copy(args.Payload, 0, udpReplyBuf, pOff, args.Payload.Length);

                        localUdpRelay.Send(udpReplyBuf, udpReplyBuf.Length, clientEndpoint);
                    }
                    catch { }
                }

                _datagramDestination.DatagramReceived += OnDatagramReceived;
                try
                {
                    await Task.WhenAny(tcpMonitor, udpForwarder);
                }
                finally
                {
                    _datagramDestination.DatagramReceived -= OnDatagramReceived;
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"SOCKSProxy: UDP ASSOCIATE error: {ex.Message}");
            }
            finally
            {
                udpRelay?.Close();
            }
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }
}
