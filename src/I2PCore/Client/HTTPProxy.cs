using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    /// HTTP proxy for browsing .i2p sites. Listens on a local TCP port and
    /// forwards HTTP requests to I2P destinations via the streaming layer.
    /// Supports the ?i2paddresshelper= mechanism and HTTPS CONNECT tunneling.
    /// </summary>
    public class HTTPProxy : IDisposable
    {
        public const int DefaultPort = 4444;
        public const int ForwardBufferSize = 8192;
        public const int HeaderMaxBytes = 65536;

        private readonly int _listenPort;
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private readonly ClientDestination _clientDestination;
        private readonly StreamingDestination _streamingDestination;

        /// <summary>
        /// Address book: hostname -> base64 destination.
        /// Populated by ?i2paddresshelper= links and manual entries.
        /// </summary>
        private readonly ConcurrentDictionary<string, string> _addressBook = new();

        public bool IsRunning { get; private set; }

        /// <summary>
        /// Optional outproxy URL for non-.i2p requests.
        /// When set, non-.i2p HTTP requests are forwarded to this outproxy
        /// (which should be an .i2p address running an exit proxy).
        /// Example: "http://false.i2p" or "http://outproxy.purokishi.i2p"
        /// </summary>
        public string OutproxyUrl { get; set; }

        /// <summary>
        /// Create an HTTP proxy that uses the given ClientDestination for I2P connectivity.
        /// </summary>
        /// <param name="clientDestination">The I2P client destination to use for outbound streams.</param>
        /// <param name="streamingDestination">The streaming destination for creating streams.</param>
        /// <param name="listenPort">Local TCP port to listen on (default 4444).</param>
        public HTTPProxy(
            ClientDestination clientDestination,
            StreamingDestination streamingDestination,
            int listenPort = DefaultPort)
        {
            _clientDestination = clientDestination ?? throw new ArgumentNullException(nameof(clientDestination));
            _streamingDestination = streamingDestination ?? throw new ArgumentNullException(nameof(streamingDestination));
            _listenPort = listenPort;
        }

        /// <summary>
        /// Register a known destination in the address book.
        /// </summary>
        /// <param name="hostname">The .i2p hostname (e.g. "example.i2p").</param>
        /// <param name="base64Destination">The full base64 I2P destination.</param>
        public void AddAddressBookEntry(string hostname, string base64Destination)
        {
            _addressBook[hostname.ToLowerInvariant()] = base64Destination;
        }

        /// <summary>
        /// Start accepting HTTP proxy connections.
        /// </summary>
        public void Start()
        {
            if (IsRunning) return;

            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, _listenPort);
            _listener.Start();
            IsRunning = true;

            Logging.LogInformation($"HTTPProxy: Listening on 127.0.0.1:{_listenPort}");

            Task.Run(() => AcceptLoop(_cts.Token));
        }

        /// <summary>
        /// Stop the proxy and close all connections.
        /// </summary>
        public void Stop()
        {
            if (!IsRunning) return;

            IsRunning = false;
            _cts?.Cancel();

            try { _listener?.Stop(); }
            catch (Exception) { /* ignore */ }

            Logging.LogInformation("HTTPProxy: Stopped");
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
                Logging.LogWarning($"HTTPProxy: Accept loop error: {ex.Message}");
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

                    // Read the HTTP request header
                    var headerBytes = await ReadHttpHeader(stream, ct);
                    if (headerBytes == null || headerBytes.Length == 0)
                        return;

                    var headerText = Encoding.ASCII.GetString(headerBytes);
                    var requestLine = headerText.Split('\n')[0].Trim('\r');
                    var parts = requestLine.Split(' ');

                    if (parts.Length < 3)
                    {
                        await SendError(stream, 400, "Bad Request");
                        return;
                    }

                    var method = parts[0].ToUpperInvariant();
                    var target = parts[1];

                    if (method == "CONNECT")
                    {
                        HttpProxyLogger.Inst.Log( method, target, "Received", "Handling CONNECT tunnel" );
                        await HandleConnect(stream, target, ct);
                        return;
                    }

                    HttpProxyLogger.Inst.Log( method, target, "Received", "Handling HTTP request" );

                    // Parse the URL to extract the .i2p host
                    if (!Uri.TryCreate(target, UriKind.Absolute, out var uri))
                    {
                        Logging.LogDebug($"HTTPProxy: Invalid URL format '{target}'");
                        await SendError(stream, 400, "Invalid URL");
                        return;
                    }

                    if (uri == null)
                    {
                        Logging.LogDebug("HTTPProxy: uri is null after TryCreate");
                        return;
                    }

                    var hostname = uri.Host?.ToLowerInvariant();
                    if (string.IsNullOrEmpty(hostname))
                    {
                        Logging.LogDebug($"HTTPProxy: No host in URL '{target}'");
                        await SendError(stream, 400, "Invalid URL (no host)");
                        return;
                    }

                    if (!hostname.EndsWith(".i2p"))
                    {
                        if (string.IsNullOrEmpty(OutproxyUrl))
                        {
                            await SendError(stream, 403,
                                "Only .i2p sites are supported. Configure an outproxy for clearnet access.");
                            return;
                        }

                        // Forward non-.i2p requests through the outproxy
                        await ForwardToOutproxy(stream, requestLine, target, headerBytes, ct);
                        return;
                    }

                    // Check for ?i2paddresshelper= in query string
                    var dest64 = ExtractAddressHelper(uri);
                    if (dest64 != null)
                    {
                        _addressBook[hostname] = dest64;
                        Logging.LogDebug($"HTTPProxy: Address helper registered for {hostname}");

                        // Redirect to the same URL without the helper parameter
                        var cleanUrl = RemoveAddressHelperParam(uri);
                        var redirect = $"HTTP/1.1 301 Moved Permanently\r\nLocation: {cleanUrl}\r\nConnection: close\r\n\r\n";
                        var redirectBytes = Encoding.ASCII.GetBytes(redirect);
                        await stream.WriteAsync(redirectBytes, 0, redirectBytes.Length, ct);
                        return;
                    }

                    // Resolve the .i2p hostname to an I2P destination
                    var destination = ResolveDestination(hostname);
                    if (destination != null)
                    {
                        HttpProxyLogger.Inst.Log( method, target, "Lookup", $"Resolved {hostname} from address book" );
                    }

                    if (destination == null && hostname != null && hostname.EndsWith(".b32.i2p"))
                    {
                        // b32 address: perform async LeaseSet lookup via floodfills
                        HttpProxyLogger.Inst.Log( method, target, "Lookup", $"Starting async b32 lookup for {hostname}" );
                        destination = await ResolveB32Async(hostname, ct);
                        if (destination != null)
                        {
                            HttpProxyLogger.Inst.Log( method, target, "Lookup", $"Resolved b32 {hostname}" );
                        }
                        else
                        {
                            HttpProxyLogger.Inst.Log( method, target, "Error", $"Failed to resolve b32 {hostname}" );
                        }
                    }
                    if (destination == null)
                    {
                        Logging.LogDebug($"HTTPProxy: Cannot resolve {hostname}");
                        await SendError(stream, 504, $"Cannot resolve {hostname}");
                        return;
                    }

                    // Rewrite the request line to use a relative path
                    var relativePath = uri.PathAndQuery ?? "/";
                    var rewrittenHeader = RewriteRequestHeader(headerText, method, relativePath, hostname);
                    if (string.IsNullOrEmpty(rewrittenHeader))
                    {
                        Logging.LogWarning("HTTPProxy: Rewritten header is empty");
                        await SendError(stream, 500, "Internal error rewriting request");
                        return;
                    }

                    // Wait for inbound and outbound tunnels to be established
                    int tunnelWaitAttempts = 0;
                    while ((_clientDestination.ClientState == ClientDestination.ClientStates.NoTunnels || _clientDestination.SignedLeases == null) && tunnelWaitAttempts < 60)
                    {
                        if (tunnelWaitAttempts == 0)
                        {
                            HttpProxyLogger.Inst.Log(method, target, "Connecting", "Waiting for client tunnels to be established...");
                        }
                        await Task.Delay(1000, ct);
                        tunnelWaitAttempts++;
                    }

                    if (_clientDestination.ClientState == ClientDestination.ClientStates.NoTunnels || _clientDestination.SignedLeases == null)
                    {
                        var reason = _clientDestination.SignedLeases == null ? "LeaseSet not ready" : "No established tunnels";
                        Logging.LogWarning($"HTTPProxy: Timeout waiting for tunnels for {hostname} ({reason})");
                        await SendError(stream, 504, $"I2P tunnels not ready ({reason}). Please try again in a few moments.");
                        return;
                    }

                    // Connect to the I2P destination via streaming
                    I2PStream i2pStream = null;
                    try
                    {
                        i2pStream = _streamingDestination.CreateStream(destination);
                        HttpProxyLogger.Inst.Log( method, target, "Connecting", $"Created I2P stream {i2pStream.RecvStreamId:X8} to {hostname}" );
                    }
                    catch (Exception ex)
                    {
                        Logging.LogWarning($"HTTPProxy: Failed to connect to {hostname}: {ex.Message}");
                        await SendError(stream, 504, "I2P connection failed");
                        return;
                    }

                    if (i2pStream == null)
                    {
                        Logging.LogWarning($"HTTPProxy: CreateStream returned null for {hostname}");
                        await SendError(stream, 500, "Internal error creating I2P stream");
                        return;
                    }

                    // Send the rewritten HTTP request
                    var requestBytes = Encoding.ASCII.GetBytes(rewrittenHeader);
                    i2pStream.Send(requestBytes);

                    // Bidirectional forwarding
                    await ForwardBidirectional(stream, i2pStream, method, target, ct);
                }
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"HTTPProxy: Client handler error: {ex.Message}\r\n{ex.StackTrace}");
            }
        }

        /// <summary>
        /// Handle HTTPS CONNECT method: establish a tunnel through I2P.
        /// </summary>
        private async Task HandleConnect(NetworkStream clientStream, string target, CancellationToken ct)
        {
            // target is host:port, e.g. "example.i2p:443"
            var colonIdx = target.LastIndexOf(':');
            var hostname = colonIdx > 0
                ? target.Substring(0, colonIdx).ToLowerInvariant()
                : target.ToLowerInvariant();

            if (!hostname.EndsWith(".i2p"))
            {
                if (string.IsNullOrEmpty(OutproxyUrl))
                {
                    await SendError(clientStream, 403, "CONNECT only supported for .i2p");
                    return;
                }
                // For CONNECT to non-.i2p through outproxy, we can't easily tunnel HTTPS
                // through an HTTP outproxy. Return an error for this case.
                await SendError(clientStream, 403,
                    "HTTPS CONNECT through outproxy is not supported. Use HTTP only.");
                return;
            }

            var destination = ResolveDestination(hostname);
            if (destination == null && hostname.EndsWith(".b32.i2p"))
                destination = await ResolveB32Async(hostname, ct);

            if (destination == null)
            {
                await SendError(clientStream, 504, $"Cannot resolve {hostname}");
                return;
            }

            I2PStream i2pStream;
            try
            {
                i2pStream = _streamingDestination.CreateStream(destination);
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"HTTPProxy: CONNECT failed to {hostname}: {ex.Message}");
                await SendError(clientStream, 504, "I2P connection failed");
                return;
            }

            // Tell the client the tunnel is established (matches Java I2P's response)
            var established = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-agent: I2P\r\n\r\n");
            await clientStream.WriteAsync(established, 0, established.Length, ct);

            // Now forward raw bytes in both directions
            await ForwardBidirectional(clientStream, i2pStream, "CONNECT", target, ct);
        }

        /// <summary>
        /// Extract the i2paddresshelper value from a URL query string.
        /// </summary>
        private static string ExtractAddressHelper(Uri uri)
        {
            var query = uri.Query;
            if (string.IsNullOrEmpty(query))
                return null;

            // Parse manually for ?i2paddresshelper= or &i2paddresshelper=
            const string key = "i2paddresshelper=";
            var idx = query.IndexOf(key, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                return null;

            var start = idx + key.Length;
            var end = query.IndexOf('&', start);
            var value = end > 0
                ? query.Substring(start, end - start)
                : query.Substring(start);

            return Uri.UnescapeDataString(value);
        }

        /// <summary>
        /// Remove the i2paddresshelper parameter from the URL.
        /// </summary>
        private static string RemoveAddressHelperParam(Uri uri)
        {
            var query = uri.Query;
            if (string.IsNullOrEmpty(query))
                return uri.ToString();

            const string key = "i2paddresshelper";
            var builder = new StringBuilder();
            builder.Append(uri.GetLeftPart(UriPartial.Path));

            var pairs = query.TrimStart('?').Split('&');
            var filtered = new StringBuilder();
            foreach (var pair in pairs)
            {
                if (!pair.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase)
                    && !pair.Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    if (filtered.Length > 0) filtered.Append('&');
                    filtered.Append(pair);
                }
            }

            if (filtered.Length > 0)
            {
                builder.Append('?');
                builder.Append(filtered);
            }

            return builder.ToString();
        }

        /// <summary>
        /// Resolve an .i2p hostname to an I2PDestination.
        /// First checks the local address book, then falls back to base32 lookup.
        /// </summary>
        private I2PDestination ResolveDestination(string hostname)
        {
            // Check address book
            if (_addressBook.TryGetValue(hostname, out var base64))
            {
                try
                {
                    var destBytes = FreenetBase64.Decode(base64);
                    return new I2PDestination(new BufRef(destBytes));
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"HTTPProxy: Failed to decode address book entry for {hostname}: {ex.Message}");
                }
            }

            // For .b32.i2p addresses, async lookup is handled by ResolveB32Async
            if (hostname.EndsWith(".b32.i2p"))
            {
                Logging.LogDebug($"HTTPProxy: b32 lookup for {hostname} requires async netdb query");
            }
            else
            {
                Logging.LogDebug($"HTTPProxy: Cannot resolve {hostname} - not in address book");
            }

            return null;
        }

        /// <summary>
        /// Resolve a .b32.i2p address by performing a LeaseSet lookup via floodfills.
        /// The b32 string is the base32-encoded 32-byte identity hash.
        /// </summary>
        private async Task<I2PDestination> ResolveB32Async(string hostname, CancellationToken ct)
        {
            try
            {
                // Decode the b32 address to an identity hash
                var identHash = new I2PIdentHash(hostname);
                Logging.LogInformation($"HTTPProxy: Looking up b32 address {hostname} → {identHash.Id32Short}");

                // Use ClientDestination's LookupDestination which goes through
                // IdentResolver → floodfill DatabaseLookup → LeaseSet response
                var tcs = new TaskCompletionSource<I2PDestination>();

                _clientDestination.LookupDestination(
                    identHash,
                    (hash, leaseSet, tag) =>
                    {
                        if (leaseSet != null)
                        {
                            Logging.LogInformation($"HTTPProxy: b32 resolved {hostname} → LeaseSet with {leaseSet.Leases.Count()} leases");
                            tcs.TrySetResult(leaseSet.Destination);
                        }
                        else
                        {
                            Logging.LogWarning($"HTTPProxy: b32 lookup failed for {hostname}");
                            tcs.TrySetResult(null);
                        }
                    });

                // Wait up to 120 seconds for the lookup (I2P is slow; client tunnels need time to build)
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(120));

                try
                {
                    var result = await tcs.Task.WaitAsync(timeoutCts.Token);
                    if (result != null)
                    {
                        // Cache the resolved destination in the address book for future lookups
                        try
                        {
                            var destStream = new BufRefStream();
                            result.Write(destStream);
                            var destBase64 = FreenetBase64.Encode(new BufLen(destStream.ToByteArray()));
                            _addressBook[hostname.ToLowerInvariant()] = destBase64;
                            Logging.LogInformation($"HTTPProxy: Cached resolved destination for {hostname}");
                        }
                        catch (Exception cacheEx)
                        {
                            Logging.LogDebug($"HTTPProxy: Failed to cache destination: {cacheEx.Message}");
                        }
                    }
                    return result;
                }
                catch (OperationCanceledException)
                {
                    Logging.LogWarning($"HTTPProxy: b32 lookup timed out for {hostname}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"HTTPProxy: b32 resolution error for {hostname}: {ex.Message}");
                return null;
            }
        }

        // Headers stripped from client requests (fingerprinting / proxy metadata)
        // Matches Java I2P I2PTunnelHTTPClient defaults
        private static readonly HashSet<string> StrippedRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
        {
            "User-Agent",
            "Via",
            "Referer",
            "Accept-Language",
            "Accept-Charset",
            "Keep-Alive",
            "Proxy-Connection",
            "Proxy-Authorization",
            "From",
        };

        // Java I2P uses this anonymous User-Agent for I2P destinations (MYOB/6.66 (AN/ON))
        private const string I2PUserAgent = "MYOB/6.66 (AN/ON)";

        // Java I2P adds this header to signal gzip support via I2P's custom encoding
        private const string I2PAcceptEncoding = "x-i2p-gzip;q=1.0, identity;q=0.5, deflate;q=0, gzip;q=0, *;q=0";

        /// <summary>
        /// Rewrite the HTTP request header to match Java I2P's I2PTunnelHTTPClient behavior:
        /// - Convert absolute URI to relative path
        /// - Set Host header to the I2P hostname
        /// - Strip fingerprinting headers (User-Agent, Via, Referer, Accept-Language, etc.)
        /// - Replace User-Agent with MYOB/6.66 (AN/ON)
        /// - Add X-Accept-Encoding for I2P's gzip support
        /// - Strip proxy-specific headers
        /// </summary>
        private static string RewriteRequestHeader(string header, string method, string relativePath, string hostname)
        {
            var lines = header.Split(new[] { "\r\n" }, StringSplitOptions.None);
            var sb = new StringBuilder();

            // Rewrite request line: absolute URI → relative, always HTTP/1.1
            sb.Append(method);
            sb.Append(' ');
            sb.Append(relativePath);
            sb.Append(" HTTP/1.1\r\n");

            // Host header (mandatory)
            sb.Append("Host: ");
            sb.Append(hostname);
            sb.Append("\r\n");

            // Anonymous User-Agent (Java I2P: MYOB/6.66 (AN/ON))
            sb.Append("User-Agent: ");
            sb.Append(I2PUserAgent);
            sb.Append("\r\n");

            // X-Accept-Encoding: signal I2P gzip support (Java I2P default behaviour)
            sb.Append("X-Accept-Encoding: ");
            sb.Append(I2PAcceptEncoding);
            sb.Append("\r\n");

            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrEmpty(line)) continue;

                // Determine header name
                var colonIdx = line.IndexOf(':');
                if (colonIdx <= 0)
                {
                    // Not a header line (blank line terminator handled above)
                    continue;
                }

                var headerName = line.Substring(0, colonIdx).Trim();

                // Skip headers we've already set or are stripping
                if (headerName.Equals("Host", StringComparison.OrdinalIgnoreCase)
                    || StrippedRequestHeaders.Contains(headerName))
                    continue;

                sb.Append(line);
                sb.Append("\r\n");
            }

            // Terminate headers
            sb.Append("\r\n");

            return sb.ToString();
        }

        /// <summary>
        /// Read HTTP header from stream until \r\n\r\n is found.
        /// </summary>
        private static async Task<byte[]> ReadHttpHeader(NetworkStream stream, CancellationToken ct)
        {
            var buffer = new byte[HeaderMaxBytes];
            int totalRead = 0;

            while (totalRead < HeaderMaxBytes)
            {
                var bytesRead = await stream.ReadAsync(buffer, totalRead, Math.Min(1024, buffer.Length - totalRead), ct);
                if (bytesRead == 0)
                    return null;

                totalRead += bytesRead;

                // Look for end of headers
                for (int i = Math.Max(0, totalRead - bytesRead - 3); i <= totalRead - 4; i++)
                {
                    if (buffer[i] == '\r' && buffer[i + 1] == '\n'
                        && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                    {
                        var result = new byte[i + 4];
                        Array.Copy(buffer, result, i + 4);
                        return result;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Forward data bidirectionally between a TCP NetworkStream and an I2PStream.
        /// </summary>
        private static async Task ForwardBidirectional(NetworkStream tcpStream, I2PStream i2pStream, string method, string target, CancellationToken ct)
        {
            if (tcpStream == null || i2pStream == null)
            {
                Logging.LogWarning("HTTPProxy: ForwardBidirectional called with null stream(s)");
                return;
            }

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
            var responseData = new StringBuilder();
            bool isFirstDataReceived = false;

            var i2pToTcpWorker = Task.Run(async () =>
            {
                try
                {
                    await foreach (var data in i2pDataQueue.Reader.ReadAllAsync(linkedCts.Token))
                    {
                        if (!isFirstDataReceived)
                        {
                            isFirstDataReceived = true;
                            HttpProxyLogger.Inst.Log(method, target, "Streaming", $"First data packet received from I2P: {data.Length} bytes.");
                        }

                        // Capture first 10KB for logging
                        if (responseData.Length < 10240)
                        {
                            responseData.Append(Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 10240 - responseData.Length)));
                        }

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

            Action<I2PStream, I2PStream.StreamStatus> statusChangedHandler = (stream, status) =>
            {
                HttpProxyLogger.Inst.Log( method, target, "Streaming", $"I2P stream status changed to {status}" );
            };

            Action<I2PStream, uint, int> packetSentHandler = (stream, seq, len) =>
            {
                HttpProxyLogger.Inst.Log( method, target, "Streaming", $"I2P packet SENT: seq {seq}, {len} bytes" );
            };

            Action<I2PStream, uint, int> packetReceivedHandler = (stream, seq, len) =>
            {
                HttpProxyLogger.Inst.Log( method, target, "Streaming", $"I2P packet RECEIVED: seq {seq}, {len} bytes" );
            };

            i2pStream.DataReceived += dataReceivedHandler;
            i2pStream.StreamClosed += streamClosedHandler;
            i2pStream.StatusChanged += statusChangedHandler;
            i2pStream.PacketSent += packetSentHandler;
            i2pStream.PacketReceived += packetReceivedHandler;

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
                i2pStream.StatusChanged -= statusChangedHandler;
                i2pStream.PacketSent -= packetSentHandler;
                i2pStream.PacketReceived -= packetReceivedHandler;

                // Log the final status and captured data
                HttpProxyLogger.Inst.Log( method, target, "Completed", 
                    $"Transferred data finished. Captured {responseData.Length} bytes of response body.",
                    responseData.ToString() );
                
                // Ensure worker tasks are really finished
                try { await Task.WhenAll(tcpToI2p, i2pToTcpWorker); } catch { }
                
                i2pStream.Close();
            }
        }

        private static async Task SendError(NetworkStream stream, int statusCode, string message)
        {
            var body = $"<html><body><h1>{statusCode} {message}</h1></body></html>";
            var response = $"HTTP/1.1 {statusCode} {message}\r\n"
                         + "Content-Type: text/html\r\n"
                         + $"Content-Length: {body.Length}\r\n"
                         + "Connection: close\r\n"
                         + "\r\n"
                         + body;

            var bytes = Encoding.ASCII.GetBytes(response);
            try
            {
                await stream.WriteAsync(bytes, 0, bytes.Length);
            }
            catch (Exception) { /* client may have disconnected */ }
        }

        /// <summary>
        /// Forward a non-.i2p HTTP request through the configured outproxy.
        /// The outproxy is an .i2p destination that acts as an HTTP exit proxy.
        /// We connect to the outproxy via I2P and forward the original HTTP request.
        /// </summary>
        private async Task ForwardToOutproxy(NetworkStream clientStream, string requestLine, string target, byte[] headerData, CancellationToken ct)
        {
            try
            {
                // Parse the outproxy URL to get the .i2p host
                if (!Uri.TryCreate(OutproxyUrl, UriKind.Absolute, out var outproxyUri))
                {
                    await SendError(clientStream, 502, "Invalid outproxy URL configuration");
                    return;
                }

                var outproxyHost = outproxyUri.Host.ToLowerInvariant();
                var outproxyDest = ResolveDestination(outproxyHost);
                if (outproxyDest == null)
                {
                    await SendError(clientStream, 502, $"Cannot resolve outproxy: {outproxyHost}");
                    return;
                }

                // Create I2P stream to the outproxy
                I2PStream i2pStream;
                try
                {
                    i2pStream = _streamingDestination.CreateStream(outproxyDest);
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"HTTPProxy: Failed to connect to outproxy {outproxyHost}: {ex.Message}");
                    await SendError(clientStream, 502, "Failed to connect to outproxy");
                    return;
                }

                // Forward the original request as-is to the outproxy
                // (outproxies expect the full absolute URL in the request line)
                var headerStr = Encoding.ASCII.GetString(headerData);

                // Ensure request has Connection: close to simplify handling
                if (!headerStr.Contains("Connection:", StringComparison.OrdinalIgnoreCase))
                {
                    headerStr = headerStr.TrimEnd('\r', '\n') + "\r\nConnection: close\r\n\r\n";
                }

                i2pStream.Send(Encoding.ASCII.GetBytes(headerStr));

                Logging.LogDebug($"HTTPProxy: Forwarding to outproxy {outproxyHost}: {requestLine}");
                HttpProxyLogger.Inst.Log( "OUTPROXY", target, "Forwarding", $"Forwarding to outproxy {outproxyHost}" );

                await ForwardBidirectional(clientStream, i2pStream, "OUTPROXY", target, ct);
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"HTTPProxy: Outproxy error: {ex.Message}");
                try { await SendError(clientStream, 502, "Outproxy connection failed"); }
                catch { }
            }
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }
}
