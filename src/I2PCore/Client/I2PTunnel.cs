using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.Streaming;
using I2PCore.Utils;

namespace I2PCore.Client
{
    /// <summary>
    /// Outbound tunnel client: listens on a local TCP port and forwards all
    /// connections to a fixed I2P destination via the streaming layer.
    /// This is the equivalent of "client tunnel" in i2pd/Java I2P.
    /// </summary>
    public class I2PTunnelClient : IDisposable
    {
        public const int ForwardBufferSize = 8192;

        private readonly int _listenPort;
        private readonly I2PDestination _remoteDestination;
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private readonly ClientDestination _clientDestination;
        private readonly StreamingDestination _streamingDestination;

        public bool IsRunning { get; private set; }

        /// <summary>
        /// Create an outbound I2P tunnel client.
        /// </summary>
        /// <param name="clientDestination">The I2P client destination for outbound connectivity.</param>
        /// <param name="streamingDestination">The streaming destination for creating streams.</param>
        /// <param name="remoteDestination">The fixed remote I2P destination to tunnel to.</param>
        /// <param name="listenPort">Local TCP port to listen on.</param>
        public I2PTunnelClient(
            ClientDestination clientDestination,
            StreamingDestination streamingDestination,
            I2PDestination remoteDestination,
            int listenPort)
        {
            _clientDestination = clientDestination ?? throw new ArgumentNullException(nameof(clientDestination));
            _streamingDestination = streamingDestination ?? throw new ArgumentNullException(nameof(streamingDestination));
            _remoteDestination = remoteDestination ?? throw new ArgumentNullException(nameof(remoteDestination));
            _listenPort = listenPort;
        }

        /// <summary>
        /// Start accepting local TCP connections and tunneling them to I2P.
        /// </summary>
        public void Start()
        {
            if (IsRunning) return;

            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, _listenPort);
            _listener.Start();
            IsRunning = true;

            Logging.LogInformation(
                $"I2PTunnelClient: Listening on 127.0.0.1:{_listenPort} -> "
                + $"{_remoteDestination.IdentHash.Id32Short}");

            Task.Run(() => AcceptLoop(_cts.Token));
        }

        /// <summary>
        /// Stop the tunnel client.
        /// </summary>
        public void Stop()
        {
            if (!IsRunning) return;

            IsRunning = false;
            _cts?.Cancel();

            try { _listener?.Stop(); }
            catch (Exception) { /* ignore */ }

            Logging.LogInformation("I2PTunnelClient: Stopped");
        }

        private async Task AcceptLoop(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleConnection(tcpClient, ct), ct);
                }
            }
            catch (ObjectDisposedException) { /* listener stopped */ }
            catch (Exception ex)
            {
                Logging.LogWarning($"I2PTunnelClient: Accept loop error: {ex.Message}");
            }
        }

        private async Task HandleConnection(TcpClient tcpClient, CancellationToken ct)
        {
            try
            {
                using (tcpClient)
                {
                    tcpClient.NoDelay = true;
                    var tcpStream = tcpClient.GetStream();

                    I2PStream i2pStream;
                    try
                    {
                        i2pStream = _streamingDestination.CreateStream(_remoteDestination);
                    }
                    catch (Exception ex)
                    {
                        Logging.LogWarning(
                            $"I2PTunnelClient: Failed to open I2P stream: {ex.Message}");
                        return;
                    }

                    Logging.LogDebug(
                        $"I2PTunnelClient: New tunnel connection from "
                        + $"{tcpClient.Client.RemoteEndPoint}");

                    await ForwardBidirectional(tcpStream, i2pStream, ct);
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PTunnelClient: Connection error: {ex.Message}");
            }
        }

        /// <summary>
        /// Forward data bidirectionally between a TCP NetworkStream and an I2PStream.
        /// </summary>
        private static async Task ForwardBidirectional(
            NetworkStream tcpStream,
            I2PStream i2pStream,
            CancellationToken ct)
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

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }

    /// <summary>
    /// Inbound tunnel server: accepts incoming I2P streaming connections and
    /// forwards them to a local TCP host:port. This is the equivalent of
    /// "server tunnel" in i2pd/Java I2P.
    /// </summary>
    public class I2PTunnelServer : IDisposable
    {
        public const int ForwardBufferSize = 8192;

        private readonly string _targetHost;
        private readonly int _targetPort;
        private CancellationTokenSource _cts;
        private readonly ClientDestination _clientDestination;
        private readonly StreamingDestination _streamingDestination;

        public bool IsRunning { get; private set; }

        /// <summary>
        /// Create an inbound I2P tunnel server.
        /// </summary>
        /// <param name="clientDestination">The I2P client destination that receives inbound streams.</param>
        /// <param name="streamingDestination">The streaming destination for accepting streams.</param>
        /// <param name="targetHost">The local TCP host to forward to (e.g. "127.0.0.1").</param>
        /// <param name="targetPort">The local TCP port to forward to.</param>
        public I2PTunnelServer(
            ClientDestination clientDestination,
            StreamingDestination streamingDestination,
            string targetHost,
            int targetPort)
        {
            _clientDestination = clientDestination ?? throw new ArgumentNullException(nameof(clientDestination));
            _streamingDestination = streamingDestination ?? throw new ArgumentNullException(nameof(streamingDestination));
            _targetHost = targetHost ?? throw new ArgumentNullException(nameof(targetHost));
            _targetPort = targetPort;
        }

        /// <summary>
        /// Start accepting incoming I2P streams and forwarding to the local target.
        /// </summary>
        public void Start()
        {
            if (IsRunning) return;

            _cts = new CancellationTokenSource();
            IsRunning = true;

            Logging.LogInformation(
                $"I2PTunnelServer: Accepting I2P streams -> {_targetHost}:{_targetPort} "
                + $"(dest: {_clientDestination.Destination.IdentHash.Id32Short})");

            Task.Run(() => AcceptLoop(_cts.Token));
        }

        /// <summary>
        /// Stop the tunnel server.
        /// </summary>
        public void Stop()
        {
            if (!IsRunning) return;

            IsRunning = false;
            _cts?.Cancel();

            Logging.LogInformation("I2PTunnelServer: Stopped");
        }

        private async Task AcceptLoop(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    I2PStream i2pStream;
                    try
                    {
                        i2pStream = await _streamingDestination.AcceptStreamAsync(ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (i2pStream == null)
                        continue;

                    _ = Task.Run(() => HandleIncoming(i2pStream, ct), ct);
                }
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    Logging.LogWarning($"I2PTunnelServer: Accept loop error: {ex.Message}");
            }
        }

        private async Task HandleIncoming(I2PStream i2pStream, CancellationToken ct)
        {
            TcpClient tcpClient = null;
            try
            {
                tcpClient = new TcpClient();
                await tcpClient.ConnectAsync(_targetHost, _targetPort);
                tcpClient.NoDelay = true;

                var tcpStream = tcpClient.GetStream();

                Logging.LogDebug(
                    $"I2PTunnelServer: Incoming I2P stream -> {_targetHost}:{_targetPort}");

                await ForwardBidirectional(tcpStream, i2pStream, ct);
            }
            catch (Exception ex)
            {
                Logging.LogDebug(
                    $"I2PTunnelServer: Failed to connect to {_targetHost}:{_targetPort}: {ex.Message}");
                i2pStream.Close();
            }
            finally
            {
                tcpClient?.Dispose();
            }
        }

        /// <summary>
        /// Forward data bidirectionally between a TCP NetworkStream and an I2PStream.
        /// </summary>
        private static async Task ForwardBidirectional(
            NetworkStream tcpStream,
            I2PStream i2pStream,
            CancellationToken ct)
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

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }
}
