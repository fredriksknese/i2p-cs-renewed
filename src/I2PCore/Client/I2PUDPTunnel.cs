using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
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
    // Constants from i2pd reference
    public static class UDPTunnelConstants
    {
        public const int SESSION_TIMEOUT_MS = 120000;           // 2 minutes
        public const int REPLIABLE_DATAGRAM_INTERVAL_MS = 100;  // min interval for signed datagrams
        public const int MAX_UNACKED_DATAGRAM_TIME_MS = 8000;   // ACK timeout
        public const int MAX_NUM_UNACKED_DATAGRAMS = 500;       // max unacked window
        public const int MAX_MTU = 65536;
    }

    /// <summary>
    /// Tracks an active UDP session between a local UDP endpoint and a remote I2P destination.
    /// Used by I2PUDPServerTunnel for per-client sessions.
    /// </summary>
    public class UDPSession : IDisposable
    {
        public I2PIdentHash RemoteIdentity { get; set; }
        public IPEndPoint LocalEndpoint { get; set; }
        public IPEndPoint RemoteEndpoint { get; set; }
        public ushort LocalPort { get; set; }
        public ushort RemotePort { get; set; }
        public long LastActivity { get; set; }

        // Datagram sequence tracking
        public uint NextSendPacketNum { get; set; } = 1;
        public uint LastReceivedPacketNum { get; set; }

        // RTT tracking
        public long RTT { get; set; }
        public bool IsFirstPacket { get; set; } = true;
        public bool IsSendingAllowed { get; set; } = true;

        // Unacked datagrams for ACK-based flow control
        private readonly List<(uint Seqn, long Timestamp)> _unackedDatagrams = new();
        private readonly object _ackLock = new();

        public UdpClient Socket { get; set; }

        public void RecordSend(uint seqn)
        {
            lock (_ackLock)
            {
                _unackedDatagrams.Add((seqn, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
                if (_unackedDatagrams.Count > UDPTunnelConstants.MAX_NUM_UNACKED_DATAGRAMS)
                    IsSendingAllowed = false;
            }
        }

        public void ProcessAck(uint seqn)
        {
            lock (_ackLock)
            {
                IsFirstPacket = false;
                int idx = _unackedDatagrams.FindIndex(d => d.Seqn == seqn);
                if (idx >= 0)
                {
                    var sendTime = _unackedDatagrams[idx].Timestamp;
                    var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    var newRtt = now - sendTime;
                    RTT = RTT == 0 ? newRtt : (RTT + newRtt) / 2;

                    // Remove all datagrams up to and including this seqn
                    _unackedDatagrams.RemoveAll(d => d.Seqn <= seqn);
                }
                IsSendingAllowed = true;
            }
        }

        public void DeleteExpiredUnacked()
        {
            lock (_ackLock)
            {
                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                _unackedDatagrams.RemoveAll(d =>
                    now - d.Timestamp > UDPTunnelConstants.MAX_UNACKED_DATAGRAM_TIME_MS);
            }
        }

        public int UnackedCount
        {
            get { lock (_ackLock) return _unackedDatagrams.Count; }
        }

        public void Dispose()
        {
            Socket?.Dispose();
        }
    }

    /// <summary>
    /// I2P UDP Server Tunnel: receives datagrams from I2P and forwards them to a local UDP endpoint.
    /// Multiple remote I2P destinations are multiplexed through sessions.
    /// Port of i2pd's I2PUDPServerTunnel.
    /// </summary>
    public class I2PUDPServerTunnel : IDisposable
    {
        public string Name { get; }
        public bool IsRunning { get; private set; }

        private readonly IPEndPoint _forwardTo;
        private readonly ushort _i2pPort;
        private readonly bool _gzip;
        private readonly DatagramDestination _datagramDest;
        private readonly ConcurrentDictionary<uint, UDPSession> _sessions = new();
        private UDPSession _lastSession; // cache
        private readonly CancellationTokenSource _cts = new();
        private Timer _cleanupTimer;

        public I2PUDPServerTunnel(
            string name,
            DatagramDestination datagramDest,
            IPEndPoint forwardTo,
            ushort i2pPort,
            bool gzip = false)
        {
            Name = name;
            _datagramDest = datagramDest ?? throw new ArgumentNullException(nameof(datagramDest));
            _forwardTo = forwardTo ?? throw new ArgumentNullException(nameof(forwardTo));
            _i2pPort = i2pPort;
            _gzip = gzip;
        }

        public void Start()
        {
            if (IsRunning) return;
            IsRunning = true;

            // Register to receive datagrams from I2P
            _datagramDest.DatagramReceived += OnDatagramReceived;
            _datagramDest.RegisterPortHandler(_i2pPort, OnPortDatagram);

            // Periodic cleanup of stale sessions
            _cleanupTimer = new Timer(_ => ExpireStale(), null, 30000, 30000);

            Logging.LogInformation($"I2PUDPServerTunnel '{Name}': Started, forwarding to {_forwardTo}");
        }

        public void Stop()
        {
            if (!IsRunning) return;
            IsRunning = false;

            _datagramDest.DatagramReceived -= OnDatagramReceived;
            _datagramDest.UnregisterPortHandler(_i2pPort);
            _cleanupTimer?.Dispose();
            _cts.Cancel();

            foreach (var session in _sessions.Values)
                session.Dispose();
            _sessions.Clear();

            Logging.LogInformation($"I2PUDPServerTunnel '{Name}': Stopped");
        }

        private void OnDatagramReceived(object sender, DatagramDestination.DatagramReceivedEventArgs e)
        {
            if (e.ToPort == _i2pPort || _i2pPort == 0)
                HandleRecvFromI2P(e);
        }

        private void OnPortDatagram(DatagramDestination.DatagramReceivedEventArgs e)
        {
            HandleRecvFromI2P(e);
        }

        private void HandleRecvFromI2P(DatagramDestination.DatagramReceivedEventArgs e)
        {
            if (e.Payload == null || e.Payload.Length == 0) return;

            try
            {
                var senderHash = e.Sender != null ? new I2PIdentHash(e.Sender) : null;
                var session = ObtainSession(senderHash, e.FromPort, e.ToPort);

                session.LastActivity = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Forward to local UDP endpoint
                session.Socket.Send(e.Payload, e.Payload.Length, _forwardTo);
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PUDPServerTunnel '{Name}': Error forwarding: {ex.Message}");
            }
        }

        private UDPSession ObtainSession(I2PIdentHash remoteHash, ushort fromPort, ushort toPort)
        {
            uint idx = ((uint)fromPort << 16) | toPort;

            // Fast path: check cache
            var last = _lastSession;
            if (last != null && _sessions.ContainsKey(idx))
                return last;

            return _sessions.GetOrAdd(idx, key =>
            {
                var session = new UDPSession
                {
                    RemoteIdentity = remoteHash,
                    RemoteEndpoint = _forwardTo,
                    LocalPort = toPort,
                    RemotePort = fromPort,
                    LastActivity = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    Socket = new UdpClient()
                };

                // Start receiving from local UDP (for return traffic)
                Task.Run(() => ReceiveFromLocal(session));

                _lastSession = session;
                Logging.LogDebug($"I2PUDPServerTunnel '{Name}': New session from {remoteHash?.Id32Short}");
                return session;
            });
        }

        private async Task ReceiveFromLocal(UDPSession session)
        {
            try
            {
                while (!_cts.IsCancellationRequested && IsRunning)
                {
                    var result = await session.Socket.ReceiveAsync();
                    if (result.Buffer.Length > 0 && session.RemoteIdentity != null)
                    {
                        // Forward back to I2P
                        _datagramDest.SendRepliableDatagram(
                            session.RemoteIdentity, result.Buffer,
                            session.LocalPort, session.RemotePort);
                    }
                }
            }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PUDPServerTunnel '{Name}': Local receive error: {ex.Message}");
            }
        }

        public void ExpireStale()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var expired = _sessions
                .Where(kv => now - kv.Value.LastActivity > UDPTunnelConstants.SESSION_TIMEOUT_MS)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in expired)
            {
                if (_sessions.TryRemove(key, out var session))
                {
                    session.Dispose();
                    Logging.LogDebug($"I2PUDPServerTunnel '{Name}': Expired session");
                }
            }
        }

        public int SessionCount => _sessions.Count;

        public void Dispose()
        {
            Stop();
        }
    }

    /// <summary>
    /// I2P UDP Client Tunnel: receives datagrams from a local UDP socket
    /// and forwards them to a remote I2P destination.
    /// Port of i2pd's I2PUDPClientTunnel.
    /// </summary>
    public class I2PUDPClientTunnel : IDisposable
    {
        public string Name { get; }
        public bool IsRunning { get; private set; }
        public bool IsResolved { get; private set; }

        private readonly string _remoteDest;
        private readonly IPEndPoint _localEndpoint;
        private readonly ushort _remotePort;
        private readonly bool _gzip;
        private readonly DatagramDestination _datagramDest;
        private readonly DatagramDestination.DatagramProtocol _datagramVersion;

        private UdpClient _localSocket;
        private I2PIdentHash _remoteIdentHash;
        private readonly CancellationTokenSource _cts = new();
        private readonly ConcurrentDictionary<ushort, (IPEndPoint Endpoint, long LastTime)> _sessions = new();
        private Timer _cleanupTimer;

        // ACK/flow control state
        private uint _nextSendPacketNum = 1;
        private uint _lastReceivedPacketNum;
        private long _rtt;
        private long _lastRepliableTime;
        private bool _isSendingAllowed = true;

        public I2PUDPClientTunnel(
            string name,
            string remoteDest,
            IPEndPoint localEndpoint,
            DatagramDestination datagramDest,
            ushort remotePort,
            bool gzip = false,
            DatagramDestination.DatagramProtocol version = DatagramDestination.DatagramProtocol.RepliableV2)
        {
            Name = name;
            _remoteDest = remoteDest ?? throw new ArgumentNullException(nameof(remoteDest));
            _localEndpoint = localEndpoint ?? throw new ArgumentNullException(nameof(localEndpoint));
            _datagramDest = datagramDest ?? throw new ArgumentNullException(nameof(datagramDest));
            _remotePort = remotePort;
            _gzip = gzip;
            _datagramVersion = version;
        }

        public void Start()
        {
            if (IsRunning) return;
            IsRunning = true;

            _localSocket = new UdpClient(_localEndpoint);

            // Register for incoming I2P datagrams
            _datagramDest.DatagramReceived += OnDatagramReceived;

            // Start local receive loop
            _ = Task.Run(() => ReceiveFromLocalLoop(), _cts.Token);

            // Start resolving remote destination
            _ = Task.Run(() => TryResolving(), _cts.Token);

            // Periodic cleanup
            _cleanupTimer = new Timer(_ => ExpireStale(), null, 30000, 30000);

            Logging.LogInformation($"I2PUDPClientTunnel '{Name}': Started on {_localEndpoint}");
        }

        public void Stop()
        {
            if (!IsRunning) return;
            IsRunning = false;

            _datagramDest.DatagramReceived -= OnDatagramReceived;
            _cleanupTimer?.Dispose();
            _cts.Cancel();
            _localSocket?.Dispose();
            _sessions.Clear();

            Logging.LogInformation($"I2PUDPClientTunnel '{Name}': Stopped");
        }

        private async Task TryResolving()
        {
            while (!_cts.IsCancellationRequested && !IsResolved)
            {
                try
                {
                    // Try to resolve as base32 address
                    if (_remoteDest.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase) ||
                        _remoteDest.EndsWith(".b32.i2p", StringComparison.OrdinalIgnoreCase))
                    {
                        var stripped = _remoteDest;
                        if (stripped.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase))
                            stripped = stripped[..^4];
                        if (stripped.EndsWith(".b32", StringComparison.OrdinalIgnoreCase))
                            stripped = stripped[..^4];

                        _remoteIdentHash = new I2PIdentHash(stripped);
                        IsResolved = true;
                        Logging.LogInformation($"I2PUDPClientTunnel '{Name}': Resolved to {_remoteIdentHash.Id32Short}");
                        return;
                    }

                    // Try base64 destination
                    var destBytes = FreenetBase64.Decode(_remoteDest);
                    if (destBytes != null && destBytes.Length >= 387)
                    {
                        var dest = new I2PDestination(new I2PBufferCursor(destBytes));
                        _remoteIdentHash = new I2PIdentHash(dest);
                        IsResolved = true;
                        Logging.LogInformation($"I2PUDPClientTunnel '{Name}': Resolved to {_remoteIdentHash.Id32Short}");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogDebug($"I2PUDPClientTunnel '{Name}': Resolve attempt failed: {ex.Message}");
                }

                await Task.Delay(1000, _cts.Token);
            }
        }

        private async Task ReceiveFromLocalLoop()
        {
            try
            {
                while (!_cts.IsCancellationRequested && IsRunning)
                {
                    var result = await _localSocket.ReceiveAsync();
                    if (result.Buffer.Length > 0)
                        HandleReceiveFromLocal(result.Buffer, result.RemoteEndPoint);
                }
            }
            catch (ObjectDisposedException) { }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PUDPClientTunnel '{Name}': Local receive error: {ex.Message}");
            }
        }

        private void HandleReceiveFromLocal(byte[] data, IPEndPoint from)
        {
            if (!IsResolved || _remoteIdentHash == null)
            {
                Logging.LogDebug($"I2PUDPClientTunnel '{Name}': Not yet resolved, dropping packet");
                return;
            }

            if (!_isSendingAllowed) return;

            // Track session by source port
            ushort fromPort = (ushort)from.Port;
            _sessions[fromPort] = (from, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long interval = _rtt > 0
                ? Math.Max(UDPTunnelConstants.REPLIABLE_DATAGRAM_INTERVAL_MS, _rtt / 2)
                : UDPTunnelConstants.REPLIABLE_DATAGRAM_INTERVAL_MS;

            if (now - _lastRepliableTime >= interval)
            {
                // Send signed/repliable datagram
                _datagramDest.SendRepliableDatagram(
                    _remoteIdentHash, data, fromPort, _remotePort);
                _lastRepliableTime = now;
            }
            else
            {
                // Batch mode: send raw (unsigned) for performance
                _datagramDest.SendRawDatagram(
                    _remoteIdentHash, data, fromPort, _remotePort);
            }

            _nextSendPacketNum++;
        }

        private void OnDatagramReceived(object sender, DatagramDestination.DatagramReceivedEventArgs e)
        {
            if (e.Payload == null || e.Payload.Length == 0) return;

            try
            {
                // Forward to the local client that last used this port
                ushort toPort = e.ToPort;
                if (toPort == 0) toPort = (ushort)_localEndpoint.Port;

                if (_sessions.TryGetValue(toPort, out var session))
                {
                    _localSocket.Send(e.Payload, e.Payload.Length, session.Endpoint);
                }
                else if (_sessions.Count > 0)
                {
                    // Send to the most recently active client
                    var latest = _sessions.Values.OrderByDescending(s => s.LastTime).First();
                    _localSocket.Send(e.Payload, e.Payload.Length, latest.Endpoint);
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PUDPClientTunnel '{Name}': Forward to local error: {ex.Message}");
            }
        }

        public void ExpireStale()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var expired = _sessions
                .Where(kv => now - kv.Value.LastTime > UDPTunnelConstants.SESSION_TIMEOUT_MS)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in expired)
                _sessions.TryRemove(key, out _);
        }

        public int SessionCount => _sessions.Count;

        public void Dispose()
        {
            Stop();
        }
    }
}
