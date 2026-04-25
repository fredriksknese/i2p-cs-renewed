using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.Streaming
{
    /// <summary>
    /// DatagramDestination manages datagram (UDP-like) messaging over I2P.
    /// Supports repliable datagrams (with sender identity + signature),
    /// raw datagrams (unsigned), and port-based routing.
    ///
    /// Each datagram session tracks the routing path and lease for a specific
    /// remote destination, optimizing for repeated sends.
    /// </summary>
    public class DatagramDestination : IDisposable
    {
        /// <summary>
        /// Datagram protocol versions.
        /// </summary>
        public enum DatagramProtocol : byte
        {
            Repliable = 0, // Standard repliable (destination + signature + payload)
            Raw = 1,       // Raw unsigned
            RepliableV2 = 2, // v2: with from/to ports
            RepliableV3 = 3  // v3: with from/to ports + offline signature support
        }

        /// <summary>
        /// Received datagram event data
        /// </summary>
        public class DatagramReceivedEventArgs : EventArgs
        {
            public I2PDestination Sender { get; set; }
            public byte[] Payload { get; set; }
            public ushort FromPort { get; set; }
            public ushort ToPort { get; set; }
            public bool Verified { get; set; }
            public bool IsRaw { get; set; }
        }

        /// <summary>
        /// Tracks a datagram session to a specific remote destination.
        /// </summary>
        private class DatagramSession
        {
            public I2PIdentHash RemoteHash { get; set; }
            public long LastSendTime { get; set; }
            public long LastReceiveTime { get; set; }
            public int SendCount { get; set; }
            public int ReceiveCount { get; set; }
        }

        private readonly I2PDestination _localDestination;
        private readonly I2PSigningPrivateKey _signingKey;
        private readonly Action<I2PIdentHash, byte[]> _sendCallback;
        private readonly ConcurrentDictionary<I2PIdentHash, DatagramSession> _sessions = new();
        private bool _disposed;

        // Port-based receive handlers
        private readonly ConcurrentDictionary<ushort, Action<DatagramReceivedEventArgs>> _portHandlers = new();

        /// <summary>
        /// Fired when a datagram is received on any port.
        /// </summary>
        public event EventHandler<DatagramReceivedEventArgs> DatagramReceived;

        /// <summary>
        /// Create a datagram destination for sending and receiving datagrams.
        /// </summary>
        /// <param name="localDestination">Our I2P destination</param>
        /// <param name="signingKey">Private signing key for repliable datagrams</param>
        /// <param name="sendCallback">Callback to send raw data to a remote ident hash</param>
        public DatagramDestination(
            I2PDestination localDestination,
            I2PSigningPrivateKey signingKey,
            Action<I2PIdentHash, byte[]> sendCallback)
        {
            _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));
            _signingKey = signingKey;
            _sendCallback = sendCallback ?? throw new ArgumentNullException(nameof(sendCallback));
        }

        /// <summary>
        /// Register a handler for datagrams arriving on a specific port.
        /// </summary>
        public void RegisterPortHandler(ushort port, Action<DatagramReceivedEventArgs> handler)
        {
            _portHandlers[port] = handler;
        }

        /// <summary>
        /// Unregister a port handler.
        /// </summary>
        public void UnregisterPortHandler(ushort port)
        {
            _portHandlers.TryRemove(port, out _);
        }

        /// <summary>
        /// Send a repliable datagram (includes sender identity and signature).
        /// </summary>
        public void SendRepliableDatagram(I2PIdentHash destination, byte[] payload,
            ushort fromPort = 0, ushort toPort = 0)
        {
            if (destination == null) throw new ArgumentNullException(nameof(destination));
            if (payload == null) throw new ArgumentNullException(nameof(payload));

            byte[] datagram;
            if (fromPort != 0 || toPort != 0)
            {
                // v2/v3 format with ports
                datagram = CreateRepliableDatagramV2(payload, fromPort, toPort);
            }
            else
            {
                datagram = I2PDatagramDissector.CreateRepliableDatagram(
                    _localDestination, _signingKey, payload);
            }

            TrackSend(destination);
            _sendCallback(destination, datagram);
        }

        /// <summary>
        /// Send a v3 repliable datagram with offline signature support.
        /// </summary>
        public void SendRepliableDatagramV3(I2PIdentHash destination, byte[] payload,
            I2POfflineSignature offlineSignature = null,
            ushort fromPort = 0, ushort toPort = 0)
        {
            if (destination == null) throw new ArgumentNullException(nameof(destination));
            if (payload == null) throw new ArgumentNullException(nameof(payload));

            var datagram = I2PDatagramDissector.CreateRepliableDatagramV3(
                _localDestination, _signingKey, offlineSignature, payload, fromPort, toPort);

            TrackSend(destination);
            _sendCallback(destination, datagram);
        }

        /// <summary>
        /// Send a raw (unsigned) datagram.
        /// </summary>
        public void SendRawDatagram(I2PIdentHash destination, byte[] payload,
            ushort fromPort = 0, ushort toPort = 0)
        {
            if (destination == null) throw new ArgumentNullException(nameof(destination));
            if (payload == null) throw new ArgumentNullException(nameof(payload));

            byte[] datagram;
            if (fromPort != 0 || toPort != 0)
            {
                // Raw with port header
                datagram = CreateRawDatagramWithPorts(payload, fromPort, toPort);
            }
            else
            {
                datagram = I2PDatagramDissector.CreateRawDatagram(payload);
            }

            TrackSend(destination);
            _sendCallback(destination, datagram);
        }

        /// <summary>
        /// Handle a received datagram from the network.
        /// </summary>
        public void HandleDatagram(byte[] data, bool isRaw = false)
        {
            if (data == null || data.Length == 0) return;

            try
            {
                DatagramReceivedEventArgs args;

                if (isRaw)
                {
                    args = new DatagramReceivedEventArgs
                    {
                        Payload = data,
                        IsRaw = true,
                        Verified = false
                    };
                }
                else
                {
                    var (sender, payload, verified) = I2PDatagramDissector.ParseRepliableDatagram(data);
                    if (sender == null) return;

                    args = new DatagramReceivedEventArgs
                    {
                        Sender = sender,
                        Payload = payload,
                        Verified = verified,
                        IsRaw = false
                    };

                    // Track session
                    var senderHash = new I2PIdentHash(sender);
                    TrackReceive(senderHash);
                }

                // Port-based routing
                if (_portHandlers.TryGetValue(args.ToPort, out var handler))
                {
                    handler(args);
                }

                // Generic event
                DatagramReceived?.Invoke(this, args);
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"DatagramDestination: HandleDatagram failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Get or create a session for a remote destination.
        /// </summary>
        private DatagramSession GetOrCreateSession(I2PIdentHash remote)
        {
            return _sessions.GetOrAdd(remote, hash => new DatagramSession
            {
                RemoteHash = hash,
                LastSendTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            });
        }

        private void TrackSend(I2PIdentHash remote)
        {
            var session = GetOrCreateSession(remote);
            session.LastSendTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            session.SendCount++;
        }

        private void TrackReceive(I2PIdentHash remote)
        {
            var session = GetOrCreateSession(remote);
            session.LastReceiveTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            session.ReceiveCount++;
        }

        /// <summary>
        /// Create a v2 repliable datagram with from/to ports.
        /// Format: destination + signature + fromPort(2) + toPort(2) + payload
        /// </summary>
        private byte[] CreateRepliableDatagramV2(byte[] payload, ushort fromPort, ushort toPort)
        {
            var senderBytes = _localDestination.ToByteArray();
            var signatureSize = _signingKey?.Certificate?.SignatureLength ?? 40;

            // Data to sign: destination + payload + fromPort + toPort
            var portData = new byte[4];
            portData[0] = (byte)(fromPort >> 8);
            portData[1] = (byte)(fromPort & 0xFF);
            portData[2] = (byte)(toPort >> 8);
            portData[3] = (byte)(toPort & 0xFF);

            var toSign = new byte[senderBytes.Length + payload.Length + 4];
            Array.Copy(senderBytes, 0, toSign, 0, senderBytes.Length);
            Array.Copy(payload, 0, toSign, senderBytes.Length, payload.Length);
            Array.Copy(portData, 0, toSign, senderBytes.Length + payload.Length, 4);

            byte[] signature;
            if (_signingKey != null)
                signature = I2PSignature.DoSign(_signingKey, new I2PByteBlock(toSign));
            else
                signature = new byte[signatureSize];

            var result = new byte[senderBytes.Length + signature.Length + 4 + payload.Length];
            int offset = 0;
            Array.Copy(senderBytes, 0, result, offset, senderBytes.Length);
            offset += senderBytes.Length;
            Array.Copy(signature, 0, result, offset, signature.Length);
            offset += signature.Length;
            Array.Copy(portData, 0, result, offset, 4);
            offset += 4;
            Array.Copy(payload, 0, result, offset, payload.Length);

            return result;
        }

        /// <summary>
        /// Create a raw datagram with port header.
        /// Format: fromPort(2) + toPort(2) + payload
        /// </summary>
        private static byte[] CreateRawDatagramWithPorts(byte[] payload, ushort fromPort, ushort toPort)
        {
            var result = new byte[4 + payload.Length];
            result[0] = (byte)(fromPort >> 8);
            result[1] = (byte)(fromPort & 0xFF);
            result[2] = (byte)(toPort >> 8);
            result[3] = (byte)(toPort & 0xFF);
            Array.Copy(payload, 0, result, 4, payload.Length);
            return result;
        }

        /// <summary>
        /// Clean up expired sessions (sessions with no activity for 5 minutes).
        /// </summary>
        public void CleanupExpiredSessions()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            const long EXPIRY = 300000; // 5 minutes

            var expired = _sessions
                .Where(kv => now - Math.Max(kv.Value.LastSendTime, kv.Value.LastReceiveTime) > EXPIRY)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in expired)
                _sessions.TryRemove(key, out _);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _sessions.Clear();
            _portHandlers.Clear();
        }
    }
}
