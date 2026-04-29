using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.Streaming;

/// <summary>
///     Manages all streams for a destination on a given port.
///     Handles incoming stream acceptance and outgoing stream creation.
///     Corresponds to StreamingDestination in i2pd.
/// </summary>
public class StreamingDestination : IDisposable
{
    public const int MAX_PENDING_INCOMING = 1024;

    private readonly I2PDestination _localDestination;
    private readonly byte[] _localIdentityBytes;

    // Pending incoming streams waiting to be accepted
    private readonly ConcurrentQueue<I2PStream> _pendingIncoming = new();
    private readonly SemaphoreSlim _pendingSignal = new(0);
    private readonly I2PSigningPrivateKey _signingPrivateKey;

    // All active streams indexed by our RecvStreamId
    private readonly ConcurrentDictionary<uint, I2PStream> _streams = new();

    // Callback for sending data via garlic/tunnels
    private Action<I2PDestination, byte[]> _sendCallback;

    // Callback for LeaseSet lookups
    private Action<I2PDestination> _lookupCallback;

    public StreamingDestination(
        I2PDestination localDestination,
        I2PSigningPrivateKey signingPrivateKey,
        byte[] localIdentityBytes)
    {
        _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));
        _signingPrivateKey = signingPrivateKey;
        _localIdentityBytes = localIdentityBytes;
    }

    public int ActiveStreamCount => _streams.Count;

    public void Dispose()
    {
        foreach (var kvp in _streams) kvp.Value.Terminate();
        _streams.Clear();
        _pendingSignal.Dispose();
    }

    /// <summary>
    ///     Set the callback for sending streaming data to remote destinations.
    ///     The callback receives (remoteDestination, streamingPacketBytes).
    /// </summary>
    public void SetSendCallback(Action<I2PDestination, byte[]> sendCallback)
    {
        _sendCallback = sendCallback;
    }

    /// <summary>
    ///     Set the callback for triggering LeaseSet lookups.
    /// </summary>
    public void SetLookupCallback(Action<I2PDestination> lookupCallback)
    {
        _lookupCallback = lookupCallback;
    }

    /// <summary>
    ///     Create a new outgoing stream to a remote destination
    /// </summary>
    public I2PStream CreateStream(I2PDestination remoteDestination)
    {
        if (_sendCallback == null)
            throw new InvalidOperationException("Send callback not set");

        var remote = remoteDestination;
        var stream = new I2PStream(
            _localDestination,
            remoteDestination,
            _localIdentityBytes,
            data => _sendCallback(remote, data),
            _signingPrivateKey);

        stream.LeaseSetLookupRequired += (s, d) => _lookupCallback?.Invoke(d);
        _streams[stream.RecvStreamId] = stream;
        stream.StreamClosed += OnStreamClosed;

        return stream;
    }

    /// <summary>
    ///     Accept an incoming stream (blocking)
    /// </summary>
    public I2PStream AcceptStream(int timeoutMs = -1)
    {
        if (_pendingSignal.Wait(timeoutMs))
            if (_pendingIncoming.TryDequeue(out var stream))
                return stream;
        return null;
    }

    /// <summary>
    ///     Accept an incoming stream (async)
    /// </summary>
    public async Task<I2PStream> AcceptStreamAsync(CancellationToken ct = default)
    {
        await _pendingSignal.WaitAsync(ct);
        if (_pendingIncoming.TryDequeue(out var stream))
            return stream;
        return null;
    }

    /// <summary>
    ///     Handle received streaming data from the tunnel/garlic layer.
    ///     Called when a streaming protocol message is received for this destination.
    /// </summary>
    public void HandleDataMessagePayload(byte[] payload, I2PDestination sender = null)
    {
        if (payload == null || payload.Length < 22)
            return;

        try
        {
            var packet = StreamingPacket.Parse(payload);

            // Find existing stream by ReceiveStreamId (which maps to our RecvStreamId)
            if (_streams.TryGetValue(packet.ReceiveStreamId, out var stream))
            {
                stream.HandleNextPacket(packet);
                return;
            }

            Logging.LogDebug(
                $"StreamingDestination: No stream found for ReceiveStreamId {packet.ReceiveStreamId:X8}. IsSYN: {packet.IsSYN}, Seq: {packet.SequenceNumber}");

            // New incoming SYN?
            if (packet.IsSYN && packet.SequenceNumber == 0)
            {
                if (_pendingIncoming.Count >= MAX_PENDING_INCOMING)
                {
                    Logging.LogWarning("StreamingDestination: Too many pending incoming streams");
                    return;
                }

                var remote = sender;
                Logging.LogDebug(
                    $"StreamingDestination: Creating incoming stream for SYN from " +
                    $"{remote?.IdentHash?.Id32Short ?? "?"}, SendStreamId={packet.SendStreamId:X8}, " +
                    $"payload={packet.Payload.Length} bytes, flags={packet.Flags:X4}");

                var incomingStream = new I2PStream(
                    _localDestination,
                    _localIdentityBytes,
                    packet,
                    data =>
                    {
                        if (remote != null)
                        {
                            try
                            {
                                _sendCallback?.Invoke(remote, data);
                            }
                            catch (Exception ex)
                            {
                                Logging.LogWarning(
                                    $"StreamingDestination: Send callback failed: {ex.GetType().Name}: {ex.Message}");
                            }
                        }
                        else
                        {
                            Logging.LogWarning("StreamingDestination: Cannot send — remote destination is null");
                        }
                    },
                    _signingPrivateKey);

                incomingStream.LeaseSetLookupRequired += (s, d) => _lookupCallback?.Invoke(d);
                _streams[incomingStream.RecvStreamId] = incomingStream;
                incomingStream.StreamClosed += OnStreamClosed;

                _pendingIncoming.Enqueue(incomingStream);
                _pendingSignal.Release();

                Logging.LogDebug(
                    $"StreamingDestination: New incoming stream {incomingStream.RecvStreamId:X8}, " +
                    $"status={incomingStream.Status}, remoteIdentity={incomingStream.RemoteDestination?.IdentHash?.Id32Short ?? "null"}");
                return;
            }

            // Unknown stream - possibly a late packet for a closed stream
            Logging.LogDebug($"StreamingDestination: Packet for unknown stream {packet.ReceiveStreamId:X8}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning(
                $"StreamingDestination: Error processing packet ({payload?.Length ?? 0} bytes): " +
                $"{ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
        }
    }

    /// <summary>
    ///     Remove a stream by its RecvStreamId
    /// </summary>
    public void DeleteStream(uint recvStreamId)
    {
        if (_streams.TryRemove(recvStreamId, out var stream))
        {
            stream.StreamClosed -= OnStreamClosed;
            stream.Terminate();
        }
    }

    private void OnStreamClosed(I2PStream stream)
    {
        _streams.TryRemove(stream.RecvStreamId, out _);
    }
}