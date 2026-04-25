using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using I2PCore.SessionLayer;
using I2PCore.Utils;

namespace I2PCore.Client;

/// <summary>
///     Abstract base class for I2P client services (tunnels, proxies, etc.).
///     Provides shared destination management, connection tracking, readiness checks,
///     and graceful shutdown.
///     Port of i2pd's I2PService base class.
/// </summary>
public abstract class I2PService : IDisposable
{
    /// <summary>
    ///     Callback invoked when the service destination is ready.
    /// </summary>
    public delegate void ReadyCallback(bool success);

    private readonly ConcurrentDictionary<int, IDisposable> _handlers = new();
    private readonly List<(ReadyCallback Callback, long Deadline)> _readyCallbacks = new();
    private readonly object _readyLock = new();
    private bool _disposed;
    private int _nextHandlerId;

    /// <summary>
    ///     The local I2P destination used by this service.
    /// </summary>
    public ClientDestination LocalDestination { get; protected set; }

    /// <summary>
    ///     Connection timeout in seconds. Default 30.
    /// </summary>
    public int ConnectTimeoutSeconds { get; set; } = 30;

    /// <summary>
    ///     Time in milliseconds after which idle connections are closed. 0 = disabled.
    /// </summary>
    public long CloseIdleTimeMs { get; set; }

    /// <summary>
    ///     Whether to create a new destination when the service is resumed.
    /// </summary>
    public bool NewDestinationOnResume { get; set; }

    /// <summary>
    ///     Whether the service is currently running.
    /// </summary>
    public bool IsRunning { get; protected set; }

    /// <summary>
    ///     Number of active connections/handlers.
    /// </summary>
    public int ActiveConnectionCount => _handlers.Count;

    public virtual void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        ClearHandlers();
        NotifyReady(false);
    }

    /// <summary>
    ///     Start the service. Subclasses must implement this.
    /// </summary>
    public abstract void Start();

    /// <summary>
    ///     Stop the service. Subclasses must implement this.
    /// </summary>
    public abstract void Stop();

    /// <summary>
    ///     Register an active connection handler.
    ///     Returns a handler ID that can be used to remove it later.
    /// </summary>
    protected int AddHandler(IDisposable handler)
    {
        var id = Interlocked.Increment(ref _nextHandlerId);
        _handlers[id] = handler;
        return id;
    }

    /// <summary>
    ///     Remove and dispose a connection handler.
    /// </summary>
    protected void RemoveHandler(int handlerId)
    {
        if (_handlers.TryRemove(handlerId, out var handler))
            try
            {
                handler?.Dispose();
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PService: Error disposing handler: {ex.Message}");
            }
    }

    /// <summary>
    ///     Remove all handlers and dispose them.
    /// </summary>
    protected void ClearHandlers()
    {
        foreach (var kv in _handlers)
            try
            {
                kv.Value?.Dispose();
            }
            catch
            {
            }

        _handlers.Clear();
    }

    /// <summary>
    ///     Add a callback to be invoked when the destination is ready.
    ///     If the destination is already ready, the callback is invoked immediately.
    /// </summary>
    public void AddReadyCallback(ReadyCallback callback, int timeoutMs = 30000)
    {
        if (callback == null) return;

        // Check if already ready
        if (LocalDestination != null)
        {
            callback(true);
            return;
        }

        lock (_readyLock)
        {
            var deadline = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + timeoutMs;
            _readyCallbacks.Add((callback, deadline));
        }
    }

    /// <summary>
    ///     Notify all waiting ready callbacks that the destination is available.
    ///     Call this from subclasses after the destination is initialized.
    /// </summary>
    protected void NotifyReady(bool success)
    {
        lock (_readyLock)
        {
            foreach (var (cb, _) in _readyCallbacks)
                try
                {
                    cb(success);
                }
                catch
                {
                }

            _readyCallbacks.Clear();
        }
    }

    /// <summary>
    ///     Expire timed-out ready callbacks.
    ///     Call periodically from subclasses.
    /// </summary>
    protected void ExpireReadyCallbacks()
    {
        lock (_readyLock)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var expired = _readyCallbacks.FindAll(r => now >= r.Deadline);
            foreach (var (cb, _) in expired)
                try
                {
                    cb(false);
                }
                catch
                {
                }

            _readyCallbacks.RemoveAll(r => now >= r.Deadline);
        }
    }
}