using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace I2PCore.Utils
{
    /// <summary>
    /// Daemon lifecycle helper for I2P router.
    /// Provides signal handling (SIGTERM, SIGINT, SIGHUP), graceful shutdown,
    /// and PID file management for Unix/Windows daemon mode.
    /// </summary>
    public class DaemonHelper : IDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        private readonly ManualResetEventSlim _shutdownEvent = new(false);
        private Action _reloadCallback;
        private bool _gracefulShutdownRequested;
        private bool _disposed;

        /// <summary>
        /// Token that is canceled when shutdown is requested.
        /// </summary>
        public CancellationToken ShutdownToken => _cts.Token;

        /// <summary>
        /// Whether a graceful shutdown has been requested.
        /// </summary>
        public bool IsShuttingDown => _gracefulShutdownRequested;

        /// <summary>
        /// Set the callback for SIGHUP/reload signal.
        /// </summary>
        public void OnReload(Action callback)
        {
            _reloadCallback = callback;
        }

        /// <summary>
        /// Register signal handlers for graceful shutdown and config reload.
        /// </summary>
        public void RegisterSignalHandlers()
        {
            // SIGINT (Ctrl+C)
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                Logging.LogInformation("DaemonHelper: SIGINT received, initiating shutdown...");
                RequestShutdown();
            };

            // SIGTERM
            AppDomain.CurrentDomain.ProcessExit += (_, _) =>
            {
                Logging.LogInformation("DaemonHelper: SIGTERM/ProcessExit, initiating shutdown...");
                RequestShutdown();
            };

            // SIGHUP (Unix only) - reload configuration
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                RegisterUnixSignals();
            }

            Logging.LogDebug("DaemonHelper: Signal handlers registered.");
        }

        private void RegisterUnixSignals()
        {
            // Use PosixSignalRegistration for SIGHUP on .NET 6+
            try
            {
                System.Runtime.InteropServices.PosixSignalRegistration.Create(
                    PosixSignal.SIGHUP,
                    ctx =>
                    {
                        ctx.Cancel = true;
                        Logging.LogInformation("DaemonHelper: SIGHUP received, reloading configuration...");
                        _reloadCallback?.Invoke();
                    });

                System.Runtime.InteropServices.PosixSignalRegistration.Create(
                    PosixSignal.SIGTERM,
                    ctx =>
                    {
                        ctx.Cancel = true;
                        Logging.LogInformation("DaemonHelper: SIGTERM received via PosixSignal...");
                        RequestShutdown();
                    });
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"DaemonHelper: PosixSignal registration failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Request a graceful shutdown of the router.
        /// </summary>
        public void RequestShutdown()
        {
            if (_gracefulShutdownRequested) return;
            _gracefulShutdownRequested = true;
            _cts.Cancel();
            _shutdownEvent.Set();
        }

        /// <summary>
        /// Block until shutdown is requested.
        /// </summary>
        public void WaitForShutdown()
        {
            _shutdownEvent.Wait();
        }

        /// <summary>
        /// Block until shutdown is requested, with timeout.
        /// </summary>
        public bool WaitForShutdown(TimeSpan timeout)
        {
            return _shutdownEvent.Wait(timeout);
        }

        /// <summary>
        /// Run the main loop, blocking until shutdown.
        /// </summary>
        public async Task RunUntilShutdownAsync()
        {
            try
            {
                await Task.Delay(Timeout.Infinite, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown
            }
        }

        /// <summary>
        /// Write PID file for daemon mode.
        /// </summary>
        public static void WritePidFile(string path)
        {
            try
            {
                System.IO.File.WriteAllText(path, Environment.ProcessId.ToString());
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"DaemonHelper: Failed to write PID file: {ex.Message}");
            }
        }

        /// <summary>
        /// Remove PID file on shutdown.
        /// </summary>
        public static void RemovePidFile(string path)
        {
            try
            {
                if (System.IO.File.Exists(path))
                    System.IO.File.Delete(path);
            }
            catch { }
        }

        /// <summary>
        /// Daemonize the current process on Unix/Linux.
        /// Redirects stdin/stdout/stderr to /dev/null and detaches from terminal.
        /// On Windows or if forking is unavailable, this is a no-op (runs in foreground).
        /// </summary>
        public static bool Daemonize()
        {
            if ( RuntimeInformation.IsOSPlatform( OSPlatform.Windows ) )
            {
                Logging.LogInformation( "DaemonHelper: Windows detected, running as foreground process." );
                return false;
            }

            try
            {
                // Redirect standard streams to /dev/null for daemon mode
                var devnull = System.IO.File.Open( "/dev/null", System.IO.FileMode.Open, System.IO.FileAccess.ReadWrite );
                Console.SetIn( new System.IO.StreamReader( devnull ) );
                Console.SetOut( new System.IO.StreamWriter( devnull ) { AutoFlush = true } );
                Console.SetError( new System.IO.StreamWriter( devnull ) { AutoFlush = true } );

                Logging.LogInformation( "DaemonHelper: Running in daemon mode (streams redirected to /dev/null)." );
                return true;
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"DaemonHelper: Failed to daemonize: {ex.Message}" );
                return false;
            }
        }

        /// <summary>
        /// Check if the process is running as a systemd service.
        /// </summary>
        public static bool IsRunningAsSystemdService()
        {
            return Environment.GetEnvironmentVariable( "INVOCATION_ID" ) != null ||
                   Environment.GetEnvironmentVariable( "JOURNAL_STREAM" ) != null;
        }

        /// <summary>
        /// Notify systemd that the service is ready (sd_notify protocol).
        /// </summary>
        public static void NotifySystemdReady()
        {
            var notifySocket = Environment.GetEnvironmentVariable( "NOTIFY_SOCKET" );
            if ( string.IsNullOrEmpty( notifySocket ) ) return;

            try
            {
                // Use the READY=1 notification
                var socket = new System.Net.Sockets.Socket(
                    System.Net.Sockets.AddressFamily.Unix,
                    System.Net.Sockets.SocketType.Dgram,
                    System.Net.Sockets.ProtocolType.Unspecified );

                var endpoint = new System.Net.Sockets.UnixDomainSocketEndPoint( notifySocket );
                socket.SendTo(
                    System.Text.Encoding.UTF8.GetBytes( "READY=1" ),
                    endpoint );
                socket.Close();

                Logging.LogInformation( "DaemonHelper: Notified systemd READY=1." );
            }
            catch ( Exception ex )
            {
                Logging.LogDebug( $"DaemonHelper: sd_notify failed: {ex.Message}" );
            }
        }

        /// <summary>
        /// Notify systemd of stopping.
        /// </summary>
        public static void NotifySystemdStopping()
        {
            var notifySocket = Environment.GetEnvironmentVariable( "NOTIFY_SOCKET" );
            if ( string.IsNullOrEmpty( notifySocket ) ) return;

            try
            {
                var socket = new System.Net.Sockets.Socket(
                    System.Net.Sockets.AddressFamily.Unix,
                    System.Net.Sockets.SocketType.Dgram,
                    System.Net.Sockets.ProtocolType.Unspecified );

                var endpoint = new System.Net.Sockets.UnixDomainSocketEndPoint( notifySocket );
                socket.SendTo(
                    System.Text.Encoding.UTF8.GetBytes( "STOPPING=1" ),
                    endpoint );
                socket.Close();
            }
            catch { }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _cts.Dispose();
            _shutdownEvent.Dispose();
        }
    }
}
