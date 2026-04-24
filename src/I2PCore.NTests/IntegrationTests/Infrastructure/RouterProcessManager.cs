using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Utils;

namespace I2PTests.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Manages i2pd router processes for integration testing.
    /// Handles starting, readiness detection, and cleanup.
    /// </summary>
    public class RouterProcessManager : IDisposable
    {
        private Process _i2pdProcess;
        private readonly StringBuilder _i2pdStdout = new();
        private readonly StringBuilder _i2pdStderr = new();
        private bool _disposed;

        /// <summary>
        /// Search for i2pd on the system (PATH, common locations, env var).
        /// Does NOT trigger a build from source.
        /// </summary>
        public static string FindI2pdOnSystem()
        {
            // Check environment variable first
            var envPath = Environment.GetEnvironmentVariable( "I2PD_PATH" );
            if ( !string.IsNullOrEmpty( envPath ) && File.Exists( envPath ) )
                return envPath;

            // Check common locations
            var candidates = new[]
            {
                "i2pd",  // On PATH
                "/usr/bin/i2pd",
                "/usr/local/bin/i2pd",
                "/usr/sbin/i2pd",
                Path.Combine( Environment.GetFolderPath( Environment.SpecialFolder.UserProfile ), "i2pd", "i2pd" ),
                "/snap/i2pd/current/usr/bin/i2pd",
            };

            foreach ( var candidate in candidates )
            {
                try
                {
                    var proc = Process.Start( new ProcessStartInfo
                    {
                        FileName = candidate,
                        Arguments = "--version",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    } );

                    if ( proc != null )
                    {
                        proc.WaitForExit( 5000 );
                        if ( proc.ExitCode == 0 || proc.StandardOutput.ReadToEnd().Contains( "i2pd" ) )
                        {
                            return candidate;
                        }
                    }
                }
                catch
                {
                    // Not found at this location, try next
                }
            }

            return null;
        }

        /// <summary>
        /// Find i2pd binary: checks system first, then builds from source if needed.
        /// </summary>
        public static string FindI2pdBinary()
        {
            return I2pdBuilder.GetOrBuild();
        }

        /// <summary>
        /// Kill any process listening on the given TCP port (Linux only).
        /// Used to clean up stale i2pd instances from previous test runs.
        /// </summary>
        private static void KillProcessOnPort( int port )
        {
            // Log what holds the port before killing
            try
            {
                var lsof = Process.Start( new ProcessStartInfo
                {
                    FileName = "lsof",
                    Arguments = $"-t -i TCP:{port}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                } );
                if ( lsof != null )
                {
                    var pids = lsof.StandardOutput.ReadToEnd().Trim();
                    lsof.WaitForExit( 2000 );
                    if ( !string.IsNullOrEmpty( pids ) )
                        Logging.LogWarning( $"Port {port} held by PID(s): {pids}" );
                }
            }
            catch { }

            try
            {
                var proc = Process.Start( new ProcessStartInfo
                {
                    FileName = "fuser",
                    Arguments = $"-k {port}/tcp",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                } );
                proc?.WaitForExit( 3000 );
            }
            catch
            {
                // fuser may not be available; best-effort only
            }
        }

        /// <summary>
        /// Kill any stale i2pd test processes holding the given TCP ports.
        /// Called before starting a new i2pd to avoid "Address already in use" from
        /// a previous test run that didn't clean up.
        /// </summary>
        public static void KillStaleProcessesOnPorts( params int[] ports )
        {
            foreach ( var port in ports )
            {
                Logging.LogInformation( $"Releasing TCP port {port} from stale processes (if any)..." );
                KillProcessOnPort( port );
            }

            // Wait until each port is actually free (not just a fixed sleep)
            var deadline = DateTime.UtcNow.AddSeconds( 8 );
            foreach ( var port in ports )
            {
                while ( DateTime.UtcNow < deadline && IsPortListening( port ) )
                    Thread.Sleep( 150 );

                if ( IsPortListening( port ) )
                    Logging.LogWarning( $"Port {port} still in use after {8}s wait; proceeding anyway" );
                else
                    Logging.LogInformation( $"Port {port} is now free." );
            }
        }

        /// <summary>
        /// Wait for a specific port to become reachable (listening).
        /// Used to verify that secondary services (SAM, I2CP) are up after NTCP2 is ready.
        /// </summary>
        public static async Task WaitForPortListening( int port, int timeoutMs = 30000 )
        {
            var sw = Stopwatch.StartNew();
            while ( sw.ElapsedMilliseconds < timeoutMs )
            {
                if ( IsPortListening( port ) )
                {
                    Logging.LogInformation( $"Port {port} is listening after {sw.ElapsedMilliseconds}ms" );
                    return;
                }
                await Task.Delay( 500 );
            }
            throw new TimeoutException( $"Port {port} did not start listening within {timeoutMs}ms" );
        }

        /// <summary>
        /// Start i2pd with the given config file.
        /// </summary>
        public async Task<Process> StartI2pd( string configFile, string dataDir )
        {
            var binary = FindI2pdBinary();
            if ( binary == null )
                throw new FileNotFoundException(
                    "i2pd binary not found. Install i2pd or set I2PD_PATH environment variable." );

            var args = $"--conf={configFile} --datadir={dataDir}";

            Logging.LogInformation( $"Starting i2pd: {binary} {args}" );

            _i2pdProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = binary,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = dataDir
                },
                EnableRaisingEvents = true
            };

            _i2pdProcess.OutputDataReceived += ( s, e ) =>
            {
                if ( e.Data != null )
                {
                    _i2pdStdout.AppendLine( e.Data );
                    Logging.LogDebug( $"[i2pd stdout] {e.Data}" );
                }
            };

            _i2pdProcess.ErrorDataReceived += ( s, e ) =>
            {
                if ( e.Data != null )
                {
                    _i2pdStderr.AppendLine( e.Data );
                    Logging.LogDebug( $"[i2pd stderr] {e.Data}" );
                }
            };

            _i2pdProcess.Exited += ( s, e ) =>
            {
                try
                {
                    var exitCode = _i2pdProcess.ExitCode;
                    Logging.LogWarning( $"i2pd process exited with code {exitCode}" );
                    if ( exitCode != 0 )
                    {
                        Logging.LogWarning( $"i2pd failure [stdout]:\n{_i2pdStdout}" );
                        Logging.LogWarning( $"i2pd failure [stderr]:\n{_i2pdStderr}" );
                    }
                }
                catch { }
            };

            if ( !_i2pdProcess.Start() )
                throw new InvalidOperationException( "Failed to start i2pd process" );

            _i2pdProcess.BeginOutputReadLine();
            _i2pdProcess.BeginErrorReadLine();

            Logging.LogInformation( $"i2pd started with PID {_i2pdProcess.Id}" );
            return _i2pdProcess;
        }

        /// <summary>
        /// Wait for i2pd to be ready by checking if its NTCP2 port is listening.
        /// </summary>
        public async Task WaitForReady( int ntcp2Port, int timeoutMs = 60000 )
        {
            var sw = Stopwatch.StartNew();
            while ( sw.ElapsedMilliseconds < timeoutMs )
            {
                if ( _i2pdProcess?.HasExited == true )
                    throw new InvalidOperationException(
                        $"i2pd exited prematurely with code {_i2pdProcess.ExitCode}.\n" +
                        $"stdout: {_i2pdStdout}\nstderr: {_i2pdStderr}" );

                if ( IsPortListening( ntcp2Port ) )
                {
                    Logging.LogInformation(
                        $"i2pd is ready (port {ntcp2Port} listening) after {sw.ElapsedMilliseconds}ms" );
                    return;
                }

                await Task.Delay( 500 );
            }

            throw new TimeoutException(
                $"i2pd did not become ready within {timeoutMs}ms.\n" +
                $"stdout: {_i2pdStdout}\nstderr: {_i2pdStderr}" );
        }

        /// <summary>
        /// Get i2pd's RouterInfo file path from its netDb directory.
        /// i2pd stores its own RouterInfo as router.info in the data directory.
        /// </summary>
        public string GetI2pdRouterInfoPath( string dataDir )
        {
            var riPath = Path.Combine( dataDir, "router.info" );
            if ( File.Exists( riPath ) )
                return riPath;

            // Fallback: search netDb directory
            var netDbDir = Path.Combine( dataDir, "netDb" );
            if ( Directory.Exists( netDbDir ) )
            {
                foreach ( var file in Directory.EnumerateFiles( netDbDir, "routerInfo-*.dat", SearchOption.AllDirectories ) )
                    return file;
            }

            return null;
        }

        /// <summary>
        /// Stop i2pd gracefully, then force-kill if needed.
        /// </summary>
        public void StopI2pd()
        {
            if ( _i2pdProcess == null || _i2pdProcess.HasExited )
                return;

            try
            {
                Logging.LogInformation( "Stopping i2pd..." );

                // Send SIGTERM on Linux
                _i2pdProcess.Kill( entireProcessTree: false );

                if ( !_i2pdProcess.WaitForExit( 10000 ) )
                {
                    Logging.LogWarning( "i2pd did not exit gracefully, force killing" );
                    _i2pdProcess.Kill( entireProcessTree: true );
                    _i2pdProcess.WaitForExit( 5000 );
                }

                Logging.LogInformation( $"i2pd stopped with exit code {_i2pdProcess.ExitCode}" );
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"Error stopping i2pd: {ex.Message}" );
            }
        }

        /// <summary>
        /// Get captured stdout from i2pd (useful for diagnostics on failure).
        /// </summary>
        public string GetStdout() => _i2pdStdout.ToString();

        /// <summary>
        /// Get captured stderr from i2pd.
        /// </summary>
        public string GetStderr() => _i2pdStderr.ToString();

        private static bool IsPortListening( int port )
        {
            try
            {
                using var client = new TcpClient();
                var result = client.BeginConnect( "127.0.0.1", port, null, null );
                var success = result.AsyncWaitHandle.WaitOne( TimeSpan.FromMilliseconds( 200 ) );
                if ( success )
                {
                    client.EndConnect( result );
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            if ( _disposed ) return;
            _disposed = true;
            StopI2pd();
            _i2pdProcess?.Dispose();
        }
    }
}
