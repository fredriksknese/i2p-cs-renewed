using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using I2PCore.Utils;

namespace I2PTests.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Automatically downloads and compiles i2pd from source for integration tests.
    /// Caches the built binary so subsequent test runs don't rebuild.
    /// </summary>
    public static class I2pdBuilder
    {
        private const string I2pdRepo = "https://github.com/PurpleI2P/i2pd.git";
        private const string I2pdBranch = "openssl";

        // Cache directory: ~/.cache/i2p-cs-tests/i2pd
        private static readonly string CacheDir = Path.Combine(
            Environment.GetFolderPath( Environment.SpecialFolder.UserProfile ),
            ".cache", "i2p-cs-tests", "i2pd" );

        private static readonly string SourceDir = Path.Combine( CacheDir, "src" );
        private static readonly string BuildDir = Path.Combine( CacheDir, "build" );
        private static readonly string BinaryPath = Path.Combine( BuildDir, "i2pd" );

        private static readonly object BuildLock = new();

        /// <summary>
        /// Get the path to the i2pd binary, building from source if needed.
        /// Returns null if build fails.
        /// </summary>
        public static string GetOrBuild()
        {
            // Check cached build
            if ( File.Exists( BinaryPath ) )
            {
                Logging.LogInformation( $"Using cached i2pd build: {BinaryPath}" );
                return BinaryPath;
            }

            // Build from source
            lock ( BuildLock )
            {
                // Double-check after acquiring lock
                if ( File.Exists( BinaryPath ) )
                    return BinaryPath;

                try
                {
                    BuildFromSource();
                    return File.Exists( BinaryPath ) ? BinaryPath : null;
                }
                catch ( Exception ex )
                {
                    Logging.LogWarning( $"Failed to build i2pd: {ex.Message}" );
                    return null;
                }
            }
        }

        private static void BuildFromSource()
        {
            Directory.CreateDirectory( CacheDir );
            Directory.CreateDirectory( BuildDir );

            // Clone or update
            if ( !Directory.Exists( Path.Combine( SourceDir, ".git" ) ) )
            {
                Logging.LogInformation( $"Cloning i2pd from {I2pdRepo}..." );
                RunCommand( "git", $"clone --depth 1 --branch {I2pdBranch} {I2pdRepo} \"{SourceDir}\"",
                    CacheDir, timeoutMs: 300000 );
            }
            else
            {
                Logging.LogInformation( "Updating i2pd source..." );
                RunCommand( "git", "pull --ff-only", SourceDir, timeoutMs: 60000 );
            }

            // Build with cmake
            Logging.LogInformation( "Building i2pd with cmake..." );

            RunCommand( "cmake",
                $"-S \"{SourceDir}/build\" -B \"{BuildDir}\" " +
                "-DWITH_UPNP=OFF -DWITH_MESHNET=OFF -DCMAKE_BUILD_TYPE=Release",
                BuildDir, timeoutMs: 60000 );

            var cpuCount = Environment.ProcessorCount;
            RunCommand( "cmake",
                $"--build \"{BuildDir}\" --parallel {cpuCount}",
                BuildDir, timeoutMs: 600000 );

            if ( !File.Exists( BinaryPath ) )
            {
                // cmake may put it in a subdirectory
                var altPath = Path.Combine( BuildDir, "i2pd" );
                if ( !File.Exists( altPath ) )
                {
                    // Search for it
                    foreach ( var f in Directory.EnumerateFiles( BuildDir, "i2pd", SearchOption.AllDirectories ) )
                    {
                        if ( !f.EndsWith( ".o" ) && !f.EndsWith( ".d" ) )
                        {
                            File.Copy( f, BinaryPath, true );
                            break;
                        }
                    }
                }
            }

            if ( File.Exists( BinaryPath ) )
            {
                // Make executable
                RunCommand( "chmod", $"+x \"{BinaryPath}\"", BuildDir, timeoutMs: 5000 );
                Logging.LogInformation( $"i2pd built successfully: {BinaryPath}" );
            }
            else
            {
                throw new FileNotFoundException( "i2pd binary not found after build" );
            }
        }

        private static void RunCommand( string cmd, string args, string workDir, int timeoutMs )
        {
            Logging.LogInformation( $"  $ {cmd} {args}" );

            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = cmd,
                    Arguments = args,
                    WorkingDirectory = workDir,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            proc.Start();
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();

            if ( !proc.WaitForExit( timeoutMs ) )
            {
                proc.Kill();
                throw new TimeoutException( $"Command timed out after {timeoutMs}ms: {cmd} {args}" );
            }

            if ( proc.ExitCode != 0 )
            {
                throw new InvalidOperationException(
                    $"Command failed (exit {proc.ExitCode}): {cmd} {args}\n" +
                    $"stdout: {stdout}\nstderr: {stderr}" );
            }
        }

        /// <summary>
        /// Clean the cached build (forces rebuild on next run).
        /// </summary>
        public static void Clean()
        {
            if ( Directory.Exists( BuildDir ) )
                Directory.Delete( BuildDir, true );
        }
    }
}
