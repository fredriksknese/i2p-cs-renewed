using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using I2PCore;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PTests.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Handles RouterInfo exchange between the C# router and i2pd
    /// for the private test network. Exports/imports RouterInfo files
    /// to enable direct peer discovery without reseed.
    /// </summary>
    public static class RouterInfoExchanger
    {
        /// <summary>
        /// Export a RouterInfo to a .dat file suitable for i2pd's netDb directory.
        /// Format: routerInfo-{base64hash}.dat
        /// </summary>
        public static string ExportRouterInfo( I2PRouterInfo ri, string outputDir )
        {
            Directory.CreateDirectory( outputDir );

            // I2P standard filename: base64 of 32-byte hash with + → - and / → ~
            // Must use standard Base64 then substitute (NOT BouncyCastle UrlBase64 which uses _ not ~)
            // i2pd KEEPS the '=' padding in filenames (e.g. routerInfo-XXX=.dat), so do NOT strip it.
            var hashBytes = ri.Identity.IdentHash.Hash.ToByteArray();
            var hashStr = Convert.ToBase64String( hashBytes );
            var safeHash = hashStr.Replace( '+', '-' ).Replace( '/', '~' );

            // i2pd expects files in subdirectories like r{first-char}/
            var subDir = Path.Combine( outputDir, $"r{safeHash[0]}" );
            Directory.CreateDirectory( subDir );

            var filename = $"routerInfo-{safeHash}.dat";
            var filepath = Path.Combine( subDir, filename );

            // Serialize the RouterInfo
            var brs = new BufRefStream();
            ri.Write( brs );
            File.WriteAllBytes( filepath, brs.ToByteArray() );

            Logging.LogInformation(
                $"Exported RouterInfo {ri.Identity.IdentHash.Id32Short:x8} to {filepath}" );

            return filepath;
        }

        /// <summary>
        /// Export RouterInfo directly to a flat file (for simpler exchange).
        /// </summary>
        public static string ExportRouterInfoFlat( I2PRouterInfo ri, string filepath )
        {
            var dir = Path.GetDirectoryName( filepath );
            if ( !string.IsNullOrEmpty( dir ) )
                Directory.CreateDirectory( dir );

            var brs = new BufRefStream();
            ri.Write( brs );
            File.WriteAllBytes( filepath, brs.ToByteArray() );

            Logging.LogInformation(
                $"Exported RouterInfo {ri.Identity.IdentHash.Id32Short:x8} to {filepath}" );

            return filepath;
        }

        /// <summary>
        /// Import a RouterInfo from a .dat file (i2pd format).
        /// </summary>
        public static I2PRouterInfo ImportRouterInfo( string filepath )
        {
            if ( !File.Exists( filepath ) )
                throw new FileNotFoundException( $"RouterInfo file not found: {filepath}" );

            var data = File.ReadAllBytes( filepath );
            var reader = new BufRefLen( data );
            var ri = new I2PRouterInfo( reader, false );

            Logging.LogInformation(
                $"Imported RouterInfo {ri.Identity.IdentHash.Id32Short:x8} from {filepath}" );

            return ri;
        }

        /// <summary>
        /// Wait for i2pd to generate its RouterInfo file, then import it.
        /// i2pd writes router.info to its data directory on startup.
        /// </summary>
        public static async Task<I2PRouterInfo> WaitAndImportI2pdRouterInfo(
            string i2pdDataDir, int timeoutMs = 30000 )
        {
            var riPath = Path.Combine( i2pdDataDir, "router.info" );
            var sw = System.Diagnostics.Stopwatch.StartNew();

            while ( sw.ElapsedMilliseconds < timeoutMs )
            {
                if ( File.Exists( riPath ) )
                {
                    try
                    {
                        // Wait a moment for the file to be fully written
                        await Task.Delay( 500 );
                        return ImportRouterInfo( riPath );
                    }
                    catch ( Exception ex )
                    {
                        Logging.LogDebug( $"RouterInfo not ready yet: {ex.Message}" );
                    }
                }

                // Also check netDb subdirectories
                var netDbDir = Path.Combine( i2pdDataDir, "netDb" );
                if ( Directory.Exists( netDbDir ) )
                {
                    var files = Directory.EnumerateFiles( netDbDir, "routerInfo-*.dat",
                        SearchOption.AllDirectories ).ToArray();
                    if ( files.Length > 0 )
                    {
                        try
                        {
                            await Task.Delay( 200 );
                            return ImportRouterInfo( files[0] );
                        }
                        catch
                        {
                            // Try again
                        }
                    }
                }

                await Task.Delay( 1000 );
            }

            throw new TimeoutException(
                $"i2pd RouterInfo not found in {i2pdDataDir} within {timeoutMs}ms" );
        }

        /// <summary>
        /// Place our RouterInfo into i2pd's netDb so it discovers us on startup.
        /// Must be called before i2pd starts, or i2pd must rescan its netDb.
        /// </summary>
        public static void PlaceRouterInfoForI2pd( I2PRouterInfo ri, string i2pdDataDir )
        {
            var netDbDir = Path.Combine( i2pdDataDir, "netDb" );
            ExportRouterInfo( ri, netDbDir );
        }
    }
}
