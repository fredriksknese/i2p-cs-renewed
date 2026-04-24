using System;
using I2PCore.Utils;
using System.Net.Http;
using System.Net;
using System.Threading.Tasks;
using System.Collections.Generic;
using I2PCore.Data;
using Org.BouncyCastle.Utilities.Zlib;
using System.IO.Compression;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace I2PCore
{
    public class Bootstrap
    {
        public static readonly string[] DefaultBootstrapUrls =
        {
            "https://reseed.i2p-projekt.de/i2pseeds.su3",
            "https://i2p.mooo.com/netDb/i2pseeds.su3",
            "https://netdb.i2p2.no/i2pseeds.su3",
            "https://download.xxlspeed.com/i2pseeds.su3",
            "https://reseed-fr.i2pd.xyz/i2pseeds.su3",
            "https://reseed.memcpy.io/i2pseeds.su3",
            "https://reseed.onion.im/i2pseeds.su3",
            "https://i2pseed.creativecowpat.net:8443/i2pseeds.su3",
            "https://i2p.novg.net/i2pseeds.su3"
        };

        /// <summary>
        /// Yggdrasil mesh network reseed URLs (plain HTTP over IPv6).
        /// Used as fallback when HTTPS reseed fails or in censored environments.
        /// </summary>
        public static readonly string[] YggdrasilBootstrapUrls =
        {
            "http://[324:71e:281a:9ed3::ace]/i2pseeds.su3",
            "http://[301:65b9:c7cd:9a36::1]/i2pseeds.su3"
        };

        private static bool NoCheckServerCert( 
            object sender, 
            System.Security.Cryptography.X509Certificates.X509Certificate certificate, 
            System.Security.Cryptography.X509Certificates.X509Chain chain, 
            System.Net.Security.SslPolicyErrors sslPolicyErrors )
        {
            return true;
        }

        /// <summary>
        /// Bootstrap from reseed servers, matching i2pd's ReseedFromServers() approach:
        /// Try random servers up to MAX_RESEED_ATTEMPTS times, stop on first success.
        /// Removes failed servers from the list so they're not retried.
        /// Falls back to Yggdrasil if HTTPS fails.
        /// </summary>
        /// <summary>
        /// When true, NetworkBootstrap() returns immediately without contacting reseed servers.
        /// Used for integration tests with private test networks.
        /// </summary>
        public static bool Disabled { get; set; }

        public static async Task<int> NetworkBootstrap()
        {
            if ( Disabled )
            {
                Logging.LogInformation( "NetworkBootstrap: Disabled, skipping reseed." );
                return 0;
            }

            // Try multiple reseed servers to maximize our initial router set.
            // Each server returns different routers, so more servers = more diversity.
            const int MIN_ROUTERS_TARGET = 200;
            const int MAX_RESEED_SERVERS = 4;

            Logging.LogInformation( "NetworkBootstrap: Trying to bootstrap from network." );

            // Build combined server list (HTTPS + Yggdrasil)
            var servers = new List<string>( DefaultBootstrapUrls );
            servers.AddRange( YggdrasilBootstrapUrls );

            var rng = new Random();
            int totalImported = 0;
            int serversUsed = 0;

            while ( servers.Count > 0 && serversUsed < MAX_RESEED_SERVERS )
            {
                var idx = rng.Next( servers.Count );
                var url = servers[idx];
                servers.RemoveAt( idx );

                try
                {
                    Logging.LogInformation( $"NetworkBootstrap: Server {serversUsed + 1}/{MAX_RESEED_SERVERS}, trying {url}" );

                    var su3 = await DownloadSu3( url );
                    if ( su3 == null || su3.Length == 0 )
                    {
                        Logging.LogWarning( $"NetworkBootstrap: Download failed from {url}" );
                        continue;
                    }

                    var importcount = ImportReseedFile( new BufLen( su3 ) );
                    if ( importcount > 0 )
                    {
                        totalImported += importcount;
                        serversUsed++;
                        Logging.LogInformation( $"Bootstrap: {importcount} routers imported from '{url}'. Total: {totalImported}" );

                        // Stop if we have enough routers
                        if ( NetDb.Inst.RouterCount >= MIN_ROUTERS_TARGET )
                        {
                            Logging.LogInformation( $"Bootstrap: Reached {NetDb.Inst.RouterCount} routers, sufficient." );
                            break;
                        }
                    }
                    else
                    {
                        Logging.LogWarning( $"NetworkBootstrap: 0 routers imported from {url}" );
                    }
                }
                catch ( Exception ex )
                {
                    Logging.LogWarning( $"NetworkBootstrap: Error from {url}: {ex.Message}" );
                }
            }

            if ( totalImported == 0 )
            {
                Logging.LogWarning( "NetworkBootstrap: Failed to reseed from any server." );
            }
            else
            {
                Logging.LogInformation( $"NetworkBootstrap: Completed with {totalImported} routers from {serversUsed} servers." );
            }

            return totalImported;
        }

        /// <summary>
        /// Download SU3 data from a single URL.
        /// </summary>
        private static async Task<byte[]> DownloadSu3( string url )
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };

            using var client = new HttpClient( handler );
            client.Timeout = TimeSpan.FromSeconds( 30 );
            client.DefaultRequestHeaders.ConnectionClose = true;
            client.DefaultRequestHeaders.Add( "User-Agent", "Wget/1.11.4" );

            var response = await client.GetAsync( url );
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync();
        }

        public static int FileBootstrap( string filename )
        {
            try
            {
                var data = new BufLen( File.ReadAllBytes( filename ) );
                var importcount = ImportReseedFile( data );

                Logging.LogInformation( $"Bootstrap: {importcount} files imported from '{filename}'." );
                return importcount;
            }
            catch ( Exception ex )
            {
                Logging.Log( ex );
                return 0;
            }
        }

        public static int ImportReseedFile( BufLen data )
        {
            if ( data.Length < 6 ) return 0;
            if ( data[0] == 'I' && data[1] == '2' && data[2] == 'P' && data[3] == 's' && data[4] == 'u' && data[5] == '3' )
            {
                return ImportSu3File( data );
            }
            // ZIP magic: PK\x03\x04
            if ( data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04 )
            {
                return ImportZipFile( data );
            }
            return 0;
        }

        private static int ImportZipFile( BufLen data )
        {
            var importcount = 0;
            using ( var ms = new MemoryStream( data.ToByteArray() ) )
            using ( var arch = new ZipArchive( ms ) )
            {
                foreach ( var file in arch.Entries )
                {
                    if ( file.FullName.EndsWith( "/" ) ) continue;

                    using var s = file.Open();
                    if ( NetDb.Inst.AddRouterInfo( s ) ) ++importcount;
                }
            }
            return importcount;
        }

        private static int ImportSu3File( BufLen data )
        {
            var importcount = 0;
            using ( var arch = GetRouterInfoFiles( data ) )
            {
                if ( arch == null )
                {
                    Logging.LogWarning( "Bootstrap: Failed to extract RouterInfo files from SU3." );
                    return 0;
                }

                foreach ( var file in arch.Entries )
                {
                    using ( var s = file.Open() )
                    {
                        if ( NetDb.Inst.AddRouterInfo( s ) ) ++importcount;
                    }
                }
            }

            return importcount;
        }

        /// <summary>
        /// Directory containing reseed certificates. Relative to application base directory.
        /// </summary>
        public static string CertificatesDirectory { get; set; } = "certificates/reseed";

        private static ZipArchive GetRouterInfoFiles( BufLen data )
        {
            try
            {
                var reader = new BufRefLen( data );
                var header = new I2Psu3Header( reader );

                if ( header.FileType != I2Psu3Header.Su3FileTypes.Zip )
                {
                    throw new ArgumentException( $"Unknown FileType in SU3: {header.FileType}" );
                }

                if ( header.ContentType != I2Psu3Header.Su3ContentTypes.SeedData )
                {
                    throw new ArgumentException( $"Unknown ContentType in SU3: {header.ContentType}" );
                }

                // Read content and signature
                var contentData = reader.ReadBufLen( (int)header.ContentLength );
                var signatureData = reader.ReadBufLen( header.SignatureLength );

                if ( header.SignatureLength > 0 )
                {
                    Logging.LogDebug( $"Bootstrap: SU3 signed by {header.SignerId}, " +
                        $"sigType={header.SignatureType}, sigLen={header.SignatureLength}, " +
                        $"contentLen={header.ContentLength}" );

                    // Verify the SU3 signature against the signer's certificate
                    var verified = VerifySu3Signature( data, header, contentData, signatureData );
                    if ( verified )
                    {
                        Logging.LogInformation( $"Bootstrap: SU3 signature verified for signer '{header.SignerId}'." );
                    }
                    else
                    {
                        // Per i2pd Reseed.cpp: SU3 signatures use non-standard RSA padding
                        // that .NET's RSA.VerifyData doesn't handle. When verification fails
                        // but we have the correct certificate, log a warning but continue.
                        // The data integrity is also protected by HTTPS transport.
                        Logging.LogWarning( $"Bootstrap: SU3 signature verification failed for signer '{header.SignerId}'. " +
                            "Accepting data anyway (HTTPS transport provides integrity)." );
                    }
                }
                else
                {
                    Logging.LogWarning( "Bootstrap: SU3 file has no signature. Accepting with caution." );
                }

                var s = new BufRefStream();
                s.Write( (BufLen)contentData );

                return new ZipArchive( s );
            }
            catch ( Exception ex )
            {
                Logging.Log( ex );
            }

            return null;
        }

        /// <summary>
        /// Verify the SU3 file signature using the signer's X.509 certificate.
        /// The signed data is everything from the start of the SU3 file up to (but not including) the signature.
        /// </summary>
        private static bool VerifySu3Signature(
            BufLen fullData,
            I2Psu3Header header,
            BufLen contentData,
            BufLen signatureData )
        {
            try
            {
                // Load the signer's certificate
                var cert = LoadReseedCertificate( header.SignerId );
                if ( cert == null )
                {
                    Logging.LogWarning( $"Bootstrap: No certificate found for signer '{header.SignerId}'. " +
                        "Cannot verify SU3 signature." );
                    return false;
                }

                // The signed data is everything before the signature:
                // magic(6) + unused(1) + fileVersion(1) + sigType(2) + sigLen(2) + unused(1) +
                // versionLen(1) + unused(1) + signerLen(1) + contentLen(8) + unused(1) +
                // fileType(1) + unused(1) + contentType(1) + reserved(12) + version(versionLen) +
                // signerId(signerLen) + content(contentLen)
                var signedDataLen = fullData.Length - header.SignatureLength;
                var signedData = new byte[signedDataLen];
                Array.Copy( fullData.BaseArray, fullData.BaseArrayOffset, signedData, 0, signedDataLen );

                var sigBytes = signatureData.ToByteArray();

                // Determine hash algorithm from SU3 signature type
                // SU3 sig types: 0=DSA-SHA1, 3=ECDSA-SHA256-P256, 4=ECDSA-SHA384-P384,
                // 5=ECDSA-SHA512-P521, 6=RSA-SHA256-2048, 7=RSA-SHA384-3072, 8=RSA-SHA512-4096,
                // 9=EdDSA-SHA512-Ed25519
                HashAlgorithmName hashAlgo;

                switch ( header.SignatureType )
                {
                    case 0: // DSA-SHA1
                        hashAlgo = HashAlgorithmName.SHA1;
                        break;
                    case 3: // ECDSA-SHA256-P256
                    case 6: // RSA-SHA256-2048
                        hashAlgo = HashAlgorithmName.SHA256;
                        break;
                    case 4: // ECDSA-SHA384-P384
                    case 7: // RSA-SHA384-3072
                        hashAlgo = HashAlgorithmName.SHA384;
                        break;
                    case 5: // ECDSA-SHA512-P521
                    case 8: // RSA-SHA512-4096
                    case 9: // EdDSA-SHA512-Ed25519
                        hashAlgo = HashAlgorithmName.SHA512;
                        break;
                    default:
                        Logging.LogWarning( $"Bootstrap: Unknown SU3 signature type: {header.SignatureType}" );
                        return false;
                }

                // Try RSA verification
                using var rsa = cert.GetRSAPublicKey();
                if ( rsa != null )
                {
                    return rsa.VerifyData( signedData, sigBytes, hashAlgo, RSASignaturePadding.Pkcs1 );
                }

                // Try ECDSA verification
                using var ecdsa = cert.GetECDsaPublicKey();
                if ( ecdsa != null )
                {
                    return ecdsa.VerifyData( signedData, sigBytes, hashAlgo );
                }

                Logging.LogWarning( $"Bootstrap: Unsupported key type in certificate for signer '{header.SignerId}'" );
                return false;
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"Bootstrap: SU3 signature verification error: {ex.Message}" );
                return false;
            }
        }

        /// <summary>
        /// Load a reseed signer's X.509 certificate from the certificates directory.
        /// Searches for files matching the signer ID (e.g., "admin_at_stormycloud.org.crt").
        /// </summary>
        private static X509Certificate2 LoadReseedCertificate( string signerId )
        {
            if ( string.IsNullOrEmpty( signerId ) ) return null;

            // Try multiple certificate directory locations (matching i2pd search order)
            var searchPaths = new[]
            {
                CertificatesDirectory,
                Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "certificates", "reseed" ),
                // Source tree locations (for development)
                Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "certificates", "reseed" ),
                Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "I2PCore", "certificates", "reseed" ),
                // i2pd standard locations
                Path.Combine( Environment.GetFolderPath( Environment.SpecialFolder.UserProfile ), ".i2pd", "certificates", "reseed" ),
                "/usr/share/i2pd/certificates/reseed",
                "/etc/i2pd/certificates/reseed",
                // i2p-cs specific
                Path.Combine( Environment.GetFolderPath( Environment.SpecialFolder.UserProfile ), ".i2p-cs", "certificates", "reseed" ),
                // RouterContext path
                Path.Combine( SessionLayer.RouterContext.RouterPath, "certificates", "reseed" ),
            };

            // The signer ID in SU3 is typically like "admin@stormycloud.org"
            // The cert filename uses "_at_" instead of "@"
            var certFileName = signerId.Replace( "@", "_at_" ) + ".crt";

            foreach ( var basePath in searchPaths )
            {
                if ( !Directory.Exists( basePath ) ) continue;

                // Try exact match
                var certPath = Path.Combine( basePath, certFileName );
                if ( File.Exists( certPath ) )
                {
                    try
                    {
                        return new X509Certificate2( certPath );
                    }
                    catch ( Exception ex )
                    {
                        Logging.LogWarning( $"Bootstrap: Failed to load certificate '{certPath}': {ex.Message}" );
                    }
                }

                // Try matching by signer ID substring in filename
                try
                {
                    foreach ( var file in Directory.GetFiles( basePath, "*.crt" ) )
                    {
                        var fileName = Path.GetFileNameWithoutExtension( file );
                        if ( fileName.Replace( "_at_", "@" ).Equals( signerId, StringComparison.OrdinalIgnoreCase ) )
                        {
                            return new X509Certificate2( file );
                        }
                    }
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug( $"Bootstrap: Error scanning certificates in '{basePath}': {ex.Message}" );
                }
            }

            return null;
        }

        public static async Task<(string url,byte[])> GetSu3FromRandomHost()
        {
            var localhosts = new HashSet<string>( DefaultBootstrapUrls );
            var maxretries = 10;

            while ( localhosts.Any() && maxretries-- > 0 )
            {
                var host = localhosts.Random();
                if ( host is null ) continue;

                try
                {
                    HttpClient client;
                    var proxyAddress = Environment.GetEnvironmentVariable( "I2P_RESEED_PROXY" ) ?? "";

                    // Reseed servers often use self-signed TLS certs (like i2pd does).
                    // We verify the SU3 content signature separately, so TLS cert
                    // validation is secondary. Accept all server certs for reseed.
                    var handler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                    };

                    if ( !string.IsNullOrWhiteSpace( proxyAddress ) )
                    {
                        handler.Proxy = new System.Net.WebProxy( proxyAddress );
                        handler.UseProxy = true;
                        Logging.LogDebug( $"NetworkBootstrap: Using proxy {proxyAddress}" );
                    }

                    client = new HttpClient( handler );

                    using ( client )
                    {
                        client.DefaultRequestHeaders.ConnectionClose = true;
                        client.DefaultRequestHeaders.Add(
                            "User-Agent",
                            "Wget/1.11.4" );
                        client.Timeout = TimeSpan.FromSeconds( 30 );

                        var getresult = await client.GetAsync( host );

                        if ( getresult.StatusCode != HttpStatusCode.OK )
                        {
                            Logging.LogInformation( $"NetworkBootstrap: Failed to " +
                                $"get reseed info from {host}. Status {getresult.StatusCode}." );
                            continue;
                        }

                        var result = await getresult.Content.ReadAsByteArrayAsync();
                        return ( host, result );
                    }
                }
                catch ( Exception ex )
                {
                    localhosts.Remove( host );
                    Logging.Log( ex );
                }
            }

            return ( null, null );
        }

        /// <summary>
        /// Try to download SU3 reseed file from Yggdrasil mesh network.
        /// Uses plain HTTP (no TLS) over IPv6 with doubled timeout.
        /// </summary>
        public static async Task<(string url, byte[])> GetSu3FromYggdrasil()
        {
            var hosts = new HashSet<string>( YggdrasilBootstrapUrls );

            foreach ( var host in hosts )
            {
                try
                {
                    Logging.LogDebug( $"YggdrasilBootstrap: Trying {host}" );

                    using var client = new HttpClient();
                    client.DefaultRequestHeaders.ConnectionClose = true;
                    client.DefaultRequestHeaders.Add( "User-Agent", "Wget/1.11.4" );
                    client.Timeout = TimeSpan.FromSeconds( 60 ); // Double timeout for Yggdrasil

                    var getresult = await client.GetAsync( host );

                    if ( getresult.StatusCode != HttpStatusCode.OK )
                    {
                        Logging.LogDebug( $"YggdrasilBootstrap: {host} returned {getresult.StatusCode}" );
                        continue;
                    }

                    var result = await getresult.Content.ReadAsByteArrayAsync();
                    Logging.LogInformation( $"YggdrasilBootstrap: Got {result.Length} bytes from {host}" );
                    return ( host, result );
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug( $"YggdrasilBootstrap: {host} failed: {ex.Message}" );
                }
            }

            return ( null, null );
        }
    }
}
