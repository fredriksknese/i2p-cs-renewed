using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace I2PCore;

// Batch 1-1 (docs/PRODUCTION-PLAN.md): reseed TLS certificate validation.
//
// Both reseed download paths used to install
// `ServerCertificateCustomValidationCallback = (_,_,_,_) => true`, disabling TLS
// validation unconditionally, justified by a comment saying the SU3 content
// signature is verified separately. It is not: GetRouterInfoFiles() accepted
// archives whose signature check failed. Reseed is the router's entire initial
// view of the network, so an unauthenticated bootstrap lets a network attacker
// choose every peer we will ever talk to.
//
// Default is now ordinary TLS validation against the system trust store, with
// `--insecure-reseed` (Bootstrap.InsecureReseed) restoring the old behaviour for
// operators who need it, loudly. Measured 2026-08-07 against the 9 default
// hosts: 3 served a valid chain, 1 (i2pseed.creativecowpat.net:8443) is
// genuinely self-signed and now fails, the rest were unreachable from here.
// Since NetworkBootstrap() walks a shuffled list and stops at the first success,
// losing the self-signed host does not break cold start. Per-host certificate
// pinning would recover it and belongs with the SU3 work in batch 1-2.
//
// Batch 1-2: SU3 signature verification is fail-closed. Two defects made the old
// path unable to verify anything, which is why it was left accepting archives
// whose signature check had failed:
//
//   1. The SigType table was shifted. Type 6 is RSA_SHA512_4096, not
//      RSA-SHA256-2048 as the table claimed, so the only type that occurs in
//      the wild was hashed with the wrong algorithm.
//   2. I2P's RSA convention omits the DigestInfo ASN.1 prefix from the PKCS#1
//      v1.5 block, so RSA.VerifyData(..., Pkcs1) rejects every valid signature.
//      See VerifyI2PRsaSignature.
//
// A failed or missing signature now rejects the archive and NetworkBootstrap()
// moves to the next host. --insecure-reseed downgrades that to a warning.
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
    ///     Yggdrasil mesh network reseed URLs (plain HTTP over IPv6).
    ///     Used as fallback when HTTPS reseed fails or in censored environments.
    /// </summary>
    public static readonly string[] YggdrasilBootstrapUrls =
    {
        "http://[324:71e:281a:9ed3::ace]/i2pseeds.su3",
        "http://[301:65b9:c7cd:9a36::1]/i2pseeds.su3"
    };

    /// <summary>
    ///     Bootstrap from reseed servers, matching i2pd's ReseedFromServers() approach:
    ///     Try random servers up to MAX_RESEED_ATTEMPTS times, stop on first success.
    ///     Removes failed servers from the list so they're not retried.
    ///     Falls back to Yggdrasil if HTTPS fails.
    /// </summary>
    /// <summary>
    ///     When true, NetworkBootstrap() returns immediately without contacting reseed servers.
    ///     Used for integration tests with private test networks.
    /// </summary>
    public static bool Disabled { get; set; }

    /// <summary>
    ///     Directory containing reseed certificates. Relative to application base directory.
    /// </summary>
    public static string CertificatesDirectory { get; set; } = "certificates/reseed";

    /// <summary>
    ///     When true, reseed HTTPS connections accept any server certificate.
    ///     Off by default; set by the CLI's <c>--insecure-reseed</c>. Enabling it
    ///     means a network attacker can supply this router's entire initial view
    ///     of the network, so it logs at Critical every time it is turned on.
    /// </summary>
    public static bool InsecureReseed
    {
        get => _insecureReseed;
        set
        {
            _insecureReseed = value;

            if (value)
                Logging.LogCritical(
                    "Bootstrap: INSECURE RESEED ENABLED. TLS server certificates will not be " +
                    "validated. Anyone able to intercept the reseed connection can choose every " +
                    "router this instance learns about. Do not use this on an untrusted network.");
        }
    }

    private static bool _insecureReseed;

    /// <summary>
    ///     Build the HTTP handler used for reseed downloads. Validates the server
    ///     certificate against the system trust store unless <see cref="InsecureReseed" />
    ///     is set.
    /// </summary>
    internal static HttpClientHandler CreateReseedHandler()
    {
        var handler = new HttpClientHandler();

        if (InsecureReseed)
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        return handler;
    }

    public static async Task<int> NetworkBootstrap()
    {
        if (Disabled)
        {
            Logging.LogInformation("NetworkBootstrap: Disabled, skipping reseed.");
            return 0;
        }

        // Try multiple reseed servers to maximize our initial router set.
        // Each server returns different routers, so more servers = more diversity.
        const int MIN_ROUTERS_TARGET = 200;
        const int MAX_RESEED_SERVERS = 4;

        Logging.LogInformation("NetworkBootstrap: Trying to bootstrap from network.");

        // Build combined server list (HTTPS + Yggdrasil)
        var servers = new List<string>(DefaultBootstrapUrls);
        servers.AddRange(YggdrasilBootstrapUrls);

        var rng = new Random();
        var totalImported = 0;
        var serversUsed = 0;

        while (servers.Count > 0 && serversUsed < MAX_RESEED_SERVERS)
        {
            var idx = rng.Next(servers.Count);
            var url = servers[idx];
            servers.RemoveAt(idx);

            try
            {
                Logging.LogInformation(
                    $"NetworkBootstrap: Server {serversUsed + 1}/{MAX_RESEED_SERVERS}, trying {url}");

                var su3 = await DownloadSu3(url);
                if (su3 == null || su3.Length == 0)
                {
                    Logging.LogWarning($"NetworkBootstrap: Download failed from {url}");
                    continue;
                }

                var importcount = ImportReseedFile(new I2PByteBlock(su3));
                if (importcount > 0)
                {
                    totalImported += importcount;
                    serversUsed++;
                    Logging.LogInformation(
                        $"Bootstrap: {importcount} routers imported from '{url}'. Total: {totalImported}");

                    // Stop if we have enough routers
                    if (NetDb.Inst.RouterCount >= MIN_ROUTERS_TARGET)
                    {
                        Logging.LogInformation($"Bootstrap: Reached {NetDb.Inst.RouterCount} routers, sufficient.");
                        break;
                    }
                }
                else
                {
                    Logging.LogWarning($"NetworkBootstrap: 0 routers imported from {url}");
                }
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"NetworkBootstrap: Error from {url}: {ex.Message}");
            }
        }

        if (totalImported == 0)
            Logging.LogWarning("NetworkBootstrap: Failed to reseed from any server.");
        else
            Logging.LogInformation(
                $"NetworkBootstrap: Completed with {totalImported} routers from {serversUsed} servers.");

        return totalImported;
    }

    /// <summary>
    ///     Download SU3 data from a single URL.
    /// </summary>
    private static async Task<byte[]> DownloadSu3(string url)
    {
        using var client = new HttpClient(CreateReseedHandler());
        client.Timeout = TimeSpan.FromSeconds(30);
        client.DefaultRequestHeaders.ConnectionClose = true;
        client.DefaultRequestHeaders.Add("User-Agent", "Wget/1.11.4");

        var response = await client.GetAsync(url);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync();
    }

    public static int FileBootstrap(string filename)
    {
        try
        {
            var data = new I2PByteBlock(File.ReadAllBytes(filename));
            var importcount = ImportReseedFile(data);

            Logging.LogInformation($"Bootstrap: {importcount} files imported from '{filename}'.");
            return importcount;
        }
        catch (Exception ex)
        {
            Logging.Log(ex);
            return 0;
        }
    }

    public static int ImportReseedFile(I2PByteBlock data)
    {
        if (data.Length < 6) return 0;
        if (data[0] == 'I' && data[1] == '2' && data[2] == 'P' && data[3] == 's' && data[4] == 'u' && data[5] == '3')
            return ImportSu3File(data);
        // ZIP magic: PK\x03\x04
        if (data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04) return ImportZipFile(data);
        return 0;
    }

    private static int ImportZipFile(I2PByteBlock data)
    {
        var importcount = 0;
        using (var ms = new MemoryStream(data.ToByteArray()))
        using (var arch = new ZipArchive(ms))
        {
            foreach (var file in arch.Entries)
            {
                if (file.FullName.EndsWith("/")) continue;

                using var s = file.Open();
                if (NetDb.Inst.AddRouterInfo(s)) ++importcount;
            }
        }

        return importcount;
    }

    private static int ImportSu3File(I2PByteBlock data)
    {
        var importcount = 0;
        using (var arch = GetRouterInfoFiles(data))
        {
            if (arch == null)
            {
                Logging.LogWarning("Bootstrap: Failed to extract RouterInfo files from SU3.");
                return 0;
            }

            foreach (var file in arch.Entries)
                using (var s = file.Open())
                {
                    if (NetDb.Inst.AddRouterInfo(s)) ++importcount;
                }
        }

        return importcount;
    }

    /// <summary>
    ///     Returns the content archive, or null if the SU3 is unverifiable. Internal so tests can
    ///     assert the fail-closed path without importing fixture routers into the global NetDb.
    /// </summary>
    internal static ZipArchive GetRouterInfoFiles(I2PByteBlock data)
    {
        try
        {
            var reader = new I2PBufferCursor(data);
            var start = reader.Position;
            var header = new I2Psu3Header(reader);

            if (header.FileType != I2Psu3Header.Su3FileTypes.Zip)
                throw new ArgumentException($"Unknown FileType in SU3: {header.FileType}");

            if (header.ContentType != I2Psu3Header.Su3ContentTypes.SeedData)
                throw new ArgumentException($"Unknown ContentType in SU3: {header.ContentType}");

            var contentData = reader.ReadBlock((int)header.ContentLength);

            // Everything from the magic number through the end of the content is signed.
            // Derived from the cursor rather than (fileLength - signatureLength) so trailing
            // bytes after the signature cannot shift what we hash.
            var signedData = reader.BlockSince(start);
            var signatureData = reader.ReadBlock(header.SignatureLength);

            if (header.SignatureLength == 0)
            {
                if (!InsecureReseed)
                {
                    Logging.LogWarning(
                        "Bootstrap: rejecting unsigned SU3 file. An unsigned reseed archive can be " +
                        "supplied by anyone. Use --insecure-reseed to accept it anyway.");
                    return null;
                }

                Logging.LogWarning("Bootstrap: SU3 file has no signature, accepted (--insecure-reseed).");
                return new ZipArchive(new MemoryStream(contentData.ToByteArray()));
            }

            Logging.LogDebug($"Bootstrap: SU3 signed by {header.SignerId}, " +
                             $"sigType={header.SignatureType}, sigLen={header.SignatureLength}, " +
                             $"contentLen={header.ContentLength}");

            if (VerifySu3Signature(header, signedData, signatureData))
            {
                Logging.LogInformation($"Bootstrap: SU3 signature verified for signer '{header.SignerId}'.");
                return new ZipArchive(new MemoryStream(contentData.ToByteArray()));
            }

            if (!InsecureReseed)
            {
                Logging.LogWarning(
                    $"Bootstrap: rejecting SU3 archive from signer '{header.SignerId}' — signature " +
                    "verification failed. Trying the next reseed host.");
                return null;
            }

            Logging.LogWarning(
                $"Bootstrap: SU3 signature verification failed for signer '{header.SignerId}', " +
                "accepted anyway (--insecure-reseed). This router's view of the network is untrusted.");

            return new ZipArchive(new MemoryStream(contentData.ToByteArray()));
        }
        catch (Exception ex)
        {
            Logging.Log(ex);
        }

        return null;
    }

    /// <summary>
    ///     I2P SigType values as they appear in an SU3 header, with the hash each one signs over
    ///     and the exact signature length it must carry.
    /// </summary>
    /// <remarks>
    ///     The previous table was shifted: it read type 6 as RSA-SHA256-2048, so the one type that
    ///     actually occurs in the wild was hashed with SHA-256 instead of SHA-512 and could never
    ///     have verified. Measured 2026-08-07: every reachable reseed host signs with type 6, and
    ///     all 14 certificates in certificates/reseed/ are RSA-4096.
    /// </remarks>
    private static readonly Dictionary<ushort, (string Name, HashAlgorithmName Hash, int SigLen)> Su3SigTypes = new()
    {
        [0] = ( "DSA_SHA1", HashAlgorithmName.SHA1, 40 ),
        [1] = ( "ECDSA_SHA256_P256", HashAlgorithmName.SHA256, 64 ),
        [2] = ( "ECDSA_SHA384_P384", HashAlgorithmName.SHA384, 96 ),
        [3] = ( "ECDSA_SHA512_P521", HashAlgorithmName.SHA512, 132 ),
        [4] = ( "RSA_SHA256_2048", HashAlgorithmName.SHA256, 256 ),
        [5] = ( "RSA_SHA384_3072", HashAlgorithmName.SHA384, 384 ),
        [6] = ( "RSA_SHA512_4096", HashAlgorithmName.SHA512, 512 ),
        [7] = ( "EdDSA_SHA512_Ed25519", HashAlgorithmName.SHA512, 64 )
    };

    /// <summary>
    ///     Verify an SU3 signature against the signer's pinned reseed certificate.
    ///     Returns false — never throws — for any unverifiable archive.
    /// </summary>
    internal static bool VerifySu3Signature(
        I2Psu3Header header,
        I2PByteBlock signedData,
        I2PByteBlock signatureData)
    {
        try
        {
            if (!Su3SigTypes.TryGetValue(header.SignatureType, out var sigType))
            {
                Logging.LogWarning($"Bootstrap: unknown SU3 signature type {header.SignatureType}.");
                return false;
            }

            if (header.SignatureLength != sigType.SigLen)
            {
                Logging.LogWarning(
                    $"Bootstrap: SU3 signature length {header.SignatureLength} does not match " +
                    $"{sigType.Name} (expected {sigType.SigLen}).");
                return false;
            }

            var cert = LoadReseedCertificate(header.SignerId);
            if (cert == null)
            {
                Logging.LogWarning($"Bootstrap: no pinned certificate for signer '{header.SignerId}'. " +
                                   "Cannot verify SU3 signature.");
                return false;
            }

            using (cert)
            {
                var signed = signedData.ToByteArray();
                var signature = signatureData.ToByteArray();

                using var rsa = cert.GetRSAPublicKey();
                if (rsa != null) return VerifyI2PRsaSignature(rsa, signed, signature, sigType.Hash);

                // Not reached by any current reseed signer; kept because the SigType table allows it.
                // .NET's ECDsa.VerifyData takes the raw r||s form that I2P uses.
                using var ecdsa = cert.GetECDsaPublicKey();
                if (ecdsa != null) return ecdsa.VerifyData(signed, signature, sigType.Hash);

                Logging.LogWarning(
                    $"Bootstrap: certificate for '{header.SignerId}' holds an unsupported key type " +
                    $"for {sigType.Name}.");
                return false;
            }
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Bootstrap: SU3 signature verification error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    ///     I2P signs SU3 files with a raw RSA operation over a PKCS#1 v1.5 padded block that omits
    ///     the DigestInfo ASN.1 prefix:
    ///     <code>0x00 0x01 0xFF... 0x00 || H(signedData)</code>
    ///     .NET's <c>RSA.VerifyData(..., RSASignaturePadding.Pkcs1)</c> requires the DigestInfo and
    ///     therefore rejects every valid I2P signature — which is why this used to "fail" and get
    ///     waved through. i2pd's RSAVerifier does the same modular exponentiation and compares the
    ///     trailing hash bytes; we additionally check the padding is well formed.
    /// </summary>
    private static bool VerifyI2PRsaSignature(
        RSA rsa,
        byte[] signedData,
        byte[] signature,
        HashAlgorithmName hashAlgo)
    {
        var parameters = rsa.ExportParameters(false);
        var modulusLen = parameters.Modulus.Length;

        if (signature.Length != modulusLen)
        {
            Logging.LogWarning(
                $"Bootstrap: SU3 signature is {signature.Length} bytes but the signer's modulus " +
                $"is {modulusLen}.");
            return false;
        }

        var engine = new RsaEngine();
        engine.Init(false, new RsaKeyParameters(
            false,
            new BigInteger(1, parameters.Modulus),
            new BigInteger(1, parameters.Exponent)));

        // BouncyCastle returns the integer's minimal big-endian encoding, so a block that happens
        // to start with a zero byte comes back short. Right-align it into a full-width buffer.
        var produced = engine.ProcessBlock(signature, 0, signature.Length);
        if (produced.Length > modulusLen) return false;

        var block = new byte[modulusLen];
        Array.Copy(produced, 0, block, modulusLen - produced.Length, produced.Length);

        var expected = HashData(signedData, hashAlgo);

        // 0x00 0x01, at least 8 bytes of 0xFF, 0x00, then the bare hash.
        var padEnd = modulusLen - expected.Length - 1;
        if (padEnd < 10) return false;
        if (block[0] != 0x00 || block[1] != 0x01) return false;
        if (block[padEnd] != 0x00) return false;

        for (var i = 2; i < padEnd; i++)
            if (block[i] != 0xFF)
                return false;

        return CryptographicOperations.FixedTimeEquals(
            new ReadOnlySpan<byte>(block, padEnd + 1, expected.Length),
            expected);
    }

    private static byte[] HashData(byte[] data, HashAlgorithmName algo)
    {
        if (algo == HashAlgorithmName.SHA512) return SHA512.HashData(data);
        if (algo == HashAlgorithmName.SHA384) return SHA384.HashData(data);
        if (algo == HashAlgorithmName.SHA256) return SHA256.HashData(data);
        if (algo == HashAlgorithmName.SHA1) return SHA1.HashData(data);

        throw new NotSupportedException($"Unsupported SU3 hash algorithm {algo.Name}");
    }

    /// <summary>
    ///     Load a reseed signer's X.509 certificate from the certificates directory.
    ///     Searches for files matching the signer ID (e.g., "admin_at_stormycloud.org.crt").
    /// </summary>
    private static X509Certificate2 LoadReseedCertificate(string signerId)
    {
        if (string.IsNullOrEmpty(signerId)) return null;

        // Try multiple certificate directory locations (matching i2pd search order)
        var searchPaths = new[]
        {
            CertificatesDirectory,
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates", "reseed"),
            // Source tree locations (for development)
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "certificates", "reseed"),
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "I2PCore", "certificates",
                "reseed"),
            // i2pd standard locations
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".i2pd", "certificates",
                "reseed"),
            "/usr/share/i2pd/certificates/reseed",
            "/etc/i2pd/certificates/reseed",
            // i2p-cs specific
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".i2p-cs", "certificates",
                "reseed"),
            // RouterContext path
            Path.Combine(RouterContext.RouterPath, "certificates", "reseed")
        };

        // The signer ID in SU3 is typically like "admin@stormycloud.org"
        // The cert filename uses "_at_" instead of "@"
        var certFileName = signerId.Replace("@", "_at_") + ".crt";

        foreach (var basePath in searchPaths)
        {
            if (!Directory.Exists(basePath)) continue;

            // Try exact match
            var certPath = Path.Combine(basePath, certFileName);
            if (File.Exists(certPath))
                try
                {
                    return new X509Certificate2(certPath);
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"Bootstrap: Failed to load certificate '{certPath}': {ex.Message}");
                }

            // Try matching by signer ID substring in filename
            try
            {
                foreach (var file in Directory.GetFiles(basePath, "*.crt"))
                {
                    var fileName = Path.GetFileNameWithoutExtension(file);
                    if (fileName.Replace("_at_", "@").Equals(signerId, StringComparison.OrdinalIgnoreCase))
                        return new X509Certificate2(file);
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"Bootstrap: Error scanning certificates in '{basePath}': {ex.Message}");
            }
        }

        return null;
    }

    public static async Task<(string url, byte[])> GetSu3FromRandomHost()
    {
        var localhosts = new HashSet<string>(DefaultBootstrapUrls);
        var maxretries = 10;

        while (localhosts.Any() && maxretries-- > 0)
        {
            var host = localhosts.Random();
            if (host is null) continue;

            try
            {
                HttpClient client;
                var proxyAddress = Environment.GetEnvironmentVariable("I2P_RESEED_PROXY") ?? "";

                var handler = CreateReseedHandler();

                if (!string.IsNullOrWhiteSpace(proxyAddress))
                {
                    handler.Proxy = new WebProxy(proxyAddress);
                    handler.UseProxy = true;
                    Logging.LogDebug($"NetworkBootstrap: Using proxy {proxyAddress}");
                }

                client = new HttpClient(handler);

                using (client)
                {
                    client.DefaultRequestHeaders.ConnectionClose = true;
                    client.DefaultRequestHeaders.Add(
                        "User-Agent",
                        "Wget/1.11.4");
                    client.Timeout = TimeSpan.FromSeconds(30);

                    var getresult = await client.GetAsync(host);

                    if (getresult.StatusCode != HttpStatusCode.OK)
                    {
                        Logging.LogInformation($"NetworkBootstrap: Failed to " +
                                               $"get reseed info from {host}. Status {getresult.StatusCode}.");
                        continue;
                    }

                    var result = await getresult.Content.ReadAsByteArrayAsync();
                    return (host, result);
                }
            }
            catch (Exception ex)
            {
                localhosts.Remove(host);
                Logging.Log(ex);
            }
        }

        return (null, null);
    }

    /// <summary>
    ///     Try to download SU3 reseed file from Yggdrasil mesh network.
    ///     Uses plain HTTP (no TLS) over IPv6 with doubled timeout.
    /// </summary>
    public static async Task<(string url, byte[])> GetSu3FromYggdrasil()
    {
        var hosts = new HashSet<string>(YggdrasilBootstrapUrls);

        foreach (var host in hosts)
            try
            {
                Logging.LogDebug($"YggdrasilBootstrap: Trying {host}");

                using var client = new HttpClient();
                client.DefaultRequestHeaders.ConnectionClose = true;
                client.DefaultRequestHeaders.Add("User-Agent", "Wget/1.11.4");
                client.Timeout = TimeSpan.FromSeconds(60); // Double timeout for Yggdrasil

                var getresult = await client.GetAsync(host);

                if (getresult.StatusCode != HttpStatusCode.OK)
                {
                    Logging.LogDebug($"YggdrasilBootstrap: {host} returned {getresult.StatusCode}");
                    continue;
                }

                var result = await getresult.Content.ReadAsByteArrayAsync();
                Logging.LogInformation($"YggdrasilBootstrap: Got {result.Length} bytes from {host}");
                return (host, result);
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"YggdrasilBootstrap: {host} failed: {ex.Message}");
            }

        return (null, null);
    }
}