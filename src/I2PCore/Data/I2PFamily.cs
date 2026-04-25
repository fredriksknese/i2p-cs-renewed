using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data;

/// <summary>
///     Router Family support - cryptographically groups related routers.
///     Uses X.509 certificates for family signature verification.
///     Compatible with i2pd Family.h/.cpp
/// </summary>
public class I2PFamilies
{
    private readonly ConcurrentDictionary<string, X509Certificate2>
        _familyCerts = new(StringComparer.OrdinalIgnoreCase);

    private string _certsDirectory;

    public static I2PFamilies Instance { get; } = new();

    /// <summary>
    ///     Load family certificates from the certificates directory
    /// </summary>
    public void LoadCertificates(string certsDirectory)
    {
        _certsDirectory = certsDirectory;

        if (!Directory.Exists(certsDirectory))
        {
            Logging.LogDebug($"Family certificates directory not found: {certsDirectory}");
            return;
        }

        var familyDir = Path.Combine(certsDirectory, "family");
        if (!Directory.Exists(familyDir))
            return;

        foreach (var certFile in Directory.GetFiles(familyDir, "*.crt"))
            try
            {
                var familyName = Path.GetFileNameWithoutExtension(certFile);
                var cert = new X509Certificate2(certFile);
                _familyCerts[familyName] = cert;
                Logging.LogDebug($"Loaded family certificate: {familyName}");
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"Failed to load family cert {certFile}: {ex.Message}");
            }
    }

    /// <summary>
    ///     Verify that a router's family claim is valid
    /// </summary>
    public bool VerifyFamily(I2PRouterInfo routerInfo)
    {
        if (routerInfo == null) return false;

        // Extract family name from router info options
        var familyNameStr = routerInfo.Options?.TryGet("family")?.ToString();
        if (string.IsNullOrEmpty(familyNameStr))
            return false;

        // Get family signature from router info
        var familySigStr = routerInfo.Options?.TryGet("family.sig")?.ToString();
        if (string.IsNullOrEmpty(familySigStr))
            return false;

        // Find the certificate
        if (!_familyCerts.TryGetValue(familyNameStr, out var cert))
        {
            Logging.LogDebug($"No certificate for family: {familyNameStr}");
            return false;
        }

        try
        {
            // Verify: the family signature signs (familyName + routerIdentHash)
            var identHash = routerInfo.Identity?.IdentHash?.Hash.ToByteArray();
            if (identHash == null) return false;

            var familyBytes = Encoding.UTF8.GetBytes(familyNameStr);
            var dataToVerify = new byte[familyBytes.Length + identHash.Length];
            Array.Copy(familyBytes, 0, dataToVerify, 0, familyBytes.Length);
            Array.Copy(identHash, 0, dataToVerify, familyBytes.Length, identHash.Length);

            var sigBytes = Convert.FromBase64String(familySigStr.Replace('-', '+').Replace('~', '/'));

            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null)
                return rsa.VerifyData(dataToVerify, sigBytes,
                    HashAlgorithmName.SHA512,
                    RSASignaturePadding.Pkcs1);

            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null)
                return ecdsa.VerifyData(dataToVerify, sigBytes,
                    HashAlgorithmName.SHA512);

            return false;
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"Family verification failed for {familyNameStr}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    ///     Get the family name for a router, if verified
    /// </summary>
    public string GetVerifiedFamily(I2PRouterInfo routerInfo)
    {
        var familyStr = routerInfo?.Options?.TryGet("family")?.ToString();
        if (familyStr != null && VerifyFamily(routerInfo))
            return familyStr;
        return null;
    }

    public bool HasCertificate(string familyName)
    {
        return _familyCerts.ContainsKey(familyName);
    }
}