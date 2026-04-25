using System;
using System.Security.Cryptography;
using System.Text;

namespace I2PCore.Crypto;

/// <summary>
///     HMAC-based Key Derivation Function (HKDF)
///     RFC 5869: https://tools.ietf.org/html/rfc5869
///     Used extensively in Noise protocol and ECIES for key derivation
/// </summary>
public static class HKDF
{
    /// <summary>
    ///     HKDF key derivation with SHA-256
    /// </summary>
    /// <param name="salt">Salt value (32 bytes for SHA-256, can be null)</param>
    /// <param name="inputKeyMaterial">Input key material (IKM)</param>
    /// <param name="info">Context-specific info string</param>
    /// <param name="outputLength">Desired output length in bytes</param>
    /// <returns>Derived key material</returns>
    public static byte[] DeriveKey(byte[] salt, byte[] inputKeyMaterial, byte[] info, int outputLength)
    {
        if (inputKeyMaterial == null)
            throw new ArgumentNullException(nameof(inputKeyMaterial));

        if (outputLength < 1 || outputLength > 255 * 32)
            throw new ArgumentException("Invalid output length", nameof(outputLength));

        // HKDF-Extract
        var prk = Extract(salt, inputKeyMaterial);

        // HKDF-Expand
        var okm = Expand(prk, info, outputLength);

        return okm;
    }

    /// <summary>
    ///     HKDF-Extract: Extract a pseudorandom key from input key material
    ///     PRK = HMAC-SHA256(salt, IKM)
    /// </summary>
    private static byte[] Extract(byte[] salt, byte[] ikm)
    {
        // If salt is null or empty, use a string of zeros
        if (salt == null || salt.Length == 0) salt = new byte[32]; // SHA-256 hash length

        using (var hmac = new HMACSHA256(salt))
        {
            return hmac.ComputeHash(ikm);
        }
    }

    /// <summary>
    ///     HKDF-Expand: Expand a pseudorandom key to desired length
    /// </summary>
    private static byte[] Expand(byte[] prk, byte[] info, int length)
    {
        if (info == null)
            info = Array.Empty<byte>();

        const int hashLen = 32; // SHA-256 output length
        var n = (length + hashLen - 1) / hashLen; // Ceiling division

        if (n > 255)
            throw new ArgumentException("Output length too large");

        var okm = new byte[length];
        var t = Array.Empty<byte>();

        using (var hmac = new HMACSHA256(prk))
        {
            for (byte i = 1; i <= n; i++)
            {
                // T(i) = HMAC(PRK, T(i-1) | info | i)
                hmac.Initialize();
                hmac.TransformBlock(t, 0, t.Length, null, 0);
                hmac.TransformBlock(info, 0, info.Length, null, 0);
                hmac.TransformFinalBlock(new[] { i }, 0, 1);
                t = hmac.Hash;

                // Copy to output
                var copyLen = Math.Min(hashLen, length - (i - 1) * hashLen);
                Array.Copy(t, 0, okm, (i - 1) * hashLen, copyLen);
            }
        }

        return okm;
    }

    /// <summary>
    ///     Convenience method for deriving two keys (common in Noise protocol)
    ///     Returns (chainKey, encryptionKey) as used in Noise MixKey
    /// </summary>
    public static (byte[] chainKey, byte[] encryptionKey) DeriveChainAndKey(
        byte[] chainingKey,
        byte[] inputKeyMaterial)
    {
        var output = DeriveKey(chainingKey, inputKeyMaterial, Array.Empty<byte>(), 64);

        var chainKey = new byte[32];
        var encryptionKey = new byte[32];

        Array.Copy(output, 0, chainKey, 0, 32);
        Array.Copy(output, 32, encryptionKey, 0, 32);

        return (chainKey, encryptionKey);
    }

    /// <summary>
    ///     Convenience method for Noise protocol initialization
    ///     Used to derive initial chaining key and hash from protocol name
    /// </summary>
    public static byte[] InitializeProtocol(string protocolName)
    {
        if (string.IsNullOrEmpty(protocolName))
            throw new ArgumentException("Protocol name cannot be null or empty");

        var nameBytes = Encoding.ASCII.GetBytes(protocolName);

        if (nameBytes.Length <= 32)
        {
            // If protocol name is 32 bytes or less, pad with zeros (no hashing)
            var padded = new byte[32];
            Array.Copy(nameBytes, padded, nameBytes.Length);
            return padded;
        }

        // If longer than 32 bytes, hash it
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(nameBytes);
        }
    }
}