using System;
using System.Security.Cryptography;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Crypto.Noise;

/// <summary>
///     Noise Protocol Framework Key Derivation Functions
///     Based on HMAC-SHA256
///     Implements:
///     - InitializeSymmetric()
///     - MixHash()
///     - MixKey()
///     - Split()
///     Reference: https://noiseprotocol.org/noise.html Section 5
/// </summary>
public class NoiseKDF
{
    private const int HashLength = 32; // SHA256
    private byte[] ChainingKey;
    private byte[] Hash;

    /// <summary>
    ///     Initialize symmetric state with protocol name
    /// </summary>
    public void InitializeSymmetric(string protocolName)
    {
        if (protocolName.Length <= HashLength)
        {
            // If protocol name is <= 32 bytes, pad with zeros
            Hash = new byte[HashLength];
            var nameBytes = Encoding.ASCII.GetBytes(protocolName);
            Array.Copy(nameBytes, Hash, nameBytes.Length);
        }
        else
        {
            // If protocol name is > 32 bytes, hash it
            using (var sha256 = SHA256.Create())
            {
                Hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(protocolName));
            }
        }

        ChainingKey = new byte[HashLength];
        Array.Copy(Hash, ChainingKey, HashLength);

        // NTCP2 and SSU2 follow standard Noise: MixHash(prologue) even when empty.
        // Spec: h = HASH(h || prologue). If prologue is empty, h = HASH(h).
        using (var sha256 = SHA256.Create())
        {
            Hash = sha256.ComputeHash(Hash);
        }

        // Debug logging
        Logging.LogDebugData($"NoiseKDF InitializeSymmetric: protocolName length={protocolName.Length}");
        Logging.LogDebugData($"NoiseKDF: Initial Hash = {BitConverter.ToString(Hash).Replace("-", "")}");
        Logging.LogDebugData($"NoiseKDF: Initial CK   = {BitConverter.ToString(ChainingKey).Replace("-", "")}");
    }

    /// <summary>
    ///     MixHash(data) - Mix data into the hash
    ///     h = SHA256(h || data)
    /// </summary>
    public void MixHash(byte[] data)
    {
        if (data == null || data.Length == 0) return;

        using (var sha256 = SHA256.Create())
        {
            var dataLen = data?.Length ?? 0;
            var input = new byte[Hash.Length + dataLen];
            Array.Copy(Hash, 0, input, 0, Hash.Length);
            if (dataLen > 0) Array.Copy(data, 0, input, Hash.Length, dataLen);
            Hash = sha256.ComputeHash(input);
        }

        Logging.LogDebugData(
            $"NoiseKDF MixHash: dataLen={data?.Length ?? 0}, newHash = {BitConverter.ToString(Hash).Replace("-", "").Substring(0, 32)}...");
    }

    /// <summary>
    ///     MixKey(inputKeyMaterial) - Mix IKM into the chaining key
    ///     Generates new chaining key and cipher key
    /// </summary>
    /// <returns>New cipher key (k)</returns>
    public byte[] MixKey(byte[] inputKeyMaterial)
    {
        // temp_key = HMAC-SHA256(ck, input_key_material)
        var tempKey = HMACSHA256(ChainingKey, inputKeyMaterial);

        // ck = HMAC-SHA256(temp_key, 0x01)
        ChainingKey = HMACSHA256(tempKey, new byte[] { 0x01 });

        // k = HMAC-SHA256(temp_key, ck || 0x02)
        var keyInput = new byte[ChainingKey.Length + 1];
        Array.Copy(ChainingKey, keyInput, ChainingKey.Length);
        keyInput[ChainingKey.Length] = 0x02;
        var key = HMACSHA256(tempKey, keyInput);

        // Clear temp_key
        Array.Clear(tempKey, 0, tempKey.Length);

        return key;
    }

    /// <summary>
    ///     Split() - Split the chaining key into two keys for data phase
    ///     Returns (k1, k2) where k1 is for sending and k2 is for receiving
    /// </summary>
    public (byte[] k1, byte[] k2, byte[] ck) Split()
    {
        // Final chaining key for I2P ECIES (Proposal 144)
        var ck = (byte[])ChainingKey.Clone();

        // temp_key = HMAC-SHA256(ck, zerolen)
        var tempKey = HMACSHA256(ChainingKey, Array.Empty<byte>());

        // k1 = HMAC-SHA256(temp_key, 0x01)
        var k1 = HMACSHA256(tempKey, new byte[] { 0x01 });

        // k2 = HMAC-SHA256(temp_key, k1 || 0x02)
        var k2Input = new byte[k1.Length + 1];
        Array.Copy(k1, k2Input, k1.Length);
        k2Input[k1.Length] = 0x02;
        var k2 = HMACSHA256(tempKey, k2Input);

        // Clear sensitive data
        Array.Clear(ChainingKey, 0, ChainingKey.Length);
        Array.Clear(tempKey, 0, tempKey.Length);

        return (k1, k2, ck);
    }

    /// <summary>
    ///     Get current hash (used as associated data in AEAD)
    /// </summary>
    public byte[] GetHash()
    {
        var result = new byte[Hash.Length];
        Array.Copy(Hash, result, Hash.Length);
        return result;
    }

    /// <summary>
    ///     Set hash value directly (for i2pd-compatible initialization)
    /// </summary>
    public void SetHash(byte[] newHash)
    {
        if (newHash.Length != HashLength)
            throw new ArgumentException($"Hash must be {HashLength} bytes");
        Array.Copy(newHash, Hash, HashLength);
        Logging.LogDebugData(
            $"NoiseKDF SetHash: newHash = {BitConverter.ToString(newHash).Replace("-", "").Substring(0, 32)}...");
    }

    /// <summary>
    ///     Get current chaining key
    /// </summary>
    public byte[] GetChainingKey()
    {
        var result = new byte[ChainingKey.Length];
        Array.Copy(ChainingKey, result, ChainingKey.Length);
        return result;
    }

    /// <summary>
    ///     HMAC-SHA256 implementation
    /// </summary>
    private static byte[] HMACSHA256(byte[] key, byte[] data)
    {
        using (var hmac = new HMACSHA256(key))
        {
            return hmac.ComputeHash(data);
        }
    }

    /// <summary>
    ///     HMAC-SHA256 (public version for external use like SipHash derivation)
    /// </summary>
    public static byte[] HMAC_SHA256(byte[] key, byte[] data)
    {
        return HMACSHA256(key, data);
    }

    /// <summary>
    ///     HMAC-SHA256 with offset (for NTCP2 SipHash)
    /// </summary>
    public static byte[] HMAC_SHA256(byte[] key, int offset, int length, byte[] data)
    {
        var keyPart = new byte[length];
        Array.Copy(key, offset, keyPart, 0, length);
        return HMACSHA256(keyPart, data);
    }

    /// <summary>
    ///     HKDF-based key derivation for additional keys (e.g., SipHash keys for NTCP2)
    ///     Matches i2pd signature: HKDF(salt, ikm, info, length)
    /// </summary>
    public static byte[] HKDF(byte[] salt, byte[] ikm, byte[] info, int outputLength)
    {
        // Extract
        byte[] prk;
        if (salt == null || salt.Length == 0) salt = new byte[32]; // All zeros
        prk = HMACSHA256(salt, ikm ?? Array.Empty<byte>());

        // Expand
        var output = new byte[outputLength];
        var t = Array.Empty<byte>();
        var offset = 0;
        byte counter = 1;

        while (offset < outputLength)
        {
            var input = new byte[t.Length + (info?.Length ?? 0) + 1];
            Array.Copy(t, 0, input, 0, t.Length);
            if (info != null)
                Array.Copy(info, 0, input, t.Length, info.Length);
            input[input.Length - 1] = counter;

            t = HMACSHA256(prk, input);

            var bytesToCopy = Math.Min(t.Length, outputLength - offset);
            Array.Copy(t, 0, output, offset, bytesToCopy);
            offset += bytesToCopy;
            counter++;
        }

        // Clear sensitive data
        Array.Clear(prk, 0, prk.Length);
        Array.Clear(t, 0, t.Length);

        return output;
    }
}