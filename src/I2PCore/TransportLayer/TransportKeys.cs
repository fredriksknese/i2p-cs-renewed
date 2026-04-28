using System;
using System.IO;
using I2PCore.Utils;

namespace I2PCore.TransportLayer;

/// <summary>
///     Persistent storage for transport protocol static keys
///     Keys must persist across router restarts to maintain network identity
/// </summary>
public static class TransportKeys
{
    private static string KeysDirectory
    {
        get
        {
            var dir = Path.Combine(StreamUtils.AppPath, "keys");
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>
    ///     Load NTCP2 static keys from persistent storage
    ///     Returns (staticPrivateKey, staticPublicKey, iv) or null if not found
    /// </summary>
    public static (byte[] privateKey, byte[] publicKey, byte[] iv)? LoadNTCP2Keys()
    {
        try
        {
            var keyFile = Path.Combine(KeysDirectory, "ntcp2_keys.dat");
            if (!File.Exists(keyFile))
                return null;

            var data = File.ReadAllBytes(keyFile);
            if (data.Length != 32 + 32 + 16) // privKey + pubKey + IV
            {
                Logging.LogWarning($"NTCP2 key file corrupted (expected 80 bytes, got {data.Length})");
                return null;
            }

            var privateKey = new byte[32];
            var publicKey = new byte[32];
            var iv = new byte[16];

            Array.Copy(data, 0, privateKey, 0, 32);
            Array.Copy(data, 32, publicKey, 0, 32);
            Array.Copy(data, 64, iv, 0, 16);

            Logging.LogInformation("NTCP2 keys loaded from persistent storage");
            return (privateKey, publicKey, iv);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to load NTCP2 keys: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    ///     Save NTCP2 static keys to persistent storage
    /// </summary>
    public static void SaveNTCP2Keys(byte[] privateKey, byte[] publicKey, byte[] iv)
    {
        try
        {
            if (privateKey.Length != 32 || publicKey.Length != 32 || iv.Length != 16)
                throw new ArgumentException("Invalid key sizes");

            var keyFile = Path.Combine(KeysDirectory, "ntcp2_keys.dat");
            var data = new byte[80]; // 32 + 32 + 16

            Array.Copy(privateKey, 0, data, 0, 32);
            Array.Copy(publicKey, 0, data, 32, 32);
            Array.Copy(iv, 0, data, 64, 16);

            File.WriteAllBytes(keyFile, data);
            Logging.LogInformation("NTCP2 keys saved to persistent storage");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to save NTCP2 keys: {ex.Message}");
        }
    }

    /// <summary>
    ///     Load SSU2 keys from persistent storage
    ///     Returns (staticPrivateKey, staticPublicKey, introKey) or null if not found
    /// </summary>
    public static (byte[] privateKey, byte[] publicKey, byte[] introKey)? LoadSSU2Keys()
    {
        try
        {
            var keyFile = Path.Combine(KeysDirectory, "ssu2_keys.dat");
            if (!File.Exists(keyFile))
            {
                // Fallback to old file name for backward compatibility
                var oldFile = Path.Combine(KeysDirectory, "ssu2_intro_key.dat");
                if (File.Exists(oldFile))
                {
                    keyFile = oldFile;
                }
                else
                {
                    return null;
                }
            }

            var data = File.ReadAllBytes(keyFile);
            if (data.Length != 64 && data.Length != 96) // (privKey + pubKey) or (privKey + pubKey + introKey)
            {
                Logging.LogWarning($"SSU2 key file corrupted (expected 64 or 96 bytes, got {data.Length})");
                return null;
            }

            var privateKey = new byte[32];
            var publicKey = new byte[32];
            var introKey = data.Length == 96 ? new byte[32] : null;

            Array.Copy(data, 0, privateKey, 0, 32);
            Array.Copy(data, 32, publicKey, 0, 32);
            if (introKey != null)
                Array.Copy(data, 64, introKey, 0, 32);

            Logging.LogInformation("SSU2 keys loaded from persistent storage");
            return (privateKey, publicKey, introKey);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to load SSU2 keys: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    ///     Save SSU2 keys to persistent storage
    /// </summary>
    public static void SaveSSU2Keys(byte[] privateKey, byte[] publicKey, byte[] introKey)
    {
        try
        {
            if (privateKey.Length != 32 || publicKey.Length != 32 || (introKey != null && introKey.Length != 32))
                throw new ArgumentException("Invalid key sizes");

            var keyFile = Path.Combine(KeysDirectory, "ssu2_keys.dat");
            var size = introKey == null ? 64 : 96;
            var data = new byte[size];

            Array.Copy(privateKey, 0, data, 0, 32);
            Array.Copy(publicKey, 0, data, 32, 32);
            if (introKey != null)
                Array.Copy(introKey, 0, data, 64, 32);

            File.WriteAllBytes(keyFile, data);
            Logging.LogInformation("SSU2 keys saved to persistent storage");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to save SSU2 keys: {ex.Message}");
        }
    }
}