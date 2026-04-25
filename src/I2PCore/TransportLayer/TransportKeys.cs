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
    ///     Load SSU2 intro key from persistent storage
    ///     Returns (introPrivateKey, introPublicKey) or null if not found
    /// </summary>
    public static (byte[] privateKey, byte[] publicKey)? LoadSSU2IntroKey()
    {
        try
        {
            var keyFile = Path.Combine(KeysDirectory, "ssu2_intro_key.dat");
            if (!File.Exists(keyFile))
                return null;

            var data = File.ReadAllBytes(keyFile);
            if (data.Length != 64) // privKey + pubKey
            {
                Logging.LogWarning($"SSU2 intro key file corrupted (expected 64 bytes, got {data.Length})");
                return null;
            }

            var privateKey = new byte[32];
            var publicKey = new byte[32];

            Array.Copy(data, 0, privateKey, 0, 32);
            Array.Copy(data, 32, publicKey, 0, 32);

            Logging.LogInformation("SSU2 intro key loaded from persistent storage");
            return (privateKey, publicKey);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to load SSU2 intro key: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    ///     Save SSU2 intro key to persistent storage
    /// </summary>
    public static void SaveSSU2IntroKey(byte[] privateKey, byte[] publicKey)
    {
        try
        {
            if (privateKey.Length != 32 || publicKey.Length != 32)
                throw new ArgumentException("Invalid key sizes");

            var keyFile = Path.Combine(KeysDirectory, "ssu2_intro_key.dat");
            var data = new byte[64]; // 32 + 32

            Array.Copy(privateKey, 0, data, 0, 32);
            Array.Copy(publicKey, 0, data, 32, 32);

            File.WriteAllBytes(keyFile, data);
            Logging.LogInformation("SSU2 intro key saved to persistent storage");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to save SSU2 intro key: {ex.Message}");
        }
    }
}