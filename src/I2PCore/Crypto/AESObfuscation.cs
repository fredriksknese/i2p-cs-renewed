using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.Crypto;

/// <summary>
///     AES-256-CBC encryption for ephemeral key obfuscation
///     Used in NTCP2 for obfuscating X and Y keys in handshake messages 1 and 2
///     Note: This is for DPI resistance only, not for security
///     Anyone with Bob's router hash and IV (both public) can decrypt
/// </summary>
public static class AESObfuscation
{
    public const int KeySize = 32; // AES-256
    public const int IVSize = 16;
    public const int BlockSize = 32; // X25519 key size

    /// <summary>
    ///     Encrypt ephemeral key using AES-256-CBC
    /// </summary>
    /// <param name="key">Plaintext ephemeral key (32 bytes)</param>
    /// <param name="aesKey">AES key (router hash, 32 bytes)</param>
    /// <param name="iv">AES IV (16 bytes)</param>
    /// <returns>Encrypted key (32 bytes)</returns>
    public static byte[] Encrypt(byte[] key, byte[] aesKey, byte[] iv)
    {
        if (key == null || key.Length != BlockSize)
            throw new ArgumentException($"Key must be {BlockSize} bytes", nameof(key));

        if (aesKey == null || aesKey.Length != KeySize)
            throw new ArgumentException($"AES key must be {KeySize} bytes", nameof(aesKey));

        if (iv == null || iv.Length != IVSize)
            throw new ArgumentException($"IV must be {IVSize} bytes", nameof(iv));

        var cipher = new CbcBlockCipher(new AesEngine());
        var parameters = new ParametersWithIV(new KeyParameter(aesKey), iv);
        cipher.Init(true, parameters);

        var output = new byte[BlockSize];
        cipher.ProcessBlock(key, 0, output, 0);
        cipher.ProcessBlock(key, 16, output, 16);

        return output;
    }

    /// <summary>
    ///     Decrypt ephemeral key using AES-256-CBC
    /// </summary>
    /// <param name="encryptedKey">Encrypted ephemeral key (32 bytes)</param>
    /// <param name="aesKey">AES key (router hash, 32 bytes)</param>
    /// <param name="iv">AES IV (16 bytes)</param>
    /// <returns>Decrypted key (32 bytes)</returns>
    public static byte[] Decrypt(byte[] encryptedKey, byte[] aesKey, byte[] iv)
    {
        if (encryptedKey == null || encryptedKey.Length != BlockSize)
            throw new ArgumentException($"Encrypted key must be {BlockSize} bytes", nameof(encryptedKey));

        if (aesKey == null || aesKey.Length != KeySize)
            throw new ArgumentException($"AES key must be {KeySize} bytes", nameof(aesKey));

        if (iv == null || iv.Length != IVSize)
            throw new ArgumentException($"IV must be {IVSize} bytes", nameof(iv));

        var cipher = new CbcBlockCipher(new AesEngine());
        var parameters = new ParametersWithIV(new KeyParameter(aesKey), iv);
        cipher.Init(false, parameters);

        var output = new byte[BlockSize];
        cipher.ProcessBlock(encryptedKey, 0, output, 0);
        cipher.ProcessBlock(encryptedKey, 16, output, 16);

        return output;
    }

    /// <summary>
    ///     Get AES state after processing one block (for NTCP2 message 2)
    ///     In NTCP2, message 2 uses the AES state from message 1 to continue encryption
    /// </summary>
    public static byte[] GetStateAfterEncryption(byte[] aesKey, byte[] iv, byte[] firstBlock)
    {
        if (firstBlock == null || firstBlock.Length != BlockSize)
            throw new ArgumentException($"First block must be {BlockSize} bytes", nameof(firstBlock));

        if (aesKey == null || aesKey.Length != KeySize)
            throw new ArgumentException($"AES key must be {KeySize} bytes", nameof(aesKey));

        if (iv == null || iv.Length != IVSize)
            throw new ArgumentException($"IV must be {IVSize} bytes", nameof(iv));

        // In CBC mode, the IV for the next block is the ciphertext of the previous block
        var cipher = new CbcBlockCipher(new AesEngine());
        var parameters = new ParametersWithIV(new KeyParameter(aesKey), iv);
        cipher.Init(true, parameters);

        var output = new byte[BlockSize];
        cipher.ProcessBlock(firstBlock, 0, output, 0);
        cipher.ProcessBlock(firstBlock, 16, output, 16);

        // The new IV is the last 16 bytes of the ciphertext
        var newIV = new byte[IVSize];
        Array.Copy(output, 16, newIV, 0, IVSize);

        return newIV;
    }

    /// <summary>
    ///     Encrypt using .NET's native AES (alternative implementation)
    /// </summary>
    public static byte[] EncryptNative(byte[] key, byte[] aesKey, byte[] iv)
    {
        if (key == null || key.Length != BlockSize)
            throw new ArgumentException($"Key must be {BlockSize} bytes", nameof(key));

        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = aesKey;
            aes.IV = iv;

            using (var encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(key, 0, key.Length);
            }
        }
    }

    /// <summary>
    ///     Decrypt using .NET's native AES (alternative implementation)
    /// </summary>
    public static byte[] DecryptNative(byte[] encryptedKey, byte[] aesKey, byte[] iv)
    {
        if (encryptedKey == null || encryptedKey.Length != BlockSize)
            throw new ArgumentException($"Encrypted key must be {BlockSize} bytes", nameof(encryptedKey));

        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = aesKey;
            aes.IV = iv;

            using (var decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(encryptedKey, 0, encryptedKey.Length);
            }
        }
    }
}