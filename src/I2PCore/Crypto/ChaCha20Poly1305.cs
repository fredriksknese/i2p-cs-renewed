using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.Crypto;

/// <summary>
///     ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
///     RFC 7539: https://tools.ietf.org/html/rfc7539
///     Used in both SSU2 and NTCP2 for Noise protocol encryption
/// </summary>
public static class ChaCha20Poly1305
{
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;

    /// <summary>
    ///     Encrypt and authenticate data using ChaCha20-Poly1305
    /// </summary>
    /// <param name="key">32-byte encryption key</param>
    /// <param name="nonce">12-byte nonce (first 4 bytes zero, last 8 bytes counter)</param>
    /// <param name="plaintext">Data to encrypt</param>
    /// <param name="associatedData">Additional authenticated data (not encrypted)</param>
    /// <returns>Ciphertext with 16-byte Poly1305 MAC appended</returns>
    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData = null)
    {
        if (key == null || key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));

        if (nonce == null || nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));

        if (plaintext == null)
            plaintext = Array.Empty<byte>();

        if (associatedData == null)
            associatedData = Array.Empty<byte>();

        // Use BouncyCastle's ChaCha20Poly1305 AEAD mode
        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        var parameters = new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, associatedData);
        cipher.Init(true, parameters);

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        cipher.DoFinal(output, len);

        return output;
    }

    /// <summary>
    ///     Decrypt and verify data using ChaCha20-Poly1305
    /// </summary>
    /// <param name="key">32-byte encryption key</param>
    /// <param name="nonce">12-byte nonce</param>
    /// <param name="ciphertextWithTag">Ciphertext with 16-byte Poly1305 MAC appended</param>
    /// <param name="associatedData">Additional authenticated data</param>
    /// <returns>Decrypted plaintext, or null if authentication fails</returns>
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] associatedData = null)
    {
        if (key == null || key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));

        if (nonce == null || nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));

        if (ciphertextWithTag == null || ciphertextWithTag.Length < TagSize)
            throw new ArgumentException("Ciphertext too short", nameof(ciphertextWithTag));

        if (associatedData == null)
            associatedData = Array.Empty<byte>();

        try
        {
            // Use BouncyCastle's ChaCha20Poly1305 AEAD mode
            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, associatedData);
            cipher.Init(false, parameters);

            var output = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];
            var len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, output, 0);
            cipher.DoFinal(output, len);

            return output;
        }
        catch (Exception)
        {
            // Authentication failed
            return null;
        }
    }

    /// <summary>
    ///     Create a 12-byte nonce for ChaCha20-Poly1305
    ///     Match Java I2P's ChaChaCore.initIV:
    ///     state[12] = 0;
    ///     state[13] = 0;
    ///     state[14] = (int)nonce;
    ///     state[15] = (int)(nonce >> 32);
    ///     This means 64-bit counter at the middle/end of 12-byte IV in Little Endian.
    ///     (nonce[4..11] of 12-byte nonce).
    /// </summary>
    public static byte[] CreateNonce(ulong counter)
    {
        var nonce = new byte[NonceSize];
        // Skip first 4 bytes (word 13)
        for (var i = 0; i < 8; i++) nonce[4 + i] = (byte)(counter >> (i * 8));
        return nonce;
    }
}