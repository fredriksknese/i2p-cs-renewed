using System;
using I2PCore.Crypto;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Transport layer cryptography tests for SSU2 and NTCP2
///     Tests ChaCha20-Poly1305 AEAD and AES-256-CBC obfuscation
/// </summary>
[TestFixture]
public class TransportTest
{
    /// <summary>
    ///     Test ChaCha20-Poly1305 AEAD used by both SSU2 and NTCP2
    ///     RFC 7539: https://tools.ietf.org/html/rfc7539
    /// </summary>
    [Test]
    public void TestChaCha20Poly1305()
    {
        var key = BufUtils.RandomBytes(32);
        var nonce = BufUtils.RandomBytes(12);
        var plaintext = BufUtils.RandomBytes(1000);
        var associatedData = BufUtils.RandomBytes(16);

        // Encrypt
        var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext, associatedData);
        Assert.IsNotNull(ciphertext, "Encryption failed");
        Assert.AreEqual(plaintext.Length + 16, ciphertext.Length,
            "Ciphertext should be plaintext + 16 byte MAC");

        // Decrypt
        var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext, associatedData);
        Assert.IsNotNull(decrypted, "Decryption failed");
        Assert.IsTrue(BufUtils.Equal(plaintext, decrypted),
            "Decrypted text doesn't match original");
    }

    /// <summary>
    ///     Test ChaCha20-Poly1305 with empty plaintext
    /// </summary>
    [Test]
    public void TestChaCha20Poly1305EmptyPlaintext()
    {
        var key = BufUtils.RandomBytes(32);
        var nonce = BufUtils.RandomBytes(12);
        var plaintext = Array.Empty<byte>();
        var associatedData = BufUtils.RandomBytes(16);

        var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext, associatedData);
        Assert.IsNotNull(ciphertext);
        Assert.AreEqual(16, ciphertext.Length, "Empty plaintext should produce 16-byte MAC");

        var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext, associatedData);
        Assert.IsNotNull(decrypted);
        Assert.AreEqual(0, decrypted.Length);
    }

    /// <summary>
    ///     Test ChaCha20-Poly1305 authentication failure
    /// </summary>
    [Test]
    public void TestChaCha20Poly1305AuthFailure()
    {
        var key = BufUtils.RandomBytes(32);
        var nonce = BufUtils.RandomBytes(12);
        var plaintext = BufUtils.RandomBytes(100);

        var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

        // Corrupt the ciphertext
        ciphertext[50] ^= 0xFF;

        // Decryption should fail due to MAC verification
        var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext);
        Assert.IsNull(decrypted, "Decryption should fail with corrupted ciphertext");
    }

    /// <summary>
    ///     Test AES-256-CBC ephemeral key obfuscation used in NTCP2
    ///     Per NTCP2 spec: X and Y keys are obfuscated for DPI resistance
    /// </summary>
    [Test]
    public void TestAESObfuscation()
    {
        var ephemeralKey = BufUtils.RandomBytes(32); // X25519 public key
        var aesKey = BufUtils.RandomBytes(32); // Bob's router hash
        var iv = BufUtils.RandomBytes(16);

        // Encrypt
        var encrypted = AESObfuscation.Encrypt(ephemeralKey, aesKey, iv);
        Assert.IsNotNull(encrypted);
        Assert.AreEqual(32, encrypted.Length);
        Assert.IsFalse(BufUtils.Equal(ephemeralKey, encrypted), "Encrypted key should differ from plaintext");

        // Decrypt
        var decrypted = AESObfuscation.Decrypt(encrypted, aesKey, iv);
        Assert.IsNotNull(decrypted);
        Assert.AreEqual(32, decrypted.Length);
        Assert.IsTrue(BufUtils.Equal(ephemeralKey, decrypted), "Decrypted key should match original");
    }

    /// <summary>
    ///     Test AES-256-CBC state continuation for NTCP2 Message 2
    ///     Per NTCP2 spec: Message 2 uses CBC state from Message 1
    /// </summary>
    [Test]
    public void TestAESObfuscationStateContinuation()
    {
        var firstBlock = BufUtils.RandomBytes(32);
        var aesKey = BufUtils.RandomBytes(32);
        var iv = BufUtils.RandomBytes(16);

        // Encrypt first block (Message 1 in NTCP2)
        var encrypted1 = AESObfuscation.Encrypt(firstBlock, aesKey, iv);

        // Get CBC state after first block
        var newIV = AESObfuscation.GetStateAfterEncryption(aesKey, iv, firstBlock);
        Assert.IsNotNull(newIV);
        Assert.AreEqual(16, newIV.Length);

        // The new IV should be the last 16 bytes of the ciphertext (CBC chaining)
        for (var i = 0; i < 16; i++)
            Assert.AreEqual(encrypted1[16 + i], newIV[i],
                $"New IV byte {i} should match last 16 bytes of ciphertext");

        // Encrypt second block (Message 2 in NTCP2) using continued state
        var secondBlock = BufUtils.RandomBytes(32);
        var encrypted2 = AESObfuscation.Encrypt(secondBlock, aesKey, newIV);
        Assert.IsNotNull(encrypted2);
        Assert.AreEqual(32, encrypted2.Length);
    }

    /// <summary>
    ///     Test AES-256-CBC using native .NET implementation
    ///     Alternative to BouncyCastle implementation
    /// </summary>
    [Test]
    public void TestAESObfuscationNative()
    {
        var ephemeralKey = BufUtils.RandomBytes(32);
        var aesKey = BufUtils.RandomBytes(32);
        var iv = BufUtils.RandomBytes(16);

        // Test native .NET AES
        var encryptedNative = AESObfuscation.EncryptNative(ephemeralKey, aesKey, iv);
        var decryptedNative = AESObfuscation.DecryptNative(encryptedNative, aesKey, iv);
        Assert.IsTrue(BufUtils.Equal(ephemeralKey, decryptedNative),
            "Native AES decryption should match original");

        // Verify BouncyCastle and .NET produce same result
        var encryptedBC = AESObfuscation.Encrypt(ephemeralKey, aesKey, iv);
        Assert.IsTrue(BufUtils.Equal(encryptedNative, encryptedBC),
            "Native and BouncyCastle AES should produce identical ciphertext");
    }
}