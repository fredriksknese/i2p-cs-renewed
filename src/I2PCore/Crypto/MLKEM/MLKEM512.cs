using I2PCore.Utils;
using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace I2PCore.Crypto.MLKEM;

/// <summary>
///     ML-KEM-512 implementation using BouncyCastle (FIPS 203)
///     Module-Lattice-Based Key Encapsulation Mechanism
///     Security Level: 1 (AES-128 equivalent)
///     Parameters: k=2, η₁=3, η₂=2, du=10, dv=4
/// </summary>
public class MLKEM512
{
    // Sizes (in bytes) - from FIPS 203
    public const int PublicKeyBytes = 800; // 32 + 384k = 800 for k=2
    public const int SecretKeyBytes = 1632; // 768k + 96 = 1632 for k=2
    public const int CiphertextBytes = 768; // 32(du·k + dv) = 768
    public const int SharedSecretBytes = 32;

    /// <summary>
    ///     Generate ML-KEM-512 keypair using BouncyCastle
    /// </summary>
    public static (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = BufUtils.BcRandom;
        var keyGenParams = new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_512);
        var keyPairGenerator = new MLKemKeyPairGenerator();
        keyPairGenerator.Init(keyGenParams);

        var keyPair = keyPairGenerator.GenerateKeyPair();

        var publicKeyParams = (MLKemPublicKeyParameters)keyPair.Public;
        var privateKeyParams = (MLKemPrivateKeyParameters)keyPair.Private;

        return (publicKeyParams.GetEncoded(), privateKeyParams.GetEncoded());
    }

    /// <summary>
    ///     Encapsulate: Generate shared secret and ciphertext using BouncyCastle
    /// </summary>
    public static (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey)
    {
        var publicKeyParams = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_512, publicKey);

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_512);
        encapsulator.Init(publicKeyParams);

        var ciphertext = new byte[encapsulator.EncapsulationLength];
        var secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);

        return (ciphertext, secret);
    }

    /// <summary>
    ///     Decapsulate: Recover shared secret from ciphertext using BouncyCastle
    /// </summary>
    public static byte[] Decapsulate(byte[] ciphertext, byte[] secretKey)
    {
        var privateKeyParams = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_512, secretKey);

        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_512);
        decapsulator.Init(privateKeyParams);

        var secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);

        return secret;
    }

    /// <summary>
    ///     Extract public key from encoded secret key
    /// </summary>
    public static byte[] GetPublicKey(byte[] secretKey)
    {
        // FIPS 203: sk = (dk || ek || H(ek) || z)
        // For ML-KEM-512 (k=2): dk=768, ek=800
        var ek = new byte[PublicKeyBytes];
        Array.Copy(secretKey, 768, ek, 0, PublicKeyBytes);
        return ek;
    }
}