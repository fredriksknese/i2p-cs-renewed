using I2PCore.Utils;
using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace I2PCore.Crypto.MLKEM;

/// <summary>
///     ML-KEM-768 implementation using BouncyCastle (FIPS 203)
///     Module-Lattice-Based Key Encapsulation Mechanism
///     Security Level: 3 (AES-192 equivalent)
///     Parameters: k=3, η₁=2, η₂=2, du=10, dv=4
/// </summary>
public class MLKEM768
{
    // Sizes (in bytes) - from FIPS 203
    public const int PublicKeyBytes = 1184; // 32 + 384k = 1184 for k=3
    public const int SecretKeyBytes = 2400; // 768k + 96 = 2400 for k=3
    public const int CiphertextBytes = 1088; // 32(du·k + dv) = 1088
    public const int SharedSecretBytes = 32;

    /// <summary>
    ///     Generate ML-KEM-768 keypair using BouncyCastle
    /// </summary>
    public static (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = BufUtils.BcRandom;
        var keyGenParams = new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768);
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
        var publicKeyParams = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, publicKey);

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
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
        var privateKeyParams = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, secretKey);

        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
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
        // For ML-KEM-768 (k=3): dk=1152, ek=1184
        var ek = new byte[PublicKeyBytes];
        Array.Copy(secretKey, 1152, ek, 0, PublicKeyBytes);
        return ek;
    }
}