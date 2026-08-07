using I2PCore.Utils;
using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace I2PCore.Crypto.MLKEM;

/// <summary>
///     ML-KEM-1024 implementation using BouncyCastle (FIPS 203)
///     Module-Lattice-Based Key Encapsulation Mechanism
///     Security Level: 5 (AES-256 equivalent)
///     Parameters: k=4, η₁=2, η₂=2, du=11, dv=5
/// </summary>
public class MLKEM1024
{
    // Sizes (in bytes) - from FIPS 203
    public const int PublicKeyBytes = 1568; // 32 + 384k = 1568 for k=4
    public const int SecretKeyBytes = 3168; // 768k + 96 = 3168 for k=4
    public const int CiphertextBytes = 1568; // 32(du·k + dv) = 1568
    public const int SharedSecretBytes = 32;

    /// <summary>
    ///     Generate ML-KEM-1024 keypair using BouncyCastle
    /// </summary>
    public static (byte[] publicKey, byte[] secretKey) GenerateKeyPair()
    {
        var random = BufUtils.BcRandom;
        var keyGenParams = new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_1024);
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
        var publicKeyParams = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, publicKey);

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_1024);
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
        var privateKeyParams = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, secretKey);

        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_1024);
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
        // For ML-KEM-1024 (k=4): dk=1536, ek=1568
        var ek = new byte[PublicKeyBytes];
        Array.Copy(secretKey, 1536, ek, 0, PublicKeyBytes);
        return ek;
    }
}