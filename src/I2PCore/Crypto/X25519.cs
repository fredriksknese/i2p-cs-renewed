using System;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace I2PCore.Crypto
{
    /// <summary>
    /// X25519 Elliptic Curve Diffie-Hellman key exchange
    /// RFC 7748: https://tools.ietf.org/html/rfc7748
    /// </summary>
    public static class X25519
    {
        public const int KeySize = 32;

        /// <summary>
        /// Generate a new X25519 key pair
        /// </summary>
        public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
        {
            var random = new SecureRandom();
            var keyPairGenerator = new X25519KeyPairGenerator();
            keyPairGenerator.Init(new X25519KeyGenerationParameters(random));
            
            var keyPair = keyPairGenerator.GenerateKeyPair();
            
            var privateKey = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();
            var publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
            
            return (privateKey, publicKey);
        }

        /// <summary>
        /// Derive public key from private key
        /// </summary>
        public static byte[] GetPublicKey(byte[] privateKey)
        {
            if (privateKey == null || privateKey.Length != KeySize)
                throw new ArgumentException($"Private key must be {KeySize} bytes", nameof(privateKey));

            var privKeyParams = new X25519PrivateKeyParameters(privateKey, 0);
            var pubKeyParams = privKeyParams.GeneratePublicKey();
            
            return pubKeyParams.GetEncoded();
        }

        /// <summary>
        /// Perform X25519 Diffie-Hellman key exchange
        /// </summary>
        /// <param name="privateKey">Our private key (32 bytes)</param>
        /// <param name="publicKey">Their public key (32 bytes). High bit (MSB of byte 31) is ignored per RFC 7748.</param>
        /// <returns>Shared secret (32 bytes)</returns>
        public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null || privateKey.Length != KeySize)
                throw new ArgumentException($"Private key must be {KeySize} bytes", nameof(privateKey));
            
            if (publicKey == null || publicKey.Length != KeySize)
                throw new ArgumentException($"Public key must be {KeySize} bytes", nameof(publicKey));

            // Mask the high bit as required by RFC 7748 and I2P NTCP2-hybrid signal.
            // BouncyCastle might do this internally, but we do it explicitly to be sure
            // it doesn't interfere with MixHash if the same buffer is used.
            var maskedPubKey = new byte[32];
            Array.Copy(publicKey, maskedPubKey, 32);
            maskedPubKey[31] &= 0x7F;

            var privKeyParams = new X25519PrivateKeyParameters(privateKey, 0);
            var pubKeyParams = new X25519PublicKeyParameters(maskedPubKey, 0);
            
            var agreement = new X25519Agreement();
            agreement.Init(privKeyParams);
            
            var secret = new byte[KeySize];
            agreement.CalculateAgreement(pubKeyParams, secret, 0);
            
            return secret;
        }

        /// <summary>
        /// Validate that a public key is a valid X25519 point
        /// </summary>
        public static bool IsValidPublicKey(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != KeySize)
                return false;

            try
            {
                var maskedPubKey = new byte[32];
                Array.Copy(publicKey, maskedPubKey, 32);
                maskedPubKey[31] &= 0x7F;

                // Try to create the key parameters.
                _ = new X25519PublicKeyParameters(maskedPubKey, 0);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Clamp a private key to conform to X25519 requirements
        /// Sets bits: k[0] &= 248, k[31] &= 127, k[31] |= 64
        /// </summary>
        public static void ClampPrivateKey(byte[] privateKey)
        {
            if (privateKey == null || privateKey.Length != KeySize)
                throw new ArgumentException($"Private key must be {KeySize} bytes", nameof(privateKey));

            privateKey[0] &= 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;
        }
    }
}
