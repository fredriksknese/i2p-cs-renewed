using System;
using I2PCore.Crypto.MLKEM;
using I2PCore.TransportLayer.Crypto;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using X25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace I2PCore.Crypto
{
    /// <summary>
    /// Noise_IKhfselg2_25519+MLKEM512_ChaChaPoly_SHA256
    ///
    /// IK pattern with hybrid forward secrecy:
    /// - X25519 for initial DH
    /// - ML-KEM-512/768/1024 for post-quantum KEM
    /// - Elligator2 encoding for ephemeral keys
    /// - ChaCha20-Poly1305 AEAD
    /// - SHA-256 for hashing
    ///
    /// Pattern:
    /// <- s
    /// ...
    /// -> e, es, s, ss, ekem1, payload
    /// <- ekem2, payload
    /// </summary>
    public class NoiseIKhfs
    {
        public enum KEMVariant
        {
            MLKEM512,
            MLKEM768,
            MLKEM1024
        }

        private readonly KEMVariant kemVariant;
        private byte[] localStaticPrivate;
        private byte[] localStaticPublic;
        private byte[] remoteStaticKey;
        private byte[] localEphemeralPrivate;
        private byte[] localEphemeralPublic;
        private byte[] remoteEphemeralKey;
        private bool isInitiator;

        // KEM state
        private byte[] localKemPublicKey;   // e1: Alice's ML-KEM public key (encap_key)
        private byte[] localKemSecretKey;   // Alice's ML-KEM secret key (decap_key)
        private byte[] remoteKemPublicKey;  // e1: received from Alice
        private byte[] kemCiphertext;       // ekem1: KEM ciphertext
        private byte[] kemSharedSecret;     // Shared secret from KEM

        // Noise protocol state
        private byte[] chainingKey;
        private byte[] hash;
        protected int cipherNonce;

        public NoiseIKhfs(KEMVariant variant = KEMVariant.MLKEM512)
        {
            this.kemVariant = variant;

            string protocolName = variant switch
            {
                KEMVariant.MLKEM512 => "Noise_IKhfselg2_25519+MLKEM512_ChaChaPoly_SHA256",
                KEMVariant.MLKEM768 => "Noise_IKhfselg2_25519+MLKEM768_ChaChaPoly_SHA256",
                KEMVariant.MLKEM1024 => "Noise_IKhfselg2_25519+MLKEM1024_ChaChaPoly_SHA256",
                _ => throw new ArgumentException($"Unsupported KEM variant: {variant}")
            };

            InitializeProtocol(protocolName);
        }

        private void InitializeProtocol(string protocolName)
        {
            var h = HKDF.InitializeProtocol(protocolName);
            hash = new byte[32];
            chainingKey = new byte[32];
            Array.Copy(h, hash, 32);
            Array.Copy(h, chainingKey, 32);
            cipherNonce = 0;

            // Standard Noise initialization: MixHash(null prologue)
            MixHash(Array.Empty<byte>());
        }

        private void Initialize(byte[] staticPrivate, byte[] staticPublic, bool initiator)
        {
            this.localStaticPrivate = staticPrivate;
            this.localStaticPublic = staticPublic;
            this.isInitiator = initiator;
        }

        protected void MixHash(byte[] data)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var combined = new byte[hash.Length + data.Length];
                Array.Copy(hash, 0, combined, 0, hash.Length);
                Array.Copy(data, 0, combined, hash.Length, data.Length);
                hash = sha256.ComputeHash(combined);
            }
        }

        protected void MixKey(byte[] inputKeyMaterial)
        {
            var output = HKDF.DeriveKey(chainingKey, inputKeyMaterial, null, 64);
            chainingKey = new byte[32];
            Array.Copy(output, 0, chainingKey, 0, 32);
        }

        protected byte[] GetCipherKey()
        {
            var output = HKDF.DeriveKey(chainingKey, new byte[0], null, 64);
            byte[] key = new byte[32];
            Array.Copy(output, 32, key, 0, 32);
            return key;
        }

        protected void IncrementNonce()
        {
            cipherNonce++;
        }

        /// <summary>
        /// Create initiator (sender of first message)
        /// Uses local static keys and remote static public key
        /// </summary>
        public static NoiseIKhfs CreateInitiator(
            byte[] localStaticPrivate,
            byte[] localStaticPublic,
            byte[] remoteStaticPublic,
            KEMVariant variant = KEMVariant.MLKEM512)
        {
            var noise = new NoiseIKhfs(variant);
            noise.Initialize(localStaticPrivate, localStaticPublic, true);
            noise.remoteStaticKey = remoteStaticPublic;

            // <- s
            noise.MixHash(remoteStaticPublic);

            return noise;
        }

        /// <summary>
        /// Create Responder (receiver of first message)
        /// Uses only local static keys
        /// </summary>
        public static NoiseIKhfs CreateResponder(
            byte[] localStaticPrivate,
            byte[] localStaticPublic,
            KEMVariant variant = KEMVariant.MLKEM512)
        {
            var noise = new NoiseIKhfs(variant);
            noise.Initialize(localStaticPrivate, localStaticPublic, false);

            // <- s
            noise.MixHash(localStaticPublic);

            return noise;
        }

        /// <summary>
        /// Initiator: Create first message (e, es, e1, s, ss, payload)
        /// Pattern: -> e, es, e1, s, ss, p
        /// Returns (ephemeral_public_elligator2, encrypted_e1, encrypted_static, encrypted_payload)
        /// </summary>
        public (byte[] ephemeralPublic, byte[] encryptedKemPublicKey, byte[] encryptedStatic, byte[] encryptedPayload)
            WriteMessageA(byte[] payload)
        {
            if (remoteStaticKey == null)
                throw new InvalidOperationException("Remote static key not set");

            byte[] ephemeralEncoded = null;
            int attempts = 0;

            while ( ephemeralEncoded == null )
            {
                try
                {
                    // Generate encodable ephemeral X25519 keypair
                    localEphemeralPrivate = Elligator2.GenerateEncodablePrivateKey();
                    localEphemeralPublic = TransportLayer.Crypto.X25519.GetPublicKey(localEphemeralPrivate);

                    // Encode ephemeral public key with Elligator2
                    ephemeralEncoded = Elligator2.Encode(localEphemeralPublic);
                }
                catch ( InvalidOperationException ex ) when ( ex.Message.Contains( "Elligator2" ) )
                {
                    if ( ++attempts > 100 ) throw;
                }
            }

            // MixHash(e)
            MixHash(localEphemeralPublic);

            // es: MixKey(DH(e, rs))
            byte[] es = X25519DH(localEphemeralPrivate, remoteStaticKey);
            MixKey(es);

            // Generate ML-KEM keypair (e1 pattern)
            switch (kemVariant)
            {
                case KEMVariant.MLKEM512:
                    (localKemPublicKey, localKemSecretKey) = MLKEM512.GenerateKeyPair();
                    break;
                case KEMVariant.MLKEM768:
                    (localKemPublicKey, localKemSecretKey) = MLKEM768.GenerateKeyPair();
                    break;
                case KEMVariant.MLKEM1024:
                    (localKemPublicKey, localKemSecretKey) = MLKEM1024.GenerateKeyPair();
                    break;
                default:
                    throw new ArgumentException("Invalid KEM variant");
            }

            // EncryptAndHash(encap_key) - e1 pattern
            var cipherKem = CreateCipher();
            cipherKem.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] encryptedKemPublicKey = new byte[localKemPublicKey.Length + 16];
            int len = cipherKem.ProcessBytes(localKemPublicKey, 0, localKemPublicKey.Length, encryptedKemPublicKey, 0);
            len += cipherKem.DoFinal(encryptedKemPublicKey, len);

            MixHash(encryptedKemPublicKey);

            // Encrypt static key: s
            var cipherStatic = CreateCipher();
            cipherStatic.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] encryptedStatic = new byte[localStaticPublic.Length + 16];
            len = cipherStatic.ProcessBytes(localStaticPublic, 0, localStaticPublic.Length, encryptedStatic, 0);
            len += cipherStatic.DoFinal(encryptedStatic, len);

            MixHash(encryptedStatic);

            // ss: MixKey(DH(s, rs))
            byte[] ss = X25519DH(localStaticPrivate, remoteStaticKey);
            MixKey(ss);

            // Encrypt payload
            var cipherPayload = CreateCipher();
            cipherPayload.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] encryptedPayload = new byte[payload.Length + 16];
            len = cipherPayload.ProcessBytes(payload, 0, payload.Length, encryptedPayload, 0);
            len += cipherPayload.DoFinal(encryptedPayload, len);

            MixHash(encryptedPayload);

            return (ephemeralEncoded, encryptedKemPublicKey, encryptedStatic, encryptedPayload);
        }

        /// <summary>
        /// Responder: Read first message (e, es, e1, s, ss, payload)
        /// Pattern: <- e, es, e1, s, ss, p
        /// Returns (decrypted_payload, remote_static_key, remote_kem_public_key)
        /// </summary>
        public (byte[] payload, byte[] remoteStaticKey, byte[] remoteKemPublicKey) ReadMessageA(
            byte[] ephemeralPublicEncoded,
            byte[] encryptedKemPublicKey,
            byte[] encryptedStatic,
            byte[] encryptedPayload)
        {
            // Decode Elligator2 ephemeral key
            remoteEphemeralKey = Elligator2.Decode(ephemeralPublicEncoded);
            if (remoteEphemeralKey == null)
                throw new ArgumentException("Invalid Elligator2 encoded ephemeral key");

            MixHash(remoteEphemeralKey);

            // es: MixKey(DH(s, re))
            byte[] es = X25519DH(localStaticPrivate, remoteEphemeralKey);
            MixKey(es);

            // DecryptAndHash(encap_key) - e1 pattern
            var cipherKem = CreateCipher();
            cipherKem.Init(false, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] decryptedKemPublicKey = new byte[cipherKem.GetOutputSize(encryptedKemPublicKey.Length)];
            int len = cipherKem.ProcessBytes(encryptedKemPublicKey, 0, encryptedKemPublicKey.Length, decryptedKemPublicKey, 0);
            len += cipherKem.DoFinal(decryptedKemPublicKey, len);

            Array.Resize(ref decryptedKemPublicKey, len);
            remoteKemPublicKey = decryptedKemPublicKey;

            MixHash(encryptedKemPublicKey);

            // Decrypt static key
            var cipherStatic = CreateCipher();
            cipherStatic.Init(false, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] decryptedStatic = new byte[cipherStatic.GetOutputSize(encryptedStatic.Length)];
            len = cipherStatic.ProcessBytes(encryptedStatic, 0, encryptedStatic.Length, decryptedStatic, 0);
            len += cipherStatic.DoFinal(decryptedStatic, len);

            Array.Resize(ref decryptedStatic, len);
            remoteStaticKey = decryptedStatic;

            MixHash(encryptedStatic);

            // ss: MixKey(DH(s, rs))
            byte[] ss = X25519DH(localStaticPrivate, remoteStaticKey);
            MixKey(ss);

            // Decrypt payload
            var cipherPayload = CreateCipher();
            cipherPayload.Init(false, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] decryptedPayload = new byte[cipherPayload.GetOutputSize(encryptedPayload.Length)];
            len = cipherPayload.ProcessBytes(encryptedPayload, 0, encryptedPayload.Length, decryptedPayload, 0);
            len += cipherPayload.DoFinal(decryptedPayload, len);

            Array.Resize(ref decryptedPayload, len);
            MixHash(encryptedPayload);

            return (decryptedPayload, remoteStaticKey, remoteKemPublicKey);
        }

        /// <summary>
        /// Responder: Create reply message (e, ee, ekem1, se, payload)
        /// Pattern: <- tag, e, ee, ekem1, se, p
        /// Must be called after ReadMessageA to have remoteKemPublicKey available
        /// Returns (ephemeral_public_elligator2, encrypted_ekem1, empty_section_mac, encrypted_payload)
        /// </summary>
        public (byte[] ephemeralPublic, byte[] encryptedKemCiphertext, byte[] emptySectionMac, byte[] encryptedPayload) WriteMessageB(
            byte[] payload)
        {
            if (remoteEphemeralKey == null)
                throw new InvalidOperationException("Must call ReadMessageA first");
            if (remoteKemPublicKey == null)
                throw new InvalidOperationException("Remote KEM public key not available from ReadMessageA");

            byte[] ephemeralEncoded = null;
            int attempts = 0;

            while ( ephemeralEncoded == null )
            {
                try
                {
                    // Generate encodable ephemeral X25519 keypair
                    localEphemeralPrivate = Elligator2.GenerateEncodablePrivateKey();
                    localEphemeralPublic = TransportLayer.Crypto.X25519.GetPublicKey(localEphemeralPrivate);

                    // Encode ephemeral public key with Elligator2
                    ephemeralEncoded = Elligator2.Encode(localEphemeralPublic);
                }
                catch ( InvalidOperationException ex ) when ( ex.Message.Contains( "Elligator2" ) )
                {
                    if ( ++attempts > 100 ) throw;
                }
            }

            // MixHash(e)
            MixHash(localEphemeralPublic);

            // ee: MixKey(DH(e, re))
            byte[] ee = X25519DH(localEphemeralPrivate, remoteEphemeralKey);
            MixKey(ee);

            // Encapsulate with remote's KEM public key (ekem1 pattern)
            byte[] kemCipher, kemShared;

            switch (kemVariant)
            {
                case KEMVariant.MLKEM512:
                    (kemCipher, kemShared) = MLKEM512.Encapsulate(remoteKemPublicKey);
                    break;
                case KEMVariant.MLKEM768:
                    (kemCipher, kemShared) = MLKEM768.Encapsulate(remoteKemPublicKey);
                    break;
                case KEMVariant.MLKEM1024:
                    (kemCipher, kemShared) = MLKEM1024.Encapsulate(remoteKemPublicKey);
                    break;
                default:
                    throw new ArgumentException("Invalid KEM variant");
            }

            kemCiphertext = kemCipher;
            kemSharedSecret = kemShared;

            // EncryptAndHash(kem_ciphertext) - ekem1 pattern
            var cipherKem = CreateCipher();
            cipherKem.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] encryptedKemCiphertext = new byte[kemCiphertext.Length + 16];
            int len = cipherKem.ProcessBytes(kemCiphertext, 0, kemCiphertext.Length, encryptedKemCiphertext, 0);
            len += cipherKem.DoFinal(encryptedKemCiphertext, len);

            MixHash(encryptedKemCiphertext);

            // MixKey(kem_shared_key)
            MixKey(kemSharedSecret);

            // Empty section (for consistency with standard IK pattern)
            var cipherEmpty = CreateCipher();
            cipherEmpty.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] emptySectionMac = new byte[16];  // Just the MAC, no data
            cipherEmpty.DoFinal(emptySectionMac, 0);

            // se: MixKey(DH(e, rs))
            byte[] se = X25519DH(localEphemeralPrivate, remoteStaticKey);
            MixKey(se);

            // Encrypt payload
            var cipherPayload = CreateCipher();
            cipherPayload.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] encryptedPayload = new byte[payload.Length + 16];
            len = cipherPayload.ProcessBytes(payload, 0, payload.Length, encryptedPayload, 0);
            len += cipherPayload.DoFinal(encryptedPayload, len);

            MixHash(encryptedPayload);

            return (ephemeralEncoded, encryptedKemCiphertext, emptySectionMac, encryptedPayload);
        }

        /// <summary>
        /// Initiator: Read reply message (e, ee, ekem1, se, payload)
        /// Pattern: <- tag, e, ee, ekem1, se, p
        /// Must be called after WriteMessageA to have localKemSecretKey available
        /// </summary>
        public byte[] ReadMessageB(
            byte[] ephemeralPublicEncoded,
            byte[] encryptedKemCiphertext,
            byte[] emptySectionMac,
            byte[] encryptedPayload)
        {
            if (localKemSecretKey == null)
                throw new InvalidOperationException("Must call WriteMessageA first");

            // Decode Elligator2 ephemeral key
            remoteEphemeralKey = Elligator2.Decode(ephemeralPublicEncoded);
            if (remoteEphemeralKey == null)
                throw new ArgumentException("Invalid Elligator2 encoded ephemeral key");

            // MixHash(e)
            MixHash(remoteEphemeralKey);

            // ee: MixKey(DH(e, re))
            byte[] ee = X25519DH(localEphemeralPrivate, remoteEphemeralKey);
            MixKey(ee);

            // DecryptAndHash(kem_ciphertext) - ekem1 pattern
            var cipherKem = CreateCipher();
            cipherKem.Init(false, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] decryptedKemCiphertext = new byte[cipherKem.GetOutputSize(encryptedKemCiphertext.Length)];
            int len = cipherKem.ProcessBytes(encryptedKemCiphertext, 0, encryptedKemCiphertext.Length, decryptedKemCiphertext, 0);
            len += cipherKem.DoFinal(decryptedKemCiphertext, len);

            Array.Resize(ref decryptedKemCiphertext, len);
            kemCiphertext = decryptedKemCiphertext;

            MixHash(encryptedKemCiphertext);

            // Decapsulate KEM
            switch (kemVariant)
            {
                case KEMVariant.MLKEM512:
                    kemSharedSecret = MLKEM512.Decapsulate(kemCiphertext, localKemSecretKey);
                    break;
                case KEMVariant.MLKEM768:
                    kemSharedSecret = MLKEM768.Decapsulate(kemCiphertext, localKemSecretKey);
                    break;
                case KEMVariant.MLKEM1024:
                    kemSharedSecret = MLKEM1024.Decapsulate(kemCiphertext, localKemSecretKey);
                    break;
                default:
                    throw new ArgumentException("Invalid KEM variant");
            }

            // MixKey(kem_shared_key)
            MixKey(kemSharedSecret);

            // Empty section (verify MAC only)
            var cipherEmpty = CreateCipher();
            cipherEmpty.Init(false, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] emptyVerify = new byte[cipherEmpty.GetOutputSize(emptySectionMac.Length)];
            cipherEmpty.ProcessBytes(emptySectionMac, 0, emptySectionMac.Length, emptyVerify, 0);
            cipherEmpty.DoFinal(emptyVerify, 0);

            // se: MixKey(DH(e, rs))
            byte[] se = X25519DH(localStaticPrivate, remoteStaticKey);
            MixKey(se);

            // Decrypt payload
            var cipherPayload = CreateCipher();
            cipherPayload.Init(false, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(GetCipherKey()), GetNonce()));

            byte[] decryptedPayload = new byte[cipherPayload.GetOutputSize(encryptedPayload.Length)];
            len = cipherPayload.ProcessBytes(encryptedPayload, 0, encryptedPayload.Length, decryptedPayload, 0);
            len += cipherPayload.DoFinal(decryptedPayload, len);

            Array.Resize(ref decryptedPayload, len);
            MixHash(encryptedPayload);

            return decryptedPayload;
        }

        private byte[] X25519DH(byte[] privateKey, byte[] publicKey)
        {
            byte[] sharedSecret = new byte[32];
            X25519.ScalarMult(privateKey, 0, publicKey, 0, sharedSecret, 0);
            return sharedSecret;
        }

        private Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305 CreateCipher()
        {
            return new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        }

        private byte[] GetNonce()
        {
            byte[] nonce = new byte[12];
            // Nonce is 4 bytes of zeros followed by 8-byte counter (little-endian)
            ulong counter = (ulong)cipherNonce;
            for (int i = 0; i < 8; i++)
            {
                nonce[4 + i] = (byte)((counter >> (i * 8)) & 0xFF);
            }
            IncrementNonce();
            return nonce;
        }

        public byte[] GetChainingKey()
        {
            return (byte[])chainingKey.Clone();
        }

        public (byte[] sendKey, byte[] receiveKey, byte[] ck) FinalizeHandshake()
        {
            var ck = (byte[])chainingKey.Clone();
            var output = HKDF.DeriveKey(chainingKey, new byte[0], null, 64);
            var k1 = new byte[32];
            var k2 = new byte[32];
            Array.Copy(output, 0, k1, 0, 32);
            Array.Copy(output, 32, k2, 0, 32);

            // Per Noise spec, initiator uses k1 for sending, responder for receiving
            return isInitiator ? (k1, k2, ck) : (k2, k1, ck);
        }

        public void Dispose()
        {
            if (localStaticPrivate != null) Array.Clear(localStaticPrivate, 0, localStaticPrivate.Length);
            if (localEphemeralPrivate != null) Array.Clear(localEphemeralPrivate, 0, localEphemeralPrivate.Length);
            if (localKemSecretKey != null) Array.Clear(localKemSecretKey, 0, localKemSecretKey.Length);
            if (kemSharedSecret != null) Array.Clear(kemSharedSecret, 0, kemSharedSecret.Length);
        }
    }
}
