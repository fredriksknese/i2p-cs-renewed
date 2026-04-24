using System;

namespace I2PCore.TransportLayer.Crypto
{
    /// <summary>
    /// Noise Protocol XK Pattern Implementation
    /// Used by both SSU2 and NTCP2
    /// 
    /// XK Pattern:
    ///   <- s
    ///   ...
    ///   -> e, es
    ///   <- e, ee
    ///   -> s, se
    /// 
    /// Alice is the initiator, Bob is the responder
    /// Alice knows Bob's static key beforehand (K)
    /// Alice transmits her key to Bob (X)
    /// 
    /// Protocol names:
    /// - NTCP2: "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256" (48 bytes)
    /// - SSU2:  "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256" (52 bytes)
    /// </summary>
    public class NoiseXK
    {
        // Protocol name constants per specifications
        public const string PROTOCOL_NAME_NTCP2 = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";
        public const string PROTOCOL_NAME_NTCP2_MLKEM512 = "Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM512_ChaChaPoly_SHA256";
        public const string PROTOCOL_NAME_NTCP2_MLKEM768 = "Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM768_ChaChaPoly_SHA256";
        public const string PROTOCOL_NAME_NTCP2_MLKEM1024 = "Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM1024_ChaChaPoly_SHA256";
        public const string PROTOCOL_NAME_SSU2 = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

        private readonly NoiseKDF kdf;
        private byte[] sendKey;
        private byte[] receiveKey;
        private ulong sendNonce;
        private ulong receiveNonce;

        /// <summary>Current send nonce counter (for diagnostics)</summary>
        public ulong SendNonce => sendNonce;
        /// <summary>Current receive nonce counter (for diagnostics)</summary>
        public ulong ReceiveNonce => receiveNonce;

        // Store cipher key from Message 2 for use in Message 3 Part 1
        private byte[] message2CipherKey;

        // Alice (initiator) keys
        private byte[] aliceStaticPrivateKey;
        private byte[] aliceStaticPublicKey;
        private byte[] aliceEphemeralPrivateKey;
        private byte[] aliceEphemeralPublicKey;

        // Bob (responder) keys
        private byte[] bobStaticPrivateKey;
        private byte[] bobStaticPublicKey;
        private byte[] bobEphemeralPrivateKey;
        private byte[] bobEphemeralPublicKey;

        // Remote keys (set during handshake)
        private byte[] remoteStaticPublicKey;
        private byte[] remoteEphemeralPublicKey;

        public NoiseXK(string protocolName)
        {
            kdf = new NoiseKDF();
            kdf.InitializeSymmetric(protocolName);
        }

        /// <summary>
        /// Initialize as Alice (initiator)
        /// Per NTCP2 spec lines 260-277:
        /// h = SHA256(protocol_name)
        /// ck = h
        /// h = SHA256(h) // MixHash(null prologue)
        /// h = SHA256(h || Bob's_static_key) // MixHash(rs)
        /// </summary>
        public void InitializeAsAlice(byte[] aliceStaticPriv, byte[] aliceStaticPub, byte[] bobStaticPub)
        {
            // Copy the private key so ClearArray() at session end doesn't zero out the host's persistent key
            aliceStaticPrivateKey = (byte[])aliceStaticPriv.Clone();
            aliceStaticPublicKey = aliceStaticPub;
            bobStaticPublicKey = bobStaticPub;

            // MixHash(Bob's static key) - h = SHA256(h || rs)
            kdf.MixHash(bobStaticPublicKey);
        }

        /// <summary>
        /// Initialize as Bob (responder)
        /// Same initialization as Alice up to this point
        /// Per NTCP2 spec lines 260-279
        /// </summary>
        public void InitializeAsBob(byte[] bobStaticPriv, byte[] bobStaticPub)
        {
            // Copy the private key so ClearArray() at session end doesn't zero out the host's persistent key
            bobStaticPrivateKey = (byte[])bobStaticPriv.Clone();
            bobStaticPublicKey = bobStaticPub;

            // MixHash(Bob's static key) - h = SHA256(h || rs)
            kdf.MixHash(bobStaticPublicKey);
        }

        /// <summary>
        /// Generate new ephemeral keys for Alice and return the public key
        /// Used for MSB validation without affecting Noise state
        /// </summary>
        public byte[] GenerateAliceEphemeralKeys()
        {
            var (ephemeralPriv, ephemeralPub) = X25519.GenerateKeyPair();
            aliceEphemeralPrivateKey = ephemeralPriv;
            aliceEphemeralPublicKey = ephemeralPub;
            return ephemeralPub;
        }

        /// <summary>
        /// Generate new ephemeral keys for Bob and return the public key
        /// Used for MSB validation without affecting Noise state
        /// </summary>
        public byte[] GenerateBobEphemeralKeys()
        {
            var (ephemeralPriv, ephemeralPub) = X25519.GenerateKeyPair();
            bobEphemeralPrivateKey = ephemeralPriv;
            bobEphemeralPublicKey = ephemeralPub;
            return ephemeralPub;
        }

        /// <summary>
        /// Message 1 (Alice -> Bob): e, es
        /// Uses the currently stored ephemeral keys (must call GenerateEphemeralKeys first)
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage1WithCurrentKeys(byte[] payload)
        {
            if (aliceEphemeralPublicKey == null || aliceEphemeralPrivateKey == null)
            {
                throw new InvalidOperationException("Must call GenerateEphemeralKeys before CreateMessage1WithCurrentKeys");
            }

            // MixHash(e)
            kdf.MixHash(aliceEphemeralPublicKey);

            // es: DH(e, rs) - Alice's ephemeral with Bob's static
            var sharedSecret = X25519.ComputeSharedSecret(aliceEphemeralPrivateKey, bobStaticPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();

            // Debug logging for AEAD encryption
            I2PCore.Utils.Logging.LogDebug($"NoiseXK Message1 AEAD Encryption:");
            I2PCore.Utils.Logging.LogDebug($"  Key (k):    {BitConverter.ToString(key).Replace("-", "")}");
            I2PCore.Utils.Logging.LogDebug($"  Nonce (n):  {BitConverter.ToString(nonce).Replace("-", "")}");
            I2PCore.Utils.Logging.LogDebug($"  AD (h):     {BitConverter.ToString(associatedData).Replace("-", "")}");
            I2PCore.Utils.Logging.LogDebug($"  Plaintext:  {BitConverter.ToString(payload).Replace("-", "")}");
            I2PCore.Utils.Logging.LogDebug($"  CK (for verification): {BitConverter.ToString(kdf.GetChainingKey()).Replace("-", "")}");

            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            I2PCore.Utils.Logging.LogDebug($"  Ciphertext+MAC: {BitConverter.ToString(encryptedPayload).Replace("-", "")}");

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return (aliceEphemeralPublicKey, encryptedPayload);
        }

        /// <summary>
        /// Message 1 (Alice -> Bob): e, es
        /// Generates new ephemeral keys automatically
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage1(byte[] payload)
        {
            // Generate Alice's ephemeral key pair
            var (ephemeralPriv, ephemeralPub) = X25519.GenerateKeyPair();
            aliceEphemeralPrivateKey = ephemeralPriv;
            aliceEphemeralPublicKey = ephemeralPub;

            // MixHash(e)
            kdf.MixHash(aliceEphemeralPublicKey);

            // es: DH(e, rs) - Alice's ephemeral with Bob's static
            var sharedSecret = X25519.ComputeSharedSecret(aliceEphemeralPrivateKey, bobStaticPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return (aliceEphemeralPublicKey, encryptedPayload);
        }

        /// <summary>
        /// Message 1 with header (for SSU2): header is MixHashed before ephemeral key
        /// Uses the currently stored ephemeral keys (must call GenerateEphemeralKeys first)
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage1WithHeaderAndCurrentKeys(byte[] header, byte[] payload)
        {
            if (aliceEphemeralPublicKey == null || aliceEphemeralPrivateKey == null)
            {
                throw new InvalidOperationException("Must call GenerateEphemeralKeys before CreateMessage1WithHeaderAndCurrentKeys");
            }

            // MixHash(header) - SSU2 specific
            kdf.MixHash(header);

            // MixHash(e)
            kdf.MixHash(aliceEphemeralPublicKey);

            // es: DH(e, rs) - Alice's ephemeral with Bob's static
            var sharedSecret = X25519.ComputeSharedSecret(aliceEphemeralPrivateKey, bobStaticPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return (aliceEphemeralPublicKey, encryptedPayload);
        }

        /// <summary>
        /// Message 1 with header (for SSU2): header is MixHashed before ephemeral key
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage1WithHeader(byte[] header, byte[] payload)
        {
            // MixHash(header) - SSU2 specific
            kdf.MixHash(header);

            // Generate Alice's ephemeral key pair
            var (ephemeralPriv, ephemeralPub) = X25519.GenerateKeyPair();
            aliceEphemeralPrivateKey = ephemeralPriv;
            aliceEphemeralPublicKey = ephemeralPub;

            // MixHash(e)
            kdf.MixHash(aliceEphemeralPublicKey);

            // es: DH(e, rs) - Alice's ephemeral with Bob's static
            var sharedSecret = X25519.ComputeSharedSecret(aliceEphemeralPrivateKey, bobStaticPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return (aliceEphemeralPublicKey, encryptedPayload);
        }

        /// <summary>
        /// Message 1 (Bob receives from Alice): e, es
        /// </summary>
        public byte[] ProcessMessage1(byte[] ephemeralKey, byte[] encryptedPayload)
        {
            // Validate ephemeral key
            if (!X25519.IsValidPublicKey(ephemeralKey))
                throw new Exception("Invalid ephemeral key");

            remoteEphemeralPublicKey = ephemeralKey;

            // DIAG: log state before MixHash(e)
            var hBeforeMixE = kdf.GetHash();
            I2PCore.Utils.Logging.LogInformation($"NoiseXK PM1 DIAG: h_before_mixE={BitConverter.ToString(hBeforeMixE, 0, 8).Replace("-","")} e[0:4]={BitConverter.ToString(ephemeralKey, 0, 4).Replace("-","")} bobS[0:4]={BitConverter.ToString(bobStaticPublicKey, 0, 4).Replace("-","")} encPld[0:4]={BitConverter.ToString(encryptedPayload, 0, 4).Replace("-","")}");

            // MixHash(e)
            kdf.MixHash(remoteEphemeralPublicKey);

            var hAfterMixE = kdf.GetHash();
            I2PCore.Utils.Logging.LogInformation($"NoiseXK PM1 DIAG: h_after_mixE={BitConverter.ToString(hAfterMixE, 0, 8).Replace("-","")} ck[0:4]={BitConverter.ToString(kdf.GetChainingKey(), 0, 4).Replace("-","")}");

            // es: DH(s, re) - Bob's static with Alice's ephemeral
            I2PCore.Utils.Logging.LogInformation($"NoiseXK PM1 DIAG: e_full={BitConverter.ToString(remoteEphemeralPublicKey).Replace("-","")} bobS_full={BitConverter.ToString(bobStaticPublicKey).Replace("-","")}");
            var sharedSecret = X25519.ComputeSharedSecret(bobStaticPrivateKey, remoteEphemeralPublicKey);
            I2PCore.Utils.Logging.LogInformation($"NoiseXK PM1 DIAG: DH[0:4]={BitConverter.ToString(sharedSecret, 0, 4).Replace("-","")}");
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            I2PCore.Utils.Logging.LogInformation($"NoiseXK PM1 DIAG: key[0:4]={BitConverter.ToString(key, 0, 4).Replace("-","")} ck_after[0:4]={BitConverter.ToString(kdf.GetChainingKey(), 0, 4).Replace("-","")}");

            // Decrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            I2PCore.Utils.Logging.LogInformation($"NoiseXK PM1 DIAG: AD[0:8]={BitConverter.ToString(associatedData, 0, 8).Replace("-","")} nonce={BitConverter.ToString(nonce).Replace("-","")}");
            var payload = ChaCha20Poly1305.Decrypt(key, nonce, encryptedPayload, associatedData);

            if (payload == null)
                throw new Exception("AEAD authentication failed");

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return payload;
        }

        /// <summary>
        /// NTCP2-specific: MixHash the padding after message 1 or 2
        /// Per NTCP2 spec lines 420 and 835: Padding is authenticated by including it in KDF
        /// </summary>
        public void MixHashPadding(byte[] padding)
        {
            kdf.MixHash(padding ?? Array.Empty<byte>());
        }

        /// <summary>
        /// Message 1 with header (for SSU2): header is MixHashed before ephemeral key
        /// </summary>
        public byte[] ProcessMessage1WithHeader(byte[] header, byte[] ephemeralKey, byte[] encryptedPayload)
        {
            // MixHash(header) - SSU2 specific
            kdf.MixHash(header);

            // Validate ephemeral key
            if (!X25519.IsValidPublicKey(ephemeralKey))
                throw new Exception("Invalid ephemeral key");

            remoteEphemeralPublicKey = ephemeralKey;

            // MixHash(e)
            kdf.MixHash(remoteEphemeralPublicKey);

            // es: DH(s, re) - Bob's static with Alice's ephemeral
            var sharedSecret = X25519.ComputeSharedSecret(bobStaticPrivateKey, remoteEphemeralPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Decrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var payload = ChaCha20Poly1305.Decrypt(key, nonce, encryptedPayload, associatedData);

            if (payload == null)
                throw new Exception("AEAD authentication failed");

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return payload;
        }

        /// <summary>
        /// Message 2 (Bob -> Alice): e, ee
        /// Uses the currently stored ephemeral keys (must call GenerateBobEphemeralKeys first)
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage2WithCurrentKeys(byte[] payload)
        {
            if (bobEphemeralPublicKey == null || bobEphemeralPrivateKey == null)
            {
                throw new InvalidOperationException("Must call GenerateBobEphemeralKeys before CreateMessage2WithCurrentKeys");
            }

            // MixHash(e)
            kdf.MixHash(bobEphemeralPublicKey);

            // ee: DH(e, re) - Bob's ephemeral with Alice's ephemeral
            var sharedSecret = X25519.ComputeSharedSecret(bobEphemeralPrivateKey, remoteEphemeralPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Store key for Message 3 Part 1 (NTCP2 spec lines 826-854)
            message2CipherKey = new byte[key.Length];
            Array.Copy(key, message2CipherKey, key.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return (bobEphemeralPublicKey, encryptedPayload);
        }
        /// <summary>
        /// Message 2 (Bob -> Alice): e, ee
        /// Generates new ephemeral keys automatically
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage2(byte[] payload)
        {
            GenerateBobEphemeralKeys();
            return CreateMessage2WithCurrentKeys(payload);
        }

        /// <summary>
        /// Message 2 with header (for SSU2): header is MixHashed before ephemeral key
        /// Uses the currently stored ephemeral keys (must call GenerateBobEphemeralKeys first)
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage2WithHeaderAndCurrentKeys(byte[] header, byte[] payload)
        {
            if (bobEphemeralPublicKey == null || bobEphemeralPrivateKey == null)
            {
                throw new InvalidOperationException("Must call GenerateBobEphemeralKeys before CreateMessage2WithHeaderAndCurrentKeys");
            }

            // MixHash(header) - SSU2 specific
            kdf.MixHash(header);

            // MixHash(e)
            kdf.MixHash(bobEphemeralPublicKey);

            // ee: DH(e, re) - Bob's ephemeral with Alice's ephemeral
            var sharedSecret = X25519.ComputeSharedSecret(bobEphemeralPrivateKey, remoteEphemeralPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Store key for Message 3 Part 1 (SSU2 spec lines 1509-1537)
            message2CipherKey = new byte[key.Length];
            Array.Copy(key, message2CipherKey, key.Length);

            // Clear Alice's ephemeral key (no longer needed)
            Array.Clear(remoteEphemeralPublicKey, 0, remoteEphemeralPublicKey.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return (bobEphemeralPublicKey, encryptedPayload);
        }

        /// <summary>
        /// Message 2 with header (for SSU2): header is MixHashed before ephemeral key
        /// </summary>
        public (byte[] ephemeralKey, byte[] encryptedPayload) CreateMessage2WithHeader(byte[] header, byte[] payload)
        {
            // MixHash(header) - SSU2 specific
            kdf.MixHash(header);

            // Generate Bob's ephemeral key pair
            var (ephemeralPriv, ephemeralPub) = X25519.GenerateKeyPair();
            bobEphemeralPrivateKey = ephemeralPriv;
            bobEphemeralPublicKey = ephemeralPub;

            // MixHash(e)
            kdf.MixHash(bobEphemeralPublicKey);

            // ee: DH(e, re) - Bob's ephemeral with Alice's ephemeral
            var sharedSecret = X25519.ComputeSharedSecret(bobEphemeralPrivateKey, remoteEphemeralPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Store key for Message 3 Part 1 (SSU2 spec lines 1509-1537)
            message2CipherKey = new byte[key.Length];
            Array.Copy(key, message2CipherKey, key.Length);

            // Clear Alice's ephemeral key (no longer needed)
            Array.Clear(remoteEphemeralPublicKey, 0, remoteEphemeralPublicKey.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return (bobEphemeralPublicKey, encryptedPayload);
        }

        /// <summary>
        /// Message 2 (Alice receives from Bob): e, ee
        /// </summary>
        public byte[] ProcessMessage2(byte[] ephemeralKey, byte[] encryptedPayload)
        {
            // Validate ephemeral key
            if (!X25519.IsValidPublicKey(ephemeralKey))
                throw new Exception("Invalid ephemeral key");

            remoteEphemeralPublicKey = ephemeralKey;

            // MixHash(e)
            kdf.MixHash(remoteEphemeralPublicKey);

            // ee: DH(e, re) - Alice's ephemeral with Bob's ephemeral
            var sharedSecret = X25519.ComputeSharedSecret(aliceEphemeralPrivateKey, remoteEphemeralPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Store key for Message 3 Part 1 (NTCP2 spec lines 826-854)
            message2CipherKey = new byte[key.Length];
            Array.Copy(key, message2CipherKey, key.Length);

            // Clear Alice's ephemeral key (no longer needed)
            Array.Clear(aliceEphemeralPrivateKey, 0, aliceEphemeralPrivateKey.Length);
            Array.Clear(aliceEphemeralPublicKey, 0, aliceEphemeralPublicKey.Length);

            // Decrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var payload = ChaCha20Poly1305.Decrypt(key, nonce, encryptedPayload, associatedData);

            if (payload == null)
                throw new Exception("AEAD authentication failed");

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return payload;
        }

        /// <summary>
        /// Message 2 with header (for SSU2): header is MixHashed before ephemeral key
        /// </summary>
        public byte[] ProcessMessage2WithHeader(byte[] header, byte[] ephemeralKey, byte[] encryptedPayload)
        {
            // MixHash(header) - SSU2 specific
            kdf.MixHash(header);

            // Validate ephemeral key
            if (!X25519.IsValidPublicKey(ephemeralKey))
                throw new Exception("Invalid ephemeral key");

            remoteEphemeralPublicKey = ephemeralKey;

            // MixHash(e)
            kdf.MixHash(remoteEphemeralPublicKey);

            // ee: DH(e, re) - Alice's ephemeral with Bob's ephemeral
            var sharedSecret = X25519.ComputeSharedSecret(aliceEphemeralPrivateKey, remoteEphemeralPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Store key for Message 3 Part 1 (SSU2 spec lines 1509-1537)
            message2CipherKey = new byte[key.Length];
            Array.Copy(key, message2CipherKey, key.Length);

            // Clear Alice's ephemeral key (no longer needed)
            Array.Clear(aliceEphemeralPrivateKey, 0, aliceEphemeralPrivateKey.Length);
            Array.Clear(aliceEphemeralPublicKey, 0, aliceEphemeralPublicKey.Length);

            // Decrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var payload = ChaCha20Poly1305.Decrypt(key, nonce, encryptedPayload, associatedData);

            if (payload == null)
                throw new Exception("AEAD authentication failed");

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            return payload;
        }

        /// <summary>
        /// Message 3 Part 1 (Alice -> Bob): s (encrypted static key)
        /// NTCP2 spec lines 826-854: Must use cipher key from Message 2, nonce=1
        /// </summary>
        public byte[] CreateMessage3Part1()
        {
            if (message2CipherKey == null)
                throw new InvalidOperationException("Message 2 must be processed first");

            // Use the cipher key from message 2 (NOT chaining key)
            // NTCP2 spec line 847: "k is from handshake message 1" - this is the key from after "ee" DH
            var nonce = ChaCha20Poly1305.CreateNonce(1);  // nonce = 1 for part 1
            var associatedData = kdf.GetHash();
            var encryptedStatic = ChaCha20Poly1305.Encrypt(message2CipherKey, nonce, aliceStaticPublicKey, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedStatic);

            return encryptedStatic;
        }

        /// <summary>
        /// Message 3 Part 1 (Bob receives from Alice): s
        /// NTCP2 spec lines 826-854: Must use cipher key from Message 2, nonce=1
        /// </summary>
        public byte[] ProcessMessage3Part1(byte[] encryptedStatic)
        {
            if (message2CipherKey == null)
                throw new InvalidOperationException("Message 2 must be created first");

            // Use the cipher key from message 2 (NOT chaining key)
            var nonce = ChaCha20Poly1305.CreateNonce(1);
            var associatedData = kdf.GetHash();
            var staticKey = ChaCha20Poly1305.Decrypt(message2CipherKey, nonce, encryptedStatic, associatedData);

            if (staticKey == null)
                throw new Exception("AEAD authentication failed");

            // Validate static key
            if (!X25519.IsValidPublicKey(staticKey))
                throw new Exception("Invalid static key");

            remoteStaticPublicKey = staticKey;

            // MixHash(ciphertext)
            kdf.MixHash(encryptedStatic);

            return staticKey;
        }

        /// <summary>
        /// Message 3 Part 2 (Alice -> Bob): se, encrypted payload
        /// </summary>
        public byte[] CreateMessage3Part2(byte[] payload)
        {
            // se: DH(s, re) - Alice's static with Bob's ephemeral
            var sharedSecret = X25519.ComputeSharedSecret(aliceStaticPrivateKey, remoteEphemeralPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Clear Bob's ephemeral key (no longer needed)
            Array.Clear(remoteEphemeralPublicKey, 0, remoteEphemeralPublicKey.Length);

            // Encrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);  // nonce resets to 0 after new key
            var associatedData = kdf.GetHash();

            I2PCore.Utils.Logging.LogDebug($"NoiseXK Msg3Part2: key={BitConverter.ToString(key).Replace("-","").Substring(0,32)}..., AD(h)={BitConverter.ToString(associatedData).Replace("-","").Substring(0,32)}..., payloadLen={payload.Length}, nonce=0");

            var encryptedPayload = ChaCha20Poly1305.Encrypt(key, nonce, payload, associatedData);

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            // Save CK and hash BEFORE Split clears them.
            // These are needed for SipHash key derivation (NTCP2 data phase).
            PreSplitChainingKey = kdf.GetChainingKey();
            PreSplitHash = kdf.GetHash();

            // Split into data phase keys
            (sendKey, receiveKey, _) = kdf.Split();
            sendNonce = 0;
            receiveNonce = 0;

            return encryptedPayload;
        }

        /// <summary>
        /// Message 3 Part 2 (Bob receives from Alice): se, payload
        /// </summary>
        public byte[] ProcessMessage3Part2(byte[] encryptedPayload)
        {
            // se: DH(e, rs) - Bob's ephemeral with Alice's static
            var sharedSecret = X25519.ComputeSharedSecret(bobEphemeralPrivateKey, remoteStaticPublicKey);
            var key = kdf.MixKey(sharedSecret);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            // Clear Bob's ephemeral key (no longer needed)
            Array.Clear(bobEphemeralPrivateKey, 0, bobEphemeralPrivateKey.Length);
            Array.Clear(bobEphemeralPublicKey, 0, bobEphemeralPublicKey.Length);

            // Decrypt payload
            var nonce = ChaCha20Poly1305.CreateNonce(0);
            var associatedData = kdf.GetHash();
            var payload = ChaCha20Poly1305.Decrypt(key, nonce, encryptedPayload, associatedData);

            if (payload == null)
                throw new Exception("AEAD authentication failed");

            // MixHash(ciphertext)
            kdf.MixHash(encryptedPayload);

            // Save CK and hash BEFORE Split clears them (Bob side).
            PreSplitChainingKey = kdf.GetChainingKey();
            PreSplitHash = kdf.GetHash();

            // Split into data phase keys (note: reversed for Bob)
            var (k1, k2, _) = kdf.Split();
            receiveKey = k1;  // Bob receives with Alice's send key
            sendKey = k2;     // Bob sends with his own key
            sendNonce = 0;
            receiveNonce = 0;

            return payload;
        }

        /// <summary>
        /// Encrypt data in data phase
        /// </summary>
        public byte[] EncryptData(byte[] plaintext)
        {
            if (sendKey == null)
                throw new InvalidOperationException("Handshake not complete");

            // NTCP2/SSU2 spec: Maximum nonce value is 2^64 - 2
            // Value 2^64 - 1 must never be sent
            // Connection must be dropped well before reaching this limit
            const ulong MAX_NONCE = ulong.MaxValue - 1;
            if (sendNonce >= MAX_NONCE)
                throw new InvalidOperationException("Nonce limit reached - session must be terminated and rekeyed");

            var nonce = ChaCha20Poly1305.CreateNonce(sendNonce++);

            // Data phase: AD must be zero-length (spec lines 167-171, 1269-1270)
            return ChaCha20Poly1305.Encrypt(sendKey, nonce, plaintext, Array.Empty<byte>());
        }

        /// <summary>
        /// Decrypt data in data phase
        /// </summary>
        public byte[] DecryptData(byte[] ciphertext)
        {
            if (receiveKey == null)
                throw new InvalidOperationException("Handshake not complete");

            // NTCP2/SSU2 spec: Maximum nonce value is 2^64 - 2
            const ulong MAX_NONCE = ulong.MaxValue - 1;
            if (receiveNonce >= MAX_NONCE)
                throw new InvalidOperationException("Nonce limit reached - session must be terminated");

            var nonce = ChaCha20Poly1305.CreateNonce(receiveNonce++);

            // Data phase: AD must be zero-length (spec lines 167-171, 1269-1270)
            return ChaCha20Poly1305.Decrypt(receiveKey, nonce, ciphertext, Array.Empty<byte>());
        }

        // ---- ML-KEM Post-Quantum Hybrid Support ----
        // These methods provide low-level Noise AEAD encrypt/decrypt operations
        // that can be inserted between the standard XK handshake steps.
        //
        // NTCP2 with ML-KEM (versions 3-5):
        //   Message 1: e, es, [encrypt(e1_kem_key)], encrypt(options)
        //   Message 2: e, ee, [encrypt(ekem_ciphertext), MixKey(kem_ss)], encrypt(options)
        //
        // The ML-KEM shared secret is mixed into the KDF so that even if X25519
        // is broken by a quantum computer, the session remains secure.

        // Track nonce for multi-step encryption within a single handshake message
        private ulong handshakeNonce;

        /// <summary>
        /// Perform the "e, es" step of Message 1 without encrypting payload.
        /// Returns the cipher key so the caller can do ML-KEM frame + options separately.
        /// </summary>
        public byte[] PerformMessage1EphemeralAndES()
        {
            if ( aliceEphemeralPublicKey == null || aliceEphemeralPrivateKey == null )
                throw new InvalidOperationException( "Must call GenerateEphemeralKeys first" );

            // MixHash(e)
            kdf.MixHash( aliceEphemeralPublicKey );

            // es: DH(e, rs)
            var sharedSecret = X25519.ComputeSharedSecret( aliceEphemeralPrivateKey, bobStaticPublicKey );
            var key = kdf.MixKey( sharedSecret );
            Array.Clear( sharedSecret, 0, sharedSecret.Length );

            handshakeNonce = 0;
            return key;
        }

        /// <summary>
        /// Perform the "e, es" step of Message 1 processing (Bob side) without decrypting payload.
        /// </summary>
        public byte[] PerformProcessMessage1EphemeralAndES( byte[] ephemeralKey )
        {
            if ( !X25519.IsValidPublicKey( ephemeralKey ) )
                throw new Exception( "Invalid ephemeral key" );

            remoteEphemeralPublicKey = ephemeralKey;

            // MixHash(e)
            kdf.MixHash( remoteEphemeralPublicKey );

            // es: DH(s, re)
            var sharedSecret = X25519.ComputeSharedSecret( bobStaticPrivateKey, remoteEphemeralPublicKey );
            var key = kdf.MixKey( sharedSecret );
            Array.Clear( sharedSecret, 0, sharedSecret.Length );

            handshakeNonce = 0;
            return key;
        }

        /// <summary>
        /// Encrypt a handshake payload block using the current cipher key and sequential nonce.
        /// MixHash is applied to the ciphertext. Returns encrypted data + 16-byte MAC.
        /// </summary>
        public byte[] EncryptHandshakeBlock( byte[] cipherKey, byte[] plaintext )
        {
            var nonce = ChaCha20Poly1305.CreateNonce( handshakeNonce++ );
            var ad = kdf.GetHash();
            var encrypted = ChaCha20Poly1305.Encrypt( cipherKey, nonce, plaintext, ad );
            kdf.MixHash( encrypted );
            return encrypted;
        }

        /// <summary>
        /// Decrypt a handshake payload block using the current cipher key and sequential nonce.
        /// MixHash is applied to the ciphertext. Returns decrypted data.
        /// </summary>
        public byte[] DecryptHandshakeBlock( byte[] cipherKey, byte[] ciphertext )
        {
            var nonce = ChaCha20Poly1305.CreateNonce( handshakeNonce++ );
            var ad = kdf.GetHash();
            var plaintext = ChaCha20Poly1305.Decrypt( cipherKey, nonce, ciphertext, ad );
            if ( plaintext == null )
                throw new Exception( "Handshake block AEAD authentication failed" );
            kdf.MixHash( ciphertext );
            return plaintext;
        }

        /// <summary>
        /// Mix a post-quantum shared secret into the KDF.
        /// Called after ML-KEM encapsulation/decapsulation on both sides.
        /// Returns the new cipher key.
        /// </summary>
        public byte[] MixKeyPQ( byte[] kemSharedSecret )
        {
            var key = kdf.MixKey( kemSharedSecret );
            handshakeNonce = 0; // Reset nonce for next frame (spec Message 2 lines 541-543)
            return key;
        }

        /// <summary>
        /// Perform "e, ee" step of Message 2 (Bob side) without encrypting payload.
        /// Returns the cipher key.
        /// </summary>
        public byte[] PerformMessage2EphemeralAndEE()
        {
            var (ephemeralPriv, ephemeralPub) = X25519.GenerateKeyPair();
            bobEphemeralPrivateKey = ephemeralPriv;
            bobEphemeralPublicKey = ephemeralPub;

            kdf.MixHash( bobEphemeralPublicKey );

            var sharedSecret = X25519.ComputeSharedSecret( bobEphemeralPrivateKey, remoteEphemeralPublicKey );
            var key = kdf.MixKey( sharedSecret );
            Array.Clear( sharedSecret, 0, sharedSecret.Length );

            handshakeNonce = 0;
            return key;
        }

        /// <summary>
        /// Get Bob's ephemeral public key (after PerformMessage2EphemeralAndEE).
        /// </summary>
        public byte[] GetBobEphemeralPublicKey() => bobEphemeralPublicKey;

        /// <summary>
        /// Perform "e, ee" step of Message 2 processing (Alice side) without decrypting payload.
        /// Returns the cipher key.
        /// </summary>
        public byte[] PerformProcessMessage2EphemeralAndEE( byte[] ephemeralKey )
        {
            if ( !X25519.IsValidPublicKey( ephemeralKey ) )
                throw new Exception( "Invalid ephemeral key" );

            remoteEphemeralPublicKey = ephemeralKey;

            kdf.MixHash( remoteEphemeralPublicKey );

            var sharedSecret = X25519.ComputeSharedSecret( aliceEphemeralPrivateKey, remoteEphemeralPublicKey );
            var key = kdf.MixKey( sharedSecret );
            Array.Clear( sharedSecret, 0, sharedSecret.Length );

            handshakeNonce = 0;
            return key;
        }

        /// <summary>
        /// Store the message 2 cipher key for Message 3 Part 1.
        /// Must be called after encrypting/decrypting Message 2 payload.
        /// </summary>
        public void StoreMessage2CipherKey( byte[] key )
        {
            message2CipherKey = new byte[key.Length];
            Array.Copy( key, message2CipherKey, key.Length );
        }

        /// <summary>
        /// Get current hash (for additional key derivation, e.g., SipHash keys)
        /// </summary>
        public byte[] GetHandshakeHash()
        {
            return kdf.GetHash();
        }

        /// <summary>
        /// Get chaining key (for NTCP2 SipHash derivation)
        /// </summary>
        public byte[] GetChainingKey()
        {
            return kdf.GetChainingKey();
        }

        // Saved before Split() clears the CK, for SipHash key derivation
        private byte[] PreSplitChainingKey;
        private byte[] PreSplitHash;

        /// <summary>
        /// Get the chaining key as it was before Split() cleared it.
        /// Required for NTCP2 SipHash key derivation which uses the original CK.
        /// </summary>
        public byte[] GetPreSplitChainingKey() => PreSplitChainingKey;

        /// <summary>
        /// Get the hash as it was right before Split().
        /// </summary>
        public byte[] GetPreSplitHash() => PreSplitHash;

        /// <summary>
        /// Get Alice's ephemeral public key (for AES state calculation)
        /// </summary>
        public byte[] GetAliceEphemeralPublicKey()
        {
            return aliceEphemeralPublicKey;
        }

        /// <summary>
        /// Get remote ephemeral public key (for AES state calculation)
        /// </summary>
        public byte[] GetRemoteEphemeralPublicKey()
        {
            return remoteEphemeralPublicKey;
        }

        /// <summary>
        /// MixHash padding data (for NTCP2 spec lines 586-596, 829-835)
        /// Padding must be MixHashed after sending Messages 1 and 2
        /// </summary>
        public void MixHash(byte[] data)
        {
            kdf.MixHash(data ?? Array.Empty<byte>());
        }

        /// <summary>
        /// Split chaining key into send/receive keys for data phase
        /// Per Noise spec, Split() generates two keys k1 and k2
        /// For Alice (initiator): k1 = sendKey (k_ab), k2 = receiveKey (k_ba)
        /// For Bob (responder): k1 = receiveKey (k_ab), k2 = sendKey (k_ba)
        /// </summary>
        /// <param name="isInitiator">True if Alice, false if Bob</param>
        public void Split(bool isInitiator)
        {
            var (k1, k2, _) = kdf.Split();

            if (isInitiator)
            {
                // Alice: k1 for sending (k_ab), k2 for receiving (k_ba)
                sendKey = k1;
                receiveKey = k2;
            }
            else
            {
                // Bob: k1 for receiving (k_ab), k2 for sending (k_ba)
                receiveKey = k1;
                sendKey = k2;
            }

            // Reset nonces for data phase
            sendNonce = 0;
            receiveNonce = 0;
        }

        /// <summary>
        /// Get send key (for SSU2 data phase header key derivation)
        /// </summary>
        public byte[] GetSendKey()
        {
            if (sendKey == null)
                throw new InvalidOperationException("Send key not available. Call Split() first.");

            var result = new byte[sendKey.Length];
            Array.Copy(sendKey, result, sendKey.Length);
            return result;
        }

        /// <summary>
        /// Get receive key (for SSU2 data phase header key derivation)
        /// </summary>
        public byte[] GetReceiveKey()
        {
            if (receiveKey == null)
                throw new InvalidOperationException("Receive key not available. Call Split() first.");

            var result = new byte[receiveKey.Length];
            Array.Copy(receiveKey, result, receiveKey.Length);
            return result;
        }

        /// <summary>
        /// Clear all sensitive key material
        /// </summary>
        public void Clear()
        {
            ClearArray(aliceStaticPrivateKey);
            ClearArray(aliceEphemeralPrivateKey);
            ClearArray(aliceEphemeralPublicKey);
            ClearArray(bobStaticPrivateKey);
            ClearArray(bobEphemeralPrivateKey);
            ClearArray(bobEphemeralPublicKey);
            ClearArray(remoteStaticPublicKey);
            ClearArray(remoteEphemeralPublicKey);
            ClearArray(sendKey);
            ClearArray(receiveKey);
            ClearArray(message2CipherKey);
        }

        private void ClearArray(byte[] array)
        {
            if (array != null)
                Array.Clear(array, 0, array.Length);
        }
    }
}
