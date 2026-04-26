using System;
using System.Security.Cryptography;
using I2PCore.Utils;

namespace I2PCore.Crypto.Noise;

/// <summary>
///     Base class for Noise Protocol implementations
///     Provides shared utilities for MixHash, MixKey, and protocol initialization
///     Noise Protocol Framework: http://noiseprotocol.org/noise.html
///     Used in ECIES-X25519-AEAD-Ratchet, NTCP2, SSU2, and tunnel building
/// </summary>
public abstract class NoiseProtocol
{
    protected byte[] chainingKey;
    protected byte[] encryptionKey;
    protected byte[] hash;
    protected ulong nonce;

    public byte[] ChainingKey => (byte[])chainingKey?.Clone();
    public byte[] Hash => (byte[])hash?.Clone();
    public byte[] EncryptionKey => (byte[])encryptionKey?.Clone();
    public ulong Nonce => nonce;

    /// <summary>
    ///     Initialize the Noise protocol with a protocol name
    ///     Sets both h and ck to the protocol name (padded or hashed to 32 bytes)
    /// </summary>
    protected void InitializeProtocol(string protocolName)
    {
        var h = HKDF.InitializeProtocol(protocolName);
        hash = new byte[32];
        chainingKey = new byte[32];
        Array.Copy(h, hash, 32);
        Array.Copy(h, chainingKey, 32);
        nonce = 0;

        // Standard Noise: MixHash(empty prologue).
        // NoiseN (tunnels) and NoiseXK (NTCP2/SSU2) need this.
        // NoiseIK (ECIES-Ratchet) must skip it — handled in NoiseIK constructor.
        MixHash(Array.Empty<byte>());
    }

    /// <summary>
    ///     MixHash(data) - Mix data into the running hash
    ///     h = SHA256(h || data)
    /// </summary>
    public void MixHash(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        using (var sha256 = SHA256.Create())
        {
            var combined = new byte[hash.Length + data.Length];
            Array.Copy(hash, 0, combined, 0, hash.Length);
            Array.Copy(data, 0, combined, hash.Length, data.Length);
            hash = sha256.ComputeHash(combined);
        }
    }

    /// <summary>
    ///     MixKey(inputKeyMaterial) - Mix key material into the chaining key
    ///     Updates both the chaining key and the encryption key
    ///     (ck, k) = HKDF(ck, ikm, "", 64)
    /// </summary>
    protected void MixKey(byte[] inputKeyMaterial)
    {
        if (inputKeyMaterial == null)
            throw new ArgumentNullException(nameof(inputKeyMaterial));

        var (newChainingKey, newEncryptionKey) = HKDF.DeriveChainAndKey(chainingKey, inputKeyMaterial);

        chainingKey = newChainingKey;
        encryptionKey = newEncryptionKey;
        nonce = 0; // Reset nonce after key change
    }

    /// <summary>
    ///     EncryptAndHash(plaintext) - Encrypt data and mix ciphertext into hash
    /// </summary>
    protected byte[] EncryptAndHash(byte[] plaintext)
    {
        if (encryptionKey == null)
            throw new InvalidOperationException("Encryption key not initialized");

        var nonceBytes = ChaCha20Poly1305.CreateNonce(nonce);
        var ciphertext = ChaCha20Poly1305.Encrypt(encryptionKey, nonceBytes, plaintext, hash);

        nonce++;
        MixHash(ciphertext);

        return ciphertext;
    }

    /// <summary>
    ///     DecryptAndHash(ciphertext) - Decrypt data and mix ciphertext into hash
    /// </summary>
    protected byte[] DecryptAndHash(byte[] ciphertext)
    {
        if (encryptionKey == null)
            throw new InvalidOperationException("Encryption key not initialized");

        var nonceBytes = ChaCha20Poly1305.CreateNonce(nonce);
        var plaintext = ChaCha20Poly1305.Decrypt(encryptionKey, nonceBytes, ciphertext, hash);

        if (plaintext == null)
            throw new CryptographicException("Decryption failed - authentication error");

        nonce++;
        MixHash(ciphertext);

        return plaintext;
    }

    /// <summary>
    ///     Split() - Derive final transport keys from the handshake
    ///     Returns (sendKey, receiveKey) for data phase encryption
    /// </summary>
    protected (byte[] sendKey, byte[] receiveKey, byte[] ck) Split()
    {
        // Final chaining key for I2P ECIES (Proposal 144)
        var ck = (byte[])chainingKey.Clone();

        var output = HKDF.DeriveKey(chainingKey, Array.Empty<byte>(), Array.Empty<byte>(), 64);

        var sendKey = new byte[32];
        var receiveKey = new byte[32];

        Array.Copy(output, 0, sendKey, 0, 32);
        Array.Copy(output, 32, receiveKey, 0, 32);

        return (sendKey, receiveKey, ck);
    }

    /// <summary>
    ///     Clear sensitive key material
    /// </summary>
    protected void ClearKeys()
    {
        if (chainingKey != null) Array.Clear(chainingKey, 0, chainingKey.Length);
        if (hash != null) Array.Clear(hash, 0, hash.Length);
        if (encryptionKey != null) Array.Clear(encryptionKey, 0, encryptionKey.Length);
    }
}

/// <summary>
///     Noise handshake state for message processing
/// </summary>
public class NoiseHandshakeState : NoiseProtocol
{
    public byte[] LocalStaticPrivateKey { get; set; }
    public byte[] LocalStaticPublicKey { get; set; }
    public byte[] LocalEphemeralPrivateKey { get; set; }
    public byte[] LocalEphemeralPublicKey { get; set; }

    public byte[] RemoteStaticPublicKey { get; set; }
    public byte[] RemoteEphemeralPublicKey { get; set; }

    /// <summary>
    ///     Initialize handshake with protocol name
    /// </summary>
    public void Initialize(string protocolName)
    {
        InitializeProtocol(protocolName);
    }

    /// <summary>
    ///     Mix the hash of null prologue (standard Noise initialization)
    ///     h = SHA256(h)
    /// </summary>
    public void MixHashNullPrologue()
    {
        using (var sha256 = SHA256.Create())
        {
            hash = sha256.ComputeHash(hash);
        }
    }

    /// <summary>
    ///     Process "e" pattern - generate ephemeral key and mix it
    /// </summary>
    public void GenerateEphemeralKey()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        LocalEphemeralPrivateKey = privateKey;
        LocalEphemeralPublicKey = publicKey;
        MixHash(publicKey);
    }

    /// <summary>
    ///     Process "e" pattern with Elligator2 encoding (for ECIES Ratchet stealth)
    ///     Java I2P: writeMessage writes decoded public key, MixHash(decoded),
    ///     then ECIESAEADEngine overwrites output with Elligator2-encoded form for wire.
    /// </summary>
    public byte[] GenerateEphemeralKeyElligator2()
    {
        LocalEphemeralPrivateKey = Elligator2.GenerateEncodablePrivateKey();
        LocalEphemeralPublicKey = X25519.GetPublicKey(LocalEphemeralPrivateKey);

        var encoded = Elligator2.Encode(LocalEphemeralPublicKey);

        // Self-test: verify Elligator2 round-trip
        var decoded = Elligator2.Decode(encoded);
        if (decoded == null || !decoded.AsSpan().SequenceEqual(LocalEphemeralPublicKey))
        {
            Logging.LogCritical($"ECIES-DIAG: Elligator2 ROUND-TRIP FAILED! " +
                $"original[0:4]={BitConverter.ToString(LocalEphemeralPublicKey, 0, 4)} " +
                $"decoded={( decoded != null ? BitConverter.ToString(decoded, 0, 4) : "NULL" )}");
        }
        else
        {
            Logging.LogDebug($"ECIES-DIAG: Elligator2 round-trip OK");
        }

        MixHash(LocalEphemeralPublicKey); // MixHash the DECODED key, matching Java I2P

        return encoded;
    }

    /// <summary>
    ///     Process received "e" pattern - decode and mix remote ephemeral key
    /// </summary>
    public void ReceiveEphemeralKey(byte[] ephemeralKey)
    {
        RemoteEphemeralPublicKey = ephemeralKey;
        MixHash(ephemeralKey);
    }

    /// <summary>
    ///     Process received "e" pattern with Elligator2 decoding.
    ///     Java I2P: ECIESAEADEngine.decryptNewSession decodes Elligator2 in-place
    ///     BEFORE calling state.readMessage, so MixHash sees the decoded X25519 key.
    /// </summary>
    public void ReceiveEphemeralKeyElligator2(byte[] encodedKey)
    {
        var decodedKey = Elligator2.Decode(encodedKey);
        RemoteEphemeralPublicKey = decodedKey;
        MixHash(decodedKey); // MixHash the DECODED key, matching Java I2P
    }

    /// <summary>
    ///     Process "s" pattern - encrypt and send static key
    /// </summary>
    public byte[] SendStaticKey()
    {
        if (LocalStaticPublicKey == null)
            throw new InvalidOperationException("Local static key not set");

        return EncryptAndHash(LocalStaticPublicKey);
    }

    /// <summary>
    ///     Process received "s" pattern - decrypt static key
    /// </summary>
    public void ReceiveStaticKey(byte[] encryptedKey)
    {
        RemoteStaticPublicKey = DecryptAndHash(encryptedKey);
    }

    /// <summary>
    ///     Process "es" pattern - ephemeral-static DH
    /// </summary>
    public void PerformES(bool isInitiator)
    {
        byte[] sharedSecret;

        if (isInitiator)
            // Alice: DH(e_local, s_remote)
            sharedSecret = X25519.ComputeSharedSecret(
                LocalEphemeralPrivateKey,
                RemoteStaticPublicKey);
        else
            // Bob: DH(s_local, e_remote)
            sharedSecret = X25519.ComputeSharedSecret(
                LocalStaticPrivateKey,
                RemoteEphemeralPublicKey);

        MixKey(sharedSecret);
        Array.Clear(sharedSecret, 0, sharedSecret.Length);
    }

    /// <summary>
    ///     Process "ee" pattern - ephemeral-ephemeral DH
    /// </summary>
    public void PerformEE()
    {
        var sharedSecret = X25519.ComputeSharedSecret(
            LocalEphemeralPrivateKey,
            RemoteEphemeralPublicKey);

        MixKey(sharedSecret);
        Array.Clear(sharedSecret, 0, sharedSecret.Length);
    }

    /// <summary>
    ///     Process "ss" pattern - static-static DH
    /// </summary>
    public void PerformSS()
    {
        var sharedSecret = X25519.ComputeSharedSecret(
            LocalStaticPrivateKey,
            RemoteStaticPublicKey);

        MixKey(sharedSecret);
        Array.Clear(sharedSecret, 0, sharedSecret.Length);
    }

    /// <summary>
    ///     Process "se" pattern - static-ephemeral DH
    /// </summary>
    public void PerformSE(bool isInitiator)
    {
        byte[] sharedSecret;

        if (isInitiator)
            // Alice: DH(s_local, e_remote)
            sharedSecret = X25519.ComputeSharedSecret(
                LocalStaticPrivateKey,
                RemoteEphemeralPublicKey);
        else
            // Bob: DH(e_local, s_remote)
            sharedSecret = X25519.ComputeSharedSecret(
                LocalEphemeralPrivateKey,
                RemoteStaticPublicKey);

        MixKey(sharedSecret);
        Array.Clear(sharedSecret, 0, sharedSecret.Length);
    }

    /// <summary>
    ///     Encrypt payload
    /// </summary>
    public byte[] EncryptPayload(byte[] payload)
    {
        return EncryptAndHash(payload);
    }

    /// <summary>
    ///     Decrypt payload
    /// </summary>
    public byte[] DecryptPayload(byte[] encryptedPayload)
    {
        return DecryptAndHash(encryptedPayload);
    }

    /// <summary>
    ///     Finalize handshake and get transport keys
    /// </summary>
    public (byte[] sendKey, byte[] receiveKey, byte[] ck, byte[] h) FinalizeHandshake()
    {
        var (send, recv, ck) = Split();
        return (send, recv, ck, (byte[])hash.Clone());
    }
}