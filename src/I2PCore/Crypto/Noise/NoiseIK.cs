using System;
using I2PCore.Utils;

namespace I2PCore.Crypto.Noise;

/// <summary>
///     Noise IK (interactive handshake) pattern implementation
///     Used for ECIES-X25519-AEAD-Ratchet (destination-to-destination encryption)
///     Pattern:
///     <- s ( Bob's static key known in advance)
///   -> e, es, s, ss, payload (New Session)
///   
///     <- tag, e, ee, se, payload ( New Session Reply)
///         Alice ( initiator) reveals her static key immediately
///         Bob's (responder) static key is known in advance
/// Provides mutual authentication and forward secrecy after message 2
/// 
/// </summary>
public class NoiseIK
{
    // Must match Java I2P: HandshakeState.protocolName2
    // "elg2" = Elligator2 ephemeral key encoding, "hs2" = handshake separation variant
    private const string ProtocolName = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256";
    private readonly bool isInitiator;

    private readonly NoiseHandshakeState state;
    private byte[] replyTag; // 8-byte tag for New Session Reply

    private NoiseIK(
        bool isInitiator,
        byte[] localStaticPrivateKey,
        byte[] localStaticPublicKey,
        byte[] remoteStaticPublicKey = null)
    {
        this.isInitiator = isInitiator;
        state = new NoiseHandshakeState();
        state.Initialize(ProtocolName);
        // Java I2P precomputes MixHash(empty prologue) in SymmetricState's
        // static initializer. Our InitializeProtocol() already does this.

        if (localStaticPrivateKey == null || localStaticPrivateKey.Length != 32)
            throw new ArgumentException("Local static private key required and must be 32 bytes");

        if (localStaticPublicKey == null || localStaticPublicKey.Length != 32)
            throw new ArgumentException("Local static public key required and must be 32 bytes");

        state.LocalStaticPrivateKey = localStaticPrivateKey;
        state.LocalStaticPublicKey = localStaticPublicKey;

        if (isInitiator)
        {
            if (remoteStaticPublicKey == null || remoteStaticPublicKey.Length != 32)
                throw new ArgumentException("Remote static public key required for initiator");

            state.RemoteStaticPublicKey = remoteStaticPublicKey;

            // <- s (MixHash of Bob's static key)
            state.MixHash(remoteStaticPublicKey);
        }
        else
        {
            // <- s (MixHash of own static key)
            state.MixHash(localStaticPublicKey);
        }
    }

    /// <summary>
    ///     Create a Noise IK initiator (Alice - sends New Session)
    /// </summary>
    public static NoiseIK CreateInitiator(
        byte[] localStaticPrivateKey,
        byte[] localStaticPublicKey,
        byte[] remoteStaticPublicKey)
    {
        return new NoiseIK(
            true,
            localStaticPrivateKey,
            localStaticPublicKey,
            remoteStaticPublicKey);
    }

    /// <summary>
    ///     Create a Noise IK responder (Bob - receives New Session)
    /// </summary>
    public static NoiseIK CreateResponder(
        byte[] localStaticPrivateKey,
        byte[] localStaticPublicKey)
    {
        return new NoiseIK(
            false,
            localStaticPrivateKey,
            localStaticPublicKey);
    }

    /// <summary>
    ///     Create New Session message (initiator only)
    ///     -> e, es, s, ss, payload
    ///     Returns: encodedEphemeralKey (32) || encryptedStaticKey (32+16) || encryptedPayload (len+16)
    ///     Note: Ephemeral key is Elligator2 encoded for stealth
    /// </summary>
    public byte[] CreateNewSessionMessage(byte[] payload)
    {
        if (!isInitiator)
            throw new InvalidOperationException("Only initiator can create New Session message");

        if (payload == null)
            payload = Array.Empty<byte>();

        Logging.LogDebug($"NoiseIK-DIAG: pre-e h[0:8]={BitConverter.ToString(state.Hash, 0, 8)} " +
            $"ck[0:8]={BitConverter.ToString(state.ChainingKey, 0, 8)}");

        // -> e (with Elligator2 encoding)
        var encodedEphemeralKey = state.GenerateEphemeralKeyElligator2();

        Logging.LogDebug($"NoiseIK-DIAG: post-e h[0:8]={BitConverter.ToString(state.Hash, 0, 8)} " +
            $"epk_decoded[0:4]={BitConverter.ToString(state.LocalEphemeralPublicKey, 0, 4)} " +
            $"epk_encoded[0:4]={BitConverter.ToString(encodedEphemeralKey, 0, 4)}");

        // -> es (ephemeral-static DH with Bob's key)
        state.PerformES(true);

        Logging.LogDebug($"NoiseIK-DIAG: post-es h[0:8]={BitConverter.ToString(state.Hash, 0, 8)} " +
            $"ck[0:8]={BitConverter.ToString(state.ChainingKey, 0, 8)} " +
            $"k[0:4]={BitConverter.ToString(state.EncryptionKey, 0, 4)}");

        // -> s (Alice's static key, encrypted)
        var encryptedStaticKey = state.SendStaticKey();

        Logging.LogDebug($"NoiseIK-DIAG: post-s h[0:8]={BitConverter.ToString(state.Hash, 0, 8)} " +
            $"encS[0:4]={BitConverter.ToString(encryptedStaticKey, 0, 4)} encS.len={encryptedStaticKey.Length}");

        // -> ss (static-static DH)
        state.PerformSS();

        Logging.LogDebug($"NoiseIK-DIAG: post-ss h[0:8]={BitConverter.ToString(state.Hash, 0, 8)} " +
            $"ck[0:8]={BitConverter.ToString(state.ChainingKey, 0, 8)} " +
            $"k[0:4]={BitConverter.ToString(state.EncryptionKey, 0, 4)}");

        // -> payload
        var encryptedPayload = state.EncryptPayload(payload);

        // Combine all parts
        var totalLength = encodedEphemeralKey.Length + encryptedStaticKey.Length + encryptedPayload.Length;
        var message = new byte[totalLength];
        var offset = 0;

        Array.Copy(encodedEphemeralKey, 0, message, offset, encodedEphemeralKey.Length);
        offset += encodedEphemeralKey.Length;

        Array.Copy(encryptedStaticKey, 0, message, offset, encryptedStaticKey.Length);
        offset += encryptedStaticKey.Length;

        Array.Copy(encryptedPayload, 0, message, offset, encryptedPayload.Length);

        return message;
    }

    /// <summary>
    ///     Process New Session message (responder only)
    ///     -> e, es, s, ss, payload
    ///     Input: encodedEphemeralKey (32) || encryptedStaticKey (48) || encryptedPayload
    ///     Returns: (decrypted payload, Alice's static public key)
    /// </summary>
    public (byte[] payload, byte[] remoteStaticPublicKey) ProcessNewSessionMessage(byte[] message)
    {
        if (isInitiator)
            throw new InvalidOperationException("Only responder can process New Session message");

        if (message == null || message.Length < 32 + 48 + 16)
            throw new ArgumentException("Message too short");

        var offset = 0;

        // -> e (Elligator2 encoded)
        var encodedEphemeralKey = new byte[32];
        Array.Copy(message, offset, encodedEphemeralKey, 0, 32);
        offset += 32;
        state.ReceiveEphemeralKeyElligator2(encodedEphemeralKey);

        // -> es
        state.PerformES(false);

        // -> s (Alice's static key, encrypted)
        var encryptedStaticKeyLength = 48; // 32 + 16 (MAC)
        var encryptedStaticKey = new byte[encryptedStaticKeyLength];
        Array.Copy(message, offset, encryptedStaticKey, 0, encryptedStaticKeyLength);
        offset += encryptedStaticKeyLength;
        state.ReceiveStaticKey(encryptedStaticKey);

        // -> ss
        state.PerformSS();

        // -> payload
        var encryptedPayloadLength = message.Length - offset;
        var encryptedPayload = new byte[encryptedPayloadLength];
        Array.Copy(message, offset, encryptedPayload, 0, encryptedPayloadLength);
        var payload = state.DecryptPayload(encryptedPayload);

        return (payload, state.RemoteStaticPublicKey);
    }

    /// <summary>
    ///     Create New Session Reply message (responder only)
    ///     Java I2P "hs2" format:
    ///       tag(8) || elligator2_ephemeral(32) || handshake_MAC(16) || encrypted_payload
    ///     The handshake MAC is from encrypting empty data after e,ee,se.
    ///     Then split() derives transport keys, and the payload is encrypted
    ///     with a key derived via HKDF(k_ba, "AttachPayloadKDF"), using the
    ///     handshake hash as associated data.
    /// </summary>
    public byte[] CreateNewSessionReplyMessage(byte[] replyTag, byte[] payload)
    {
        if (isInitiator)
            throw new InvalidOperationException("Only responder can create New Session Reply");

        if (replyTag == null || replyTag.Length != 8)
            throw new ArgumentException("Reply tag must be 8 bytes");

        if (payload == null)
            payload = Array.Empty<byte>();

        this.replyTag = replyTag;

        // Java I2P: mixHash(tag) before writeMessage (ECIESAEADEngine.java:1262)
        state.MixHash(replyTag);

        // <- e (with Elligator2 encoding, matching Java ECIESAEADEngine.java:1287-1293)
        var encodedEphemeralKey = state.GenerateEphemeralKeyElligator2();

        // <- ee (ephemeral-ephemeral DH)
        state.PerformEE();

        // <- se (static-ephemeral DH)
        state.PerformSE(false);

        // Encrypt empty data to produce handshake MAC (Java writeMessage with ZEROLEN payload)
        var emptyMac = state.EncryptPayload(Array.Empty<byte>());

        // Split to derive transport keys (Java: state.split() after writeMessage)
        var (key1, key2, ck, handshakeHash) = state.FinalizeHandshake();
        // Responder: sendKey = key2 = k_ba, receiveKey = key1 = k_ab
        var k_ba = key2;

        // Derive payload encryption key (Java: INFO_6 = "AttachPayloadKDF")
        var payloadKey = HKDF.DeriveKey(k_ba, Array.Empty<byte>(),
            System.Text.Encoding.ASCII.GetBytes("AttachPayloadKDF"), 32);

        // Encrypt payload with derived key, handshake hash as AD
        var nonce = ChaCha20Poly1305.CreateNonce(0);
        var encryptedPayload = ChaCha20Poly1305.Encrypt(payloadKey, nonce, payload, handshakeHash);

        // Combine: replyTag || encodedEphemeralKey || emptyMac || encryptedPayload
        var message = new byte[8 + 32 + emptyMac.Length + encryptedPayload.Length];
        Array.Copy(replyTag, 0, message, 0, 8);
        Array.Copy(encodedEphemeralKey, 0, message, 8, 32);
        Array.Copy(emptyMac, 0, message, 40, emptyMac.Length);
        Array.Copy(encryptedPayload, 0, message, 40 + emptyMac.Length, encryptedPayload.Length);

        return message;
    }

    /// <summary>
    ///     Process New Session Reply message (initiator only)
    ///     Java I2P "hs2" format:
    ///       tag(8) || elligator2_ephemeral(32) || handshake_MAC(16) || encrypted_payload
    ///     Returns: (decrypted payload, reply tag)
    /// </summary>
    public (byte[] payload, byte[] replyTag) ProcessNewSessionReplyMessage(byte[] message)
    {
        if (!isInitiator)
            throw new InvalidOperationException("Only initiator can process New Session Reply");

        if (message == null || message.Length < 8 + 32 + 16 + 16)
            throw new ArgumentException("Message too short");

        // Extract reply tag
        var replyTag = new byte[8];
        Array.Copy(message, 0, replyTag, 0, 8);

        // Extract ephemeral key (Elligator2 encoded)
        var encodedEphemeralKey = new byte[32];
        Array.Copy(message, 8, encodedEphemeralKey, 0, 32);

        // Extract handshake MAC (empty section, 16 bytes)
        var emptyMac = new byte[16];
        Array.Copy(message, 40, emptyMac, 0, 16);

        // Extract encrypted payload (after tag + ephemeral + emptyMac)
        var encryptedPayload = new byte[message.Length - 56];
        Array.Copy(message, 56, encryptedPayload, 0, encryptedPayload.Length);

        // Java I2P: mixHash(tag) before readMessage (ECIESAEADEngine.java:812)
        state.MixHash(replyTag);

        // <- e (with Elligator2 decoding, MixHash decoded key)
        state.ReceiveEphemeralKeyElligator2(encodedEphemeralKey);

        // <- ee
        state.PerformEE();

        // <- se
        state.PerformSE(true);

        // Decrypt empty section (verify handshake MAC)
        state.DecryptPayload(emptyMac);

        // Split to derive transport keys
        var (key1, key2, ck, handshakeHash) = state.FinalizeHandshake();
        // Initiator: sendKey = key1 = k_ab, receiveKey = key2 = k_ba
        var k_ba = key2;

        // Derive payload decryption key (Java: INFO_6 = "AttachPayloadKDF")
        var payloadKey = HKDF.DeriveKey(k_ba, Array.Empty<byte>(),
            System.Text.Encoding.ASCII.GetBytes("AttachPayloadKDF"), 32);

        // Decrypt payload with derived key, handshake hash as AD
        var nonce = ChaCha20Poly1305.CreateNonce(0);
        var payload = ChaCha20Poly1305.Decrypt(payloadKey, nonce, encryptedPayload, handshakeHash);

        if (payload == null)
            throw new System.Security.Cryptography.CryptographicException("NSR payload decryption failed");

        return (payload, replyTag);
    }

    /// <summary>
    ///     Finalize handshake and derive transport keys for data phase
    ///     Call after completing the handshake
    /// </summary>
    public (byte[] sendKey, byte[] receiveKey, byte[] ck) FinalizeHandshake()
    {
        var (key1, key2, ck, h) = state.FinalizeHandshake();

        // Initiator sends with key1, receives with key2
        // Responder sends with key2, receives with key1
        return isInitiator ? (key1, key2, ck) : (key2, key1, ck);
    }

    /// <summary>
    ///     Get the handshake hash for additional operations
    /// </summary>
    public byte[] GetHandshakeHash()
    {
        return (byte[])state.Hash?.Clone();
    }

    /// <summary>
    ///     Get the chaining key for ratcheting
    /// </summary>
    public byte[] GetChainingKey()
    {
        return (byte[])state.ChainingKey?.Clone();
    }

    /// <summary>
    ///     Clear sensitive key material
    /// </summary>
    public void Dispose()
    {
        if (state.LocalStaticPrivateKey != null)
            Array.Clear(state.LocalStaticPrivateKey, 0, state.LocalStaticPrivateKey.Length);
        if (state.LocalEphemeralPrivateKey != null)
            Array.Clear(state.LocalEphemeralPrivateKey, 0, state.LocalEphemeralPrivateKey.Length);
        if (replyTag != null)
            Array.Clear(replyTag, 0, replyTag.Length);
    }
}