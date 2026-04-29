using System;
using System.Buffers;
using I2PCore.Crypto.Noise;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES;

/// <summary>
///     ECIES Hybrid New Session Message with ML-KEM
///     Wire format: ephemeral_key(32) + encrypted_e1(kemPubSize+16) + encrypted_static(48) + encrypted_payload(var)
///     Uses Noise IKhfs pattern: e, es, e1, s, ss, p
///     Where e1 is the ML-KEM encap_key (public key for encapsulation)
///     ML-KEM public key sizes: 512=800, 768=1184, 1024=1568
///     ML-KEM ciphertext sizes: 512=768, 768=1088, 1024=1568
/// </summary>
public class ECIESHybridNewSessionMessage
{
    // Cleartext: Ephemeral X25519 public key (Elligator2 encoded)
    public byte[] EphemeralPublicKey { get; set; } // 32 bytes

    // Section 1: ML-KEM encap_key (e1), encrypted with ChaCha/Poly after es
    public byte[] EncryptedKEMPublicKey { get; set; } // kemPubSize+16 bytes

    // Section 2: X25519 static key (s), encrypted with ChaCha/Poly
    public byte[] EncryptedStaticKey { get; set; } // 32+16 = 48 bytes

    // Section 3: Payload (p), encrypted with ChaCha/Poly after ss
    public byte[] EncryptedPayload { get; set; } // Variable length

    /// <summary>
    ///     ML-KEM public key sizes (encap_key) by variant
    /// </summary>
    public static int GetKEMPublicKeySize(NoiseIKhfs.KEMVariant variant)
    {
        return variant switch
        {
            NoiseIKhfs.KEMVariant.MLKEM512 => 800,
            NoiseIKhfs.KEMVariant.MLKEM768 => 1184,
            NoiseIKhfs.KEMVariant.MLKEM1024 => 1568,
            _ => throw new ArgumentException($"Unknown KEM variant: {variant}")
        };
    }

    /// <summary>
    ///     ML-KEM ciphertext sizes by variant
    /// </summary>
    public static int GetKEMCiphertextSize(NoiseIKhfs.KEMVariant variant)
    {
        return variant switch
        {
            NoiseIKhfs.KEMVariant.MLKEM512 => 768,
            NoiseIKhfs.KEMVariant.MLKEM768 => 1088,
            NoiseIKhfs.KEMVariant.MLKEM1024 => 1568,
            _ => throw new ArgumentException($"Unknown KEM variant: {variant}")
        };
    }

    /// <summary>
    ///     Parse from wire format bytes
    /// </summary>
    public static ECIESHybridNewSessionMessage Parse(byte[] data, NoiseIKhfs.KEMVariant variant)
    {
        var kemPubSize = GetKEMPublicKeySize(variant);
        var encryptedKemPubSize = kemPubSize + 16; // +16 for Poly1305 MAC
        var encryptedStaticSize = 48; // 32 + 16

        var minSize = 32 + encryptedKemPubSize + encryptedStaticSize + 16; // +16 for minimum payload MAC
        if (data.Length < minSize)
            throw new ArgumentException($"Hybrid message too short: {data.Length} < {minSize}");

        var reader = new I2PBufferCursor(data);

        var msg = new ECIESHybridNewSessionMessage();
        msg.EphemeralPublicKey = reader.ReadBlock(32).ToByteArray();
        msg.EncryptedKEMPublicKey = reader.ReadBlock(encryptedKemPubSize).ToByteArray();
        msg.EncryptedStaticKey = reader.ReadBlock(encryptedStaticSize).ToByteArray();

        var remaining = data.Length - reader.BaseArrayOffset;
        msg.EncryptedPayload = reader.ReadBlock(remaining).ToByteArray();

        return msg;
    }

    /// <summary>
    ///     Serialize to wire format bytes
    /// </summary>
    public byte[] ToByteArray()
    {
        var stream = new ArrayBufferWriter<byte>();
        stream.WriteBytes(EphemeralPublicKey);
        stream.WriteBytes(EncryptedKEMPublicKey);
        stream.WriteBytes(EncryptedStaticKey);
        stream.WriteBytes(EncryptedPayload);
        return stream.WrittenSpan.ToArray();
    }

    /// <summary>
    ///     Create new hybrid session message using Noise IKhfs
    /// </summary>
    public static ECIESHybridNewSessionMessage Create(
        byte[] remoteStaticPublicKey,
        byte[] localStaticPrivate,
        byte[] localStaticPublic,
        byte[] payload,
        NoiseIKhfs.KEMVariant variant = NoiseIKhfs.KEMVariant.MLKEM512)
    {
        var noise = NoiseIKhfs.CreateInitiator(
            localStaticPrivate,
            localStaticPublic,
            remoteStaticPublicKey,
            variant);

        var (ephemeralPublic, encryptedKemPublicKey, encryptedStatic, encryptedPayload) =
            noise.WriteMessageA(payload);

        return new ECIESHybridNewSessionMessage
        {
            EphemeralPublicKey = ephemeralPublic,
            EncryptedKEMPublicKey = encryptedKemPublicKey,
            EncryptedStaticKey = encryptedStatic,
            EncryptedPayload = encryptedPayload
        };
    }

    /// <summary>
    ///     Create and return both message and noise state for processing the reply
    /// </summary>
    public static (ECIESHybridNewSessionMessage message, NoiseIKhfs noiseState) CreateWithState(
        byte[] remoteStaticPublicKey,
        byte[] localStaticPrivate,
        byte[] localStaticPublic,
        byte[] payload,
        NoiseIKhfs.KEMVariant variant = NoiseIKhfs.KEMVariant.MLKEM512)
    {
        var noise = NoiseIKhfs.CreateInitiator(
            localStaticPrivate,
            localStaticPublic,
            remoteStaticPublicKey,
            variant);

        var (ephemeralPublic, encryptedKemPublicKey, encryptedStatic, encryptedPayload) =
            noise.WriteMessageA(payload);

        var msg = new ECIESHybridNewSessionMessage
        {
            EphemeralPublicKey = ephemeralPublic,
            EncryptedKEMPublicKey = encryptedKemPublicKey,
            EncryptedStaticKey = encryptedStatic,
            EncryptedPayload = encryptedPayload
        };

        return (msg, noise);
    }

    /// <summary>
    ///     Decrypt hybrid new session message using Noise IKhfs
    ///     Returns (payload, remote_static_key, remote_kem_public_key, noise_state)
    ///     The noise_state is needed to create the reply message
    /// </summary>
    public (byte[] payload, byte[] remoteStaticKey, byte[] remoteKemPublicKey, NoiseIKhfs noiseState) DecryptWithState(
        byte[] localStaticPrivate,
        byte[] localStaticPublic,
        NoiseIKhfs.KEMVariant variant = NoiseIKhfs.KEMVariant.MLKEM512)
    {
        var noise = NoiseIKhfs.CreateResponder(
            localStaticPrivate,
            localStaticPublic,
            variant);

        var (payload, remoteStaticKey, remoteKemPublicKey) = noise.ReadMessageA(
            EphemeralPublicKey,
            EncryptedKEMPublicKey,
            EncryptedStaticKey,
            EncryptedPayload);

        return (payload, remoteStaticKey, remoteKemPublicKey, noise);
    }

    /// <summary>
    ///     Decrypt hybrid new session message (without returning noise state)
    /// </summary>
    public (byte[] payload, byte[] remoteStaticKey, byte[] remoteKemPublicKey) Decrypt(
        byte[] localStaticPrivate,
        byte[] localStaticPublic,
        NoiseIKhfs.KEMVariant variant = NoiseIKhfs.KEMVariant.MLKEM512)
    {
        var (payload, remoteStaticKey, remoteKemPublicKey, _) = DecryptWithState(
            localStaticPrivate, localStaticPublic, variant);
        return (payload, remoteStaticKey, remoteKemPublicKey);
    }
}

/// <summary>
///     ECIES Hybrid New Session Reply Message
///     Wire format: session_tag(8) + ephemeral_key(32) + encrypted_ekem1(kemCtSize+16) + empty_mac(16) +
///     encrypted_payload(var)
///     Uses Noise IKhfs pattern: tag, e, ee, ekem1, se, p
///     Where ekem1 is the ML-KEM ciphertext from ENCAPS(encap_key)
/// </summary>
public class ECIESHybridNewSessionReplyMessage
{
    // Session tag (8 bytes)
    public byte[] SessionTag { get; set; } // 8 bytes

    // Cleartext: Ephemeral X25519 public key (Elligator2 encoded)
    public byte[] EphemeralPublicKey { get; set; } // 32 bytes

    // Section 1: ML-KEM ciphertext (ekem1), encrypted with ChaCha/Poly after ee
    public byte[] EncryptedKEMCiphertext { get; set; } // kemCtSize+16 bytes

    // Section 2: Empty (for consistency with standard IK pattern)
    public byte[] EmptySectionMac { get; set; } // 16 bytes MAC only

    // Section 3: Handshake MAC (empty data after all tokens, before split)
    public byte[] HandshakeMac { get; set; } // 16 bytes MAC only

    // Section 4: Encrypted payload (with derived key after split + AttachPayloadKDF)
    public byte[] EncryptedPayload { get; set; } // Variable length

    /// <summary>
    ///     Parse from wire format bytes
    /// </summary>
    public static ECIESHybridNewSessionReplyMessage Parse(byte[] data, NoiseIKhfs.KEMVariant variant)
    {
        var kemCtSize = ECIESHybridNewSessionMessage.GetKEMCiphertextSize(variant);
        var encryptedKemCtSize = kemCtSize + 16; // +16 for Poly1305 MAC

        var minSize = 8 + 32 + encryptedKemCtSize + 16 + 16 + 16; // tag+ephemeral+ekem1+empty_mac+handshake_mac+min_payload
        if (data.Length < minSize)
            throw new ArgumentException($"Hybrid reply message too short: {data.Length} < {minSize}");

        var reader = new I2PBufferCursor(data);

        var msg = new ECIESHybridNewSessionReplyMessage();
        msg.SessionTag = reader.ReadBlock(8).ToByteArray();
        msg.EphemeralPublicKey = reader.ReadBlock(32).ToByteArray();
        msg.EncryptedKEMCiphertext = reader.ReadBlock(encryptedKemCtSize).ToByteArray();
        msg.EmptySectionMac = reader.ReadBlock(16).ToByteArray();
        msg.HandshakeMac = reader.ReadBlock(16).ToByteArray();

        var remaining = data.Length - reader.BaseArrayOffset;
        msg.EncryptedPayload = reader.ReadBlock(remaining).ToByteArray();

        return msg;
    }

    /// <summary>
    ///     Serialize to wire format bytes
    /// </summary>
    public byte[] ToByteArray()
    {
        var stream = new ArrayBufferWriter<byte>();
        stream.WriteBytes(SessionTag);
        stream.WriteBytes(EphemeralPublicKey);
        stream.WriteBytes(EncryptedKEMCiphertext);
        stream.WriteBytes(EmptySectionMac);
        stream.WriteBytes(HandshakeMac);
        stream.WriteBytes(EncryptedPayload);
        return stream.WrittenSpan.ToArray();
    }

    /// <summary>
    ///     Create hybrid new session reply using Noise IKhfs
    ///     The noise object must be from ReadMessageA that extracted the remote KEM public key
    /// </summary>
    public static ECIESHybridNewSessionReplyMessage Create(
        byte[] sessionTag,
        byte[] payload,
        NoiseIKhfs noise)
    {
        var (ephemeralPublic, encryptedKemCiphertext, emptySectionMac, handshakeMac, encryptedPayload) =
            noise.WriteMessageB(payload);

        return new ECIESHybridNewSessionReplyMessage
        {
            SessionTag = sessionTag,
            EphemeralPublicKey = ephemeralPublic,
            EncryptedKEMCiphertext = encryptedKemCiphertext,
            EmptySectionMac = emptySectionMac,
            HandshakeMac = handshakeMac,
            EncryptedPayload = encryptedPayload
        };
    }

    /// <summary>
    ///     Decrypt reply message using Noise IKhfs
    ///     The noise object must be from WriteMessageA that has the local KEM secret key
    /// </summary>
    public byte[] Decrypt(NoiseIKhfs noise)
    {
        return noise.ReadMessageB(
            EphemeralPublicKey,
            EncryptedKEMCiphertext,
            EmptySectionMac,
            HandshakeMac,
            EncryptedPayload);
    }
}

/// <summary>
///     Hybrid Session Manager for ECIES with ML-KEM
///     Manages sessions using X25519 + ML-KEM post-quantum encryption
///     Provides a wrapper around Noise IKhfs for session management
/// </summary>
public class ECIESHybridSessionManager
{
    private readonly byte[] localStaticPrivate;
    private readonly byte[] localStaticPublic;
    private readonly NoiseIKhfs.KEMVariant variant;

    public ECIESHybridSessionManager(
        byte[] localStaticPrivate,
        byte[] localStaticPublic,
        NoiseIKhfs.KEMVariant variant = NoiseIKhfs.KEMVariant.MLKEM512)
    {
        this.localStaticPrivate = localStaticPrivate;
        this.localStaticPublic = localStaticPublic;
        this.variant = variant;
    }

    /// <summary>
    ///     Create new hybrid session message to remote destination
    ///     Returns (message, noise_state) where noise_state must be saved for processing the reply
    /// </summary>
    public (ECIESHybridNewSessionMessage message, NoiseIKhfs noiseState) CreateNewSession(
        byte[] remoteStaticPublicKey,
        byte[] payload)
    {
        return ECIESHybridNewSessionMessage.CreateWithState(
            remoteStaticPublicKey,
            localStaticPrivate,
            localStaticPublic,
            payload,
            variant);
    }

    /// <summary>
    ///     Process incoming hybrid new session message from wire bytes and create reply
    /// </summary>
    public (byte[] payload, byte[] remoteStaticKey, ECIESHybridNewSessionReplyMessage reply) ProcessNewSession(
        byte[] wireData,
        byte[] sessionTag,
        byte[] replyPayload)
    {
        var message = ECIESHybridNewSessionMessage.Parse(wireData, variant);
        return ProcessNewSession(message, sessionTag, replyPayload);
    }

    /// <summary>
    ///     Process incoming hybrid new session message and create reply
    /// </summary>
    public (byte[] payload, byte[] remoteStaticKey, ECIESHybridNewSessionReplyMessage reply) ProcessNewSession(
        ECIESHybridNewSessionMessage message,
        byte[] sessionTag,
        byte[] replyPayload)
    {
        var (payload, remoteStaticKey, _, noiseState) = message.DecryptWithState(
            localStaticPrivate,
            localStaticPublic,
            variant);

        var reply = ECIESHybridNewSessionReplyMessage.Create(
            sessionTag,
            replyPayload,
            noiseState);

        return (payload, remoteStaticKey, reply);
    }

    /// <summary>
    ///     Process reply to our new session message from wire bytes
    /// </summary>
    public byte[] ProcessNewSessionReply(
        byte[] wireData,
        NoiseIKhfs noiseState)
    {
        var reply = ECIESHybridNewSessionReplyMessage.Parse(wireData, variant);
        return reply.Decrypt(noiseState);
    }

    /// <summary>
    ///     Process reply to our new session message
    /// </summary>
    public byte[] ProcessNewSessionReply(
        ECIESHybridNewSessionReplyMessage reply,
        NoiseIKhfs noiseState)
    {
        return reply.Decrypt(noiseState);
    }
}