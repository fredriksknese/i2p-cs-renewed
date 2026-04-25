using System;
using I2PCore.Crypto;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages;

/// <summary>
///     SSU2 Session Created (Handshake Message 2)
///     Noise XK pattern:
///     <- e, ee
///         Contains:
///         - Long header (32 bytes)
///         - Encrypted ephemeral key Y (32 bytes, obfuscated with ChaCha20)
///         - Encrypted payload ( variable)
/// </summary>
public class SessionCreated
{
    public SessionCreated()
    {
        Header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_SESSION_CREATED,
            Version = 2,
            NetId = 2
        };
    }

    public SSU2Header Header { get; set; }
    public byte[] EphemeralKey { get; set; } // Y, 32 bytes
    public byte[] EncryptedPayload { get; set; }
    public uint Timestamp { get; set; }
    public ushort PaddingLength { get; set; }
    public byte[] Padding { get; set; }

    public static SessionCreated Parse(I2PBufferCursor data, byte[] bobIntroKey, byte[] chainingKey, byte[] fullPacket)
    {
        var created = new SessionCreated();

        // For Session Created (Alice receives):
        // k_header_1 = bik (Bob's intro key)
        // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
        // SSU2 spec lines 1255-1270
        var kHeader1 = bobIntroKey;
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);

        // Decrypt header in place using IVs from packet end
        SSU2HeaderEncryption.DecryptLongHeaderInPacket(fullPacket, 0, kHeader1, kHeader2);

        // Parse decrypted header from packet
        created.Header = SSU2Header.ParseLongHeader(new I2PBufferCursor(fullPacket));

        // Decrypt ephemeral key Y (obfuscated with ChaCha20)
        var encryptedY = new byte[32];
        Array.Copy(fullPacket, 32, encryptedY, 0, 32);
        created.EphemeralKey = SSU2HeaderEncryption.DeobfuscateEphemeralKey(encryptedY, kHeader2);

        // Read encrypted payload (rest of packet)
        var remaining = fullPacket.Length - 64;
        created.EncryptedPayload = new byte[remaining];
        Array.Copy(fullPacket, 64, created.EncryptedPayload, 0, remaining);

        return created;
    }

    public byte[] ToByteArray(byte[] bobIntroKey, byte[] chainingKey, byte[] ephemeralKey, byte[] encryptedPayload)
    {
        // For Session Created (Bob sends):
        // k_header_1 = bik (Bob's intro key)
        // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
        // SSU2 spec lines 1255-1270
        var kHeader1 = bobIntroKey;
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);

        // Build header (plaintext first)
        var header = Header.ToByteArray();

        // Build complete packet first: header + ephKey + payload (needed for IV derivation)
        var obfuscatedY = SSU2HeaderEncryption.ObfuscateEphemeralKey(ephemeralKey, kHeader2);

        var padding = Padding ?? Array.Empty<byte>();
        var packet = new byte[header.Length + obfuscatedY.Length + encryptedPayload.Length + padding.Length];
        Array.Copy(header, 0, packet, 0, header.Length);
        Array.Copy(obfuscatedY, 0, packet, header.Length, obfuscatedY.Length);
        Array.Copy(encryptedPayload, 0, packet, header.Length + obfuscatedY.Length, encryptedPayload.Length);
        if (padding.Length > 0)
            Array.Copy(padding, 0, packet, header.Length + obfuscatedY.Length + encryptedPayload.Length,
                padding.Length);

        // Encrypt header in place using IVs from packet end
        SSU2HeaderEncryption.EncryptLongHeaderInPacket(packet, 0, kHeader1, kHeader2);

        return packet;
    }

    public byte[] BuildPayload()
    {
        // Build options block for SessionCreated payload
        var payload = new I2PByteBlock(new byte[4096]);
        var writer = new I2PBufferCursor(payload);

        // Timestamp (4 bytes)
        writer.WriteUInt32BigEndian(Timestamp);

        // Padding length (2 bytes)
        writer.WriteUInt16BigEndian(PaddingLength);

        // Reserved (2 bytes)
        writer.WriteUInt16BigEndian(0);

        return payload.ToByteArray();
    }
}