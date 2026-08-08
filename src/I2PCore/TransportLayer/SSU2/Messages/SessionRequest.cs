using System;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages;

/// <summary>
///     SSU2 Session Request (Handshake Message 1)
///     Noise XK pattern: -> e, es
///     Contains:
///     - Long header (32 bytes)
///     - Encrypted ephemeral key X (32 bytes, obfuscated with ChaCha20)
///     - Encrypted payload (variable)
/// </summary>
public class SessionRequest
{
    public const int MIN_PADDING = 0;
    public const int MAX_PADDING = 64;

    public SessionRequest()
    {
        Header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_SESSION_REQUEST,
            Version = 2,
            NetId = (byte)I2PConstants.I2PNetworkId
        };
    }

    public SSU2Header Header { get; set; }
    public byte[] EphemeralKey { get; set; } // X, 32 bytes (plaintext)
    public byte[] EncryptedPayload { get; set; } // From Noise
    public uint Timestamp { get; set; }
    public ushort PaddingLength { get; set; }
    public byte[] Padding { get; set; }

    public static SessionRequest Parse(I2PBufferCursor data, byte[] bobIntroKey, byte[] fullPacket)
    {
        var request = new SessionRequest();

        // For Session Request: k_header_1 = k_header_2 = Bob's intro key (NO derivation)
        // SSU2 spec lines 707-720
        var kHeader1 = bobIntroKey;
        var kHeader2 = bobIntroKey;

        // Decrypt header in place using IVs from packet end
        SSU2HeaderEncryption.DecryptLongHeaderInPacket(fullPacket, 0, kHeader1, kHeader2);

        // Parse decrypted header from packet
        request.Header = SSU2Header.ParseLongHeader(new I2PBufferCursor(fullPacket));

        // Decrypt ephemeral key (obfuscated with ChaCha20)
        var encryptedX = new byte[32];
        Array.Copy(fullPacket, 32, encryptedX, 0, 32);
        request.EphemeralKey = SSU2HeaderEncryption.DeobfuscateEphemeralKey(encryptedX, kHeader2);

        // Read encrypted payload (rest of the packet)
        var remaining = fullPacket.Length - 64;
        request.EncryptedPayload = new byte[remaining];
        Array.Copy(fullPacket, 64, request.EncryptedPayload, 0, remaining);

        return request;
    }

    public byte[] ToByteArray(byte[] bobIntroKey, byte[] ephemeralKey, byte[] encryptedPayload)
    {
        // For Session Request: k_header_1 = k_header_2 = Bob's intro key (NO derivation)
        // SSU2 spec lines 707-720
        var kHeader1 = bobIntroKey;
        var kHeader2 = bobIntroKey;

        // Build header (plaintext first)
        var header = Header.ToByteArray();

        // Build complete packet first: header + ephKey + payload (needed for IV derivation)
        var obfuscatedX = SSU2HeaderEncryption.ObfuscateEphemeralKey(ephemeralKey, kHeader2);

        var padding = Padding ?? Array.Empty<byte>();
        var packet = new byte[header.Length + obfuscatedX.Length + encryptedPayload.Length + padding.Length];
        Array.Copy(header, 0, packet, 0, header.Length);
        Array.Copy(obfuscatedX, 0, packet, header.Length, obfuscatedX.Length);
        Array.Copy(encryptedPayload, 0, packet, header.Length + obfuscatedX.Length, encryptedPayload.Length);
        if (padding.Length > 0)
            Array.Copy(padding, 0, packet, header.Length + obfuscatedX.Length + encryptedPayload.Length,
                padding.Length);

        // Encrypt header in place using IVs from packet end
        SSU2HeaderEncryption.EncryptLongHeaderInPacket(packet, 0, kHeader1, kHeader2);

        return packet;
    }

    public byte[] BuildPayload()
    {
        // Build options block for SessionRequest payload
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