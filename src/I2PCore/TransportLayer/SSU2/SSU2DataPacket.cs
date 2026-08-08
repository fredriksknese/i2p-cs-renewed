using System;
using System.Collections.Generic;
using I2PCore.Crypto;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     SSU2 Data Phase Packet
///     Contains blocks of data encrypted with Noise transport encryption
/// </summary>
public class SSU2DataPacket
{
    public SSU2Header Header { get; set; }
    public List<SSU2BlockWrapper> Blocks { get; set; } = new();

    public static SSU2DataPacket BuildWithI2NPMessage(I2NpMessage msg, ulong destConnId, uint packetNum)
    {
        var packet = new SSU2DataPacket
        {
            Header = new SSU2Header
            {
                IsLongHeader = false,
                DestinationConnectionId = destConnId,
                PacketNumber = packetNum // Already uint now
            }
        };

        // Create I2NP block
        // Get header and payload as a single buffer
        var headerAndPayload = msg.CreateHeader16.HeaderAndPayload;
        var msgBytes = headerAndPayload.ToByteArray();
        var i2npBlock = new SSU2BlockWrapper
        {
            BlockType = SSU2BlockType.I2NP,
            Data = msgBytes
        };
        packet.Blocks.Add(i2npBlock);

        // Add DateTime block
        var timeMs = (uint)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc))
            .TotalMilliseconds / 1000);
        var timeBytes = BufUtils.Flip32B(timeMs);

        var timeBlock = new SSU2BlockWrapper
        {
            BlockType = SSU2BlockType.DateTime,
            Data = timeBytes
        };
        packet.Blocks.Add(timeBlock);

        return packet;
    }

    /// <summary>
    ///     Build a data packet containing a single block (for control messages like RelayTagRequest).
    /// </summary>
    public static byte[] BuildWithBlock(
        SSU2BlockType blockType, byte[] blockData,
        ulong destConnId, uint packetNum,
        byte[] dataKey, byte[] headerKey1, byte[] headerKey2)
    {
        var packet = new SSU2DataPacket
        {
            Header = new SSU2Header
            {
                IsLongHeader = false,
                DestinationConnectionId = destConnId,
                PacketNumber = packetNum
            }
        };

        packet.Blocks.Add(new SSU2BlockWrapper
        {
            BlockType = blockType,
            Data = blockData ?? Array.Empty<byte>()
        });

        // Batch 4-1a: this took dataKey and headerKey2 and used neither, returning
        // packet.ToByteArray() — the bare block list, with no 16-byte header and no AEAD. Every
        // relay tag request and peer test SendBlock has ever sent went out unframed and in the
        // clear. The parameters were there all along; only the call was missing.
        return packet.BuildEncryptedPacket(dataKey, headerKey1, headerKey2);
    }

    public byte[] ToByteArray()
    {
        var result = new I2PByteBlock(new byte[8192]);
        var writer = new I2PBufferCursor(result);

        // Write blocks
        foreach (var block in Blocks)
        {
            writer.WriteByte((byte)block.BlockType);
            writer.WriteUInt16BigEndian((ushort)block.Data.Length);
            writer.WriteBytes(block.Data);
        }

        return result.ToByteArray().Copy(0, writer.Position);
    }

    public byte[] BuildEncryptedPacket(byte[] dataKey, byte[] headerKey1, byte[] headerKey2)
    {
        var payload = ToByteArray();

        // Batch 4-1a (docs/PRODUCTION-PLAN.md): this used to hand-roll a 16-byte header that was
        // not an SSU2 short header — two bytes of connection ID at 0-1, the packet number at 4,
        // and a type byte at 2 — while every reader in the codebase takes the type from offset
        // 12. Parse() mirrored the same invented layout, so build/parse round-tripped and no test
        // noticed; nothing i2pd sends could be read and nothing we send could be read by i2pd.
        // Truncating the 64-bit connection ID to its top 16 bits was the worse half: two sessions
        // agreeing in those bits were indistinguishable.
        //
        // SSU2Header.ToByteArray already emits the correct layout (connection ID 0-7, packet
        // number 8-11, type 12, flags 13-15) and the long-header path has always used it. Use the
        // one definition rather than a second, private opinion of the wire format.
        Header.IsLongHeader = false;
        Header.Type = SSU2Header.TYPE_DATA;

        var headerBytes = Header.ToByteArray();

        // Encrypt payload with ChaCha20-Poly1305 using header as AD
        // Per spec line 1901: ad = 16 byte header, before header encryption
        var nonce = ChaCha20Poly1305.CreateNonce(Header.PacketNumber);
        var encryptedPayload = ChaCha20Poly1305.Encrypt(dataKey, nonce, payload, headerBytes);

        // Build packet with unencrypted header + encrypted payload
        var packetLen = 16 + encryptedPayload.Length;
        var packet = new byte[packetLen];
        Array.Copy(headerBytes, 0, packet, 0, 16);
        Array.Copy(encryptedPayload, 0, packet, 16, encryptedPayload.Length);

        // Encrypt header in place using two-stage ChaCha20
        SSU2HeaderEncryption.EncryptShortHeaderInPacket(packet, 0, headerKey1, headerKey2);

        return packet;
    }

    public static SSU2DataPacket Parse(byte[] packetData, byte[] dataKey, byte[] headerKey1, byte[] headerKey2)
    {
        var packet = new SSU2DataPacket();

        // Decrypt header in place
        var packetCopy = new byte[packetData.Length];
        Array.Copy(packetData, packetCopy, packetData.Length);
        SSU2HeaderEncryption.DecryptShortHeaderInPacket(packetCopy, 0, headerKey1, headerKey2);

        // Parse short header (now decrypted). Batch 4-1a: this used to read the invented layout
        // described in BuildEncryptedPacket, recovering the connection ID from two bytes and the
        // packet number from offset 4. Use the canonical parser, which is the same one the
        // long-header path and SSU2Session's type peek already use.
        var reader = new I2PBufferCursor(packetCopy);
        packet.Header = SSU2Header.ParseShortHeader(reader);
        var packetNum = packet.Header.PacketNumber;

        // Build header bytes for AD (use decrypted header)
        var headerBytes = new byte[16];
        Array.Copy(packetCopy, 0, headerBytes, 0, 16);

        // Read encrypted payload (rest of packet after 16-byte header)
        var encryptedPayload = new byte[packetCopy.Length - 16];
        Array.Copy(packetCopy, 16, encryptedPayload, 0, encryptedPayload.Length);

        // Decrypt payload with ChaCha20-Poly1305 using header as AD
        var nonce = ChaCha20Poly1305.CreateNonce(packetNum);
        var decrypted = ChaCha20Poly1305.Decrypt(dataKey, nonce, encryptedPayload, headerBytes);

        if (decrypted == null)
            throw new Exception("Data packet AEAD verification failed");

        // Parse blocks
        var blockReader = new I2PBufferCursor(decrypted);
        while (blockReader.Remaining > 0)
        {
            var blockType = (SSU2BlockType)blockReader.ReadByte();
            var blockLen = blockReader.ReadUInt16BigEndian();
            var blockData = blockReader.ReadBytes(blockLen);

            packet.Blocks.Add(new SSU2BlockWrapper
            {
                BlockType = blockType,
                Data = blockData
            });
        }

        return packet;
    }
}

// Block types moved to SSU2Blocks.cs - using simple wrapper here for compatibility
public class SSU2BlockWrapper
{
    public SSU2BlockType BlockType { get; set; }
    public byte[] Data { get; set; }
}