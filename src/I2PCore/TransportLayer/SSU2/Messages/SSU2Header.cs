using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages;

/// <summary>
///     SSU2 Packet Header
///     Short header (16 bytes):
///     - Connection ID: 8 bytes
///     - Packet Number: 4 bytes
///     - Type: 1 byte
///     - Flags: 3 bytes
///     Long header (32 bytes):
///     - Destination Connection ID: 8 bytes
///     - Packet Number: 4 bytes (per spec lines 413-437)
///     - Type: 1 byte
///     - Version: 1 byte
///     - NetID: 1 byte
///     - Flag: 1 byte
///     - Source Connection ID: 8 bytes
///     - Token: 8 bytes (per spec line 437)
/// </summary>
public class SSU2Header
{
    public const int SHORT_HEADER_SIZE = 16;
    public const int LONG_HEADER_SIZE = 32;

    // Header type flags (per spec lines 310-321)
    public const byte TYPE_SESSION_REQUEST = 0;
    public const byte TYPE_SESSION_CREATED = 1;
    public const byte TYPE_SESSION_CONFIRMED = 2;
    public const byte TYPE_DATA = 6; // FIXED: spec says type 6
    public const byte TYPE_PEER_TEST = 7;
    public const byte TYPE_RETRY = 9;
    public const byte TYPE_TOKEN_REQUEST = 10;
    public const byte TYPE_HOLE_PUNCH = 11;

    public ulong DestinationConnectionId { get; set; }
    public uint PacketNumber { get; set; } // FIXED: 4 bytes, not 8
    public byte Type { get; set; }
    public byte Version { get; set; }
    public byte NetId { get; set; }
    public byte Flag { get; set; } // FIXED: Added 1 byte flag field
    public ulong SourceConnectionId { get; set; }
    public ulong Token { get; set; } // FIXED: 8 bytes, not 4

    /// <summary>
    ///     Short header flags[0]: For SessionConfirmed, encodes fragment info.
    ///     Lower nibble = total fragment count, upper nibble = fragment number (0-indexed).
    ///     E.g. 0x01 = frag 0 of 1, 0x02 = frag 0 of 2, 0x12 = frag 1 of 2.
    /// </summary>
    public byte Flags0 { get; set; }

    public byte Flags1 { get; set; }
    public byte Flags2 { get; set; }

    public bool IsLongHeader { get; set; }

    public static SSU2Header ParseShortHeader(I2PBufferCursor data)
    {
        var header = new SSU2Header
        {
            IsLongHeader = false,
            DestinationConnectionId = data.ReadUInt64BigEndian(),
            PacketNumber = data.ReadUInt32BigEndian(), // FIXED: 4 bytes
            Type = data.ReadByte()
        };
        header.Flags0 = data.ReadByte();
        header.Flags1 = data.ReadByte();
        header.Flags2 = data.ReadByte();
        return header;
    }

    public static SSU2Header ParseLongHeader(I2PBufferCursor data)
    {
        var header = new SSU2Header
        {
            IsLongHeader = true,
            DestinationConnectionId = data.ReadUInt64BigEndian(),
            PacketNumber = data.ReadUInt32BigEndian(), // FIXED: 4 bytes
            Type = data.ReadByte(),
            Version = data.ReadByte(),
            NetId = data.ReadByte(),
            Flag = data.ReadByte(),
            SourceConnectionId = data.ReadUInt64BigEndian(),
            Token = data.ReadUInt64BigEndian() // FIXED: 8 bytes
        };

        return header;
    }

    public byte[] ToByteArray()
    {
        var size = IsLongHeader ? LONG_HEADER_SIZE : SHORT_HEADER_SIZE;
        var result = new byte[size];
        var writer = new I2PBufferCursor(result);

        writer.WriteUInt64BigEndian(DestinationConnectionId);
        writer.WriteUInt32BigEndian(PacketNumber); // FIXED: 4 bytes

        if (IsLongHeader)
        {
            writer.WriteByte(Type);
            writer.WriteByte(Version);
            writer.WriteByte(NetId);
            writer.WriteByte(Flag);
            writer.WriteUInt64BigEndian(SourceConnectionId);
            writer.WriteUInt64BigEndian(Token); // FIXED: 8 bytes
        }
        else
        {
            writer.WriteByte(Type);
            // 3 bytes flags/reserved
            // flags[0] encodes fragment info for SessionConfirmed:
            //   lower nibble = total number of fragments
            //   upper nibble = fragment number (0-indexed)
            writer.WriteByte(Flags0);
            writer.WriteByte(Flags1);
            writer.WriteByte(Flags2);
        }

        return result;
    }
}