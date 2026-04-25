using System;
using System.Buffers;
using System.Collections.Generic;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES;

/// <summary>
///     ECIES-X25519-AEAD-Ratchet Block Format Parser
///     Parses payload blocks from ECIES garlic messages
///     Block type values per i2pd/I2P spec (ECIESX25519AEADRatchetSession.h):
///     - DateTime (0) - 4-byte timestamp (seconds since epoch)
///     - SessionID (1) - Session identifier
///     - Termination (4) - Session termination with reason
///     - Options (5) - Session options
///     - NextKey (7) - Ratchet key rotation: flag(1) + keyID(2) + optional key(32)
///     - Ack (8) - Message acknowledgment
///     - AckRequest (9) - Request for acknowledgment
///     - GarlicClove (11) - Garlic clove (I2NP message wrapped)
///     - Padding (254) - Random padding
/// </summary>
public class ECIESBlockFormat
{
    /// <summary>
    ///     ECIES-X25519-AEAD-Ratchet block types
    ///     Values must match i2pd eECIESx25519BlockType enum
    /// </summary>
    public enum BlockType : byte
    {
        DateTime = 0,
        SessionID = 1,
        Termination = 4,
        Options = 5,
        NextKey = 7,
        Ack = 8,
        AckRequest = 9,
        GarlicClove = 11,
        Padding = 254
    }

    // NextKey flag constants (matching i2pd ECIESX25519_NEXT_KEY_* defines)
    public const byte NEXT_KEY_KEY_PRESENT_FLAG = 0x01;
    public const byte NEXT_KEY_REVERSE_KEY_FLAG = 0x02;
    public const byte NEXT_KEY_REQUEST_REVERSE_KEY_FLAG = 0x04;

    /// <summary>
    ///     Parse blocks from payload
    /// </summary>
    public static List<Block> ParseBlocks(byte[] payload)
    {
        if (payload == null)
            throw new ArgumentNullException(nameof(payload));

        var blocks = new List<Block>();
        var reader = new I2PBufferCursor(payload);

        while (reader.Remaining > 0)
        {
            // Read block type
            var blockType = (BlockType)reader.ReadByte();

            // Read block length (2 bytes)
            var blockLength = reader.ReadUInt16BigEndian();

            // Read block data
            var blockData = reader.ReadBytes(blockLength);

            var block = ParseBlock(blockType, blockData);
            blocks.Add(block);

            // Check for termination
            if (blockType == BlockType.Termination)
                break;
        }

        return blocks;
    }

    /// <summary>
    ///     Parse a single block
    /// </summary>
    private static Block ParseBlock(BlockType type, byte[] data)
    {
        return type switch
        {
            BlockType.DateTime => ParseDateTimeBlock(data),
            BlockType.SessionID => ParseSessionIDBlock(data),
            BlockType.Termination => ParseTerminationBlock(data),
            BlockType.Options => new OptionsBlock { Data = data },
            BlockType.NextKey => ParseNextKeyBlock(data),
            BlockType.Ack => ParseAckBlock(data),
            BlockType.AckRequest => new AckRequestBlock { Data = data },
            BlockType.GarlicClove => ParseGarlicCloveBlock(data),
            BlockType.Padding => new PaddingBlock { Data = data },
            _ => new UnknownBlock { RawType = (byte)type, Data = data }
        };
    }

    /// <summary>
    ///     Parse DateTime block
    /// </summary>
    private static DateTimeBlock ParseDateTimeBlock(byte[] data)
    {
        if (data.Length != 4)
            throw new ArgumentException("DateTime block must be 4 bytes", nameof(data));

        var reader = new I2PBufferCursor(data);
        var timestamp = reader.ReadUInt32BigEndian();

        return new DateTimeBlock
        {
            Timestamp = timestamp,
            DateTime = DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime
        };
    }

    /// <summary>
    ///     Parse SessionID block (type 1)
    /// </summary>
    private static SessionIDBlock ParseSessionIDBlock(byte[] data)
    {
        if (data.Length < 2)
            throw new ArgumentException("SessionID block must be at least 2 bytes", nameof(data));

        var reader = new I2PBufferCursor(data);
        return new SessionIDBlock { SessionID = reader.ReadUInt16BigEndian() };
    }

    /// <summary>
    ///     Parse Termination block (type 4)
    ///     Format: reason (1 byte) + additional data
    /// </summary>
    private static TerminationBlock ParseTerminationBlock(byte[] data)
    {
        var block = new TerminationBlock();
        if (data.Length >= 1)
            block.Reason = data[0];
        if (data.Length > 1)
        {
            block.AdditionalData = new byte[data.Length - 1];
            Array.Copy(data, 1, block.AdditionalData, 0, data.Length - 1);
        }

        return block;
    }

    /// <summary>
    ///     Parse GarlicClove block (type 11)
    ///     This is the main payload block containing I2NP messages
    /// </summary>
    private static GarlicCloveBlock ParseGarlicCloveBlock(byte[] data)
    {
        return new GarlicCloveBlock { Data = data };
    }

    /// <summary>
    ///     Parse NextKey block (type 7)
    ///     Format: flag(1) + keyID(2) + optional publicKey(32)
    ///     Total: 3 bytes (no key) or 35 bytes (with key)
    /// </summary>
    private static NextKeyBlock ParseNextKeyBlock(byte[] data)
    {
        if (data.Length < 3)
            throw new ArgumentException("NextKey block must be at least 3 bytes", nameof(data));

        var reader = new I2PBufferCursor(data);
        var flag = reader.ReadByte();
        var keyID = reader.ReadUInt16BigEndian();

        byte[] publicKey = null;
        if ((flag & NEXT_KEY_KEY_PRESENT_FLAG) != 0 && data.Length >= 35) publicKey = reader.ReadBytes(32);

        return new NextKeyBlock
        {
            Flag = flag,
            KeyID = keyID,
            PublicKey = publicKey,
            IsReverseKey = (flag & NEXT_KEY_REVERSE_KEY_FLAG) != 0,
            IsKeyPresent = (flag & NEXT_KEY_KEY_PRESENT_FLAG) != 0,
            IsRequestReverseKey = (flag & NEXT_KEY_REQUEST_REVERSE_KEY_FLAG) != 0
        };
    }

    /// <summary>
    ///     Parse Ack block (type 8)
    ///     Format: numAcks(1) + [tagsetID(2) + ackThrough(2)] * numAcks
    /// </summary>
    private static AckBlock ParseAckBlock(byte[] data)
    {
        var block = new AckBlock();
        if (data.Length < 1) return block;

        var reader = new I2PBufferCursor(data);
        var numAcks = reader.ReadByte();

        for (var i = 0; i < numAcks && reader.Remaining >= 4; i++)
        {
            var tagsetID = reader.ReadUInt16BigEndian();
            var ackThrough = reader.ReadUInt16BigEndian();
            block.Acks.Add((tagsetID, ackThrough));
        }

        return block;
    }

    /// <summary>
    ///     Build blocks into payload
    /// </summary>
    public static byte[] BuildBlocks(List<Block> blocks)
    {
        if (blocks == null)
            throw new ArgumentNullException(nameof(blocks));

        var stream = new ArrayBufferWriter<byte>();

        foreach (var block in blocks) WriteBlock(stream, block);

        return stream.WrittenSpan.ToArray();
    }

    /// <summary>
    ///     Write a single block
    /// </summary>
    private static void WriteBlock(ArrayBufferWriter<byte> stream, Block block)
    {
        // Write block type
        stream.WriteByte((byte)block.Type);

        // Get block data
        var blockData = block.ToByteArray();

        // Write block length
        stream.WriteUInt16BigEndian((ushort)blockData.Length);

        // Write block data
        stream.WriteBytes(blockData);
    }
}

/// <summary>
///     Base class for all ECIES block types
/// </summary>
public abstract class Block
{
    public abstract ECIESBlockFormat.BlockType Type { get; }
    public abstract byte[] ToByteArray();
}

/// <summary>
///     DateTime block (type 0) - 4-byte timestamp (seconds since epoch)
/// </summary>
public class DateTimeBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.DateTime;
    public uint Timestamp { get; set; }
    public DateTime DateTime { get; set; }

    public override byte[] ToByteArray()
    {
        var stream = new ArrayBufferWriter<byte>();
        stream.WriteUInt32BigEndian(Timestamp);
        return stream.WrittenSpan.ToArray();
    }
}

/// <summary>
///     SessionID block (type 1) - Session identifier
/// </summary>
public class SessionIDBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.SessionID;
    public ushort SessionID { get; set; }

    public override byte[] ToByteArray()
    {
        var stream = new ArrayBufferWriter<byte>();
        stream.WriteUInt16BigEndian(SessionID);
        return stream.WrittenSpan.ToArray();
    }
}

/// <summary>
///     Termination block (type 4) - Session termination with reason
/// </summary>
public class TerminationBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.Termination;
    public byte Reason { get; set; }
    public byte[] AdditionalData { get; set; }

    public override byte[] ToByteArray()
    {
        if (AdditionalData == null || AdditionalData.Length == 0)
            return new[] { Reason };

        var result = new byte[1 + AdditionalData.Length];
        result[0] = Reason;
        Array.Copy(AdditionalData, 0, result, 1, AdditionalData.Length);
        return result;
    }
}

/// <summary>
///     Options block (type 5) - Session options
/// </summary>
public class OptionsBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.Options;
    public byte[] Data { get; set; }

    public override byte[] ToByteArray()
    {
        return Data ?? Array.Empty<byte>();
    }
}

/// <summary>
///     NextKey block (type 7) - Ratchet key rotation
///     Format: flag(1) + keyID(2) + optional publicKey(32)
///     Flags: KEY_PRESENT=0x01, REVERSE_KEY=0x02, REQUEST_REVERSE_KEY=0x04
/// </summary>
public class NextKeyBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.NextKey;
    public byte Flag { get; set; }
    public ushort KeyID { get; set; }
    public byte[] PublicKey { get; set; } // 32 bytes, present when KEY_PRESENT flag set
    public bool IsReverseKey { get; set; }
    public bool IsKeyPresent { get; set; }
    public bool IsRequestReverseKey { get; set; }

    public override byte[] ToByteArray()
    {
        var stream = new ArrayBufferWriter<byte>();
        stream.WriteByte(Flag);
        stream.WriteUInt16BigEndian(KeyID);
        if (PublicKey != null)
            stream.WriteBytes(PublicKey);
        return stream.WrittenSpan.ToArray();
    }
}

/// <summary>
///     Ack block (type 8) - Message acknowledgment
///     Format: numAcks(1) + [tagsetID(2) + ackThrough(2)] * numAcks
/// </summary>
public class AckBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.Ack;
    public List<(ushort TagSetID, ushort AckThrough)> Acks { get; set; } = new();

    public override byte[] ToByteArray()
    {
        var stream = new ArrayBufferWriter<byte>();
        stream.WriteByte((byte)Acks.Count);
        foreach (var (tagSetID, ackThrough) in Acks)
        {
            stream.WriteUInt16BigEndian(tagSetID);
            stream.WriteUInt16BigEndian(ackThrough);
        }

        return stream.WrittenSpan.ToArray();
    }
}

/// <summary>
///     AckRequest block (type 9) - Request for acknowledgment
/// </summary>
public class AckRequestBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.AckRequest;
    public byte[] Data { get; set; }

    public override byte[] ToByteArray()
    {
        return Data ?? Array.Empty<byte>();
    }
}

/// <summary>
///     GarlicClove block (type 11) - Contains an I2NP message (garlic clove)
///     This is the primary payload block in ECIES garlic messages
/// </summary>
public class GarlicCloveBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.GarlicClove;
    public byte[] Data { get; set; }

    public override byte[] ToByteArray()
    {
        return Data ?? Array.Empty<byte>();
    }
}

/// <summary>
///     Padding block (type 254) - Random padding
/// </summary>
public class PaddingBlock : Block
{
    public override ECIESBlockFormat.BlockType Type => ECIESBlockFormat.BlockType.Padding;
    public byte[] Data { get; set; }

    public override byte[] ToByteArray()
    {
        return Data ?? Array.Empty<byte>();
    }
}

/// <summary>
///     Unknown block type - for forward compatibility with future block types
/// </summary>
public class UnknownBlock : Block
{
    public byte RawType { get; set; }
    public override ECIESBlockFormat.BlockType Type => (ECIESBlockFormat.BlockType)RawType;
    public byte[] Data { get; set; }

    public override byte[] ToByteArray()
    {
        return Data ?? Array.Empty<byte>();
    }
}