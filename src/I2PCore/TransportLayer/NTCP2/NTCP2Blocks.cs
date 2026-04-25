using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.NTCP2;

/// <summary>
///     NTCP2 Block Definitions
///     Per NTCP2 spec
/// </summary>
public enum NTCP2BlockType : byte
{
    DateTime = 0,
    Options = 1,
    RouterInfo = 2,
    I2NP = 3,
    Termination = 4,
    Padding = 254
}

/// <summary>
///     NTCP2 Block base class
/// </summary>
public abstract class NTCP2Block
{
    public abstract NTCP2BlockType BlockType { get; }
    public abstract byte[] Serialize();
    public abstract void Parse(I2PBufferCursor data);
}

/// <summary>
///     DateTime Block (Type 0)
/// </summary>
public class NTCP2DateTimeBlock : NTCP2Block
{
    public NTCP2DateTimeBlock()
    {
        // Align with i2pd: seconds rounded with +500ms bias
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Timestamp = (uint)((nowMs + 500) / 1000);
    }

    public NTCP2DateTimeBlock(uint timestamp)
    {
        Timestamp = timestamp;
    }

    public override NTCP2BlockType BlockType => NTCP2BlockType.DateTime;
    public uint Timestamp { get; set; } // Unix timestamp in seconds

    public override byte[] Serialize()
    {
        var result = new byte[4];
        var timestampBytes = BufUtils.Flip32B(Timestamp);
        Array.Copy(timestampBytes, 0, result, 0, 4);
        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        Timestamp = data.ReadUInt32BigEndian();
    }
}

/// <summary>
///     Options Block (Type 1)
///     Per NTCP2 spec lines 1108-1160
/// </summary>
public class NTCP2OptionsBlock : NTCP2Block
{
    public override NTCP2BlockType BlockType => NTCP2BlockType.Options;

    // Requested padding limits (4.4 fixed point)
    public byte TMin { get; set; }
    public byte TMax { get; set; }
    public byte RMin { get; set; }
    public byte RMax { get; set; }

    // Dummy traffic (bytes/sec)
    public ushort TDummy { get; set; }
    public ushort RDummy { get; set; }

    // Max delay (msec)
    public ushort TDelay { get; set; }
    public ushort RDelay { get; set; }

    public override byte[] Serialize()
    {
        var result = new byte[12];
        result[0] = TMin;
        result[1] = TMax;
        result[2] = RMin;
        result[3] = RMax;

        var tdmyBytes = BufUtils.Flip16B(TDummy);
        Array.Copy(tdmyBytes, 0, result, 4, 2);
        var rdmyBytes = BufUtils.Flip16B(RDummy);
        Array.Copy(rdmyBytes, 0, result, 6, 2);
        var tdelayBytes = BufUtils.Flip16B(TDelay);
        Array.Copy(tdelayBytes, 0, result, 8, 2);
        var rdelayBytes = BufUtils.Flip16B(RDelay);
        Array.Copy(rdelayBytes, 0, result, 10, 2);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        if (data.Remaining < 11)
            throw new Exception($"Invalid Options block size: {data.Remaining} (minimum 11 bytes)");

        if (data.Remaining == 11)
        {
            // Likely go-i2p format: Version(1) + PaddingMin(1) + PaddingMax(1) + DummyMin(2) + DummyMax(2) + DelayMin(2) + DelayMax(2)
            Logging.LogDebug("NTCP2OptionsBlock: Received 11-byte options block (likely go-i2p format)");
            data.ReadByte(); // Version
            TMin = data.ReadByte();
            TMax = data.ReadByte();
            TDummy = data.ReadUInt16BigEndian();
            RDummy = data.ReadUInt16BigEndian();
            TDelay = data.ReadUInt16BigEndian();
            RDelay = data.ReadUInt16BigEndian();

            // Set default RMin/RMax (no padding)
            RMin = 0;
            RMax = 0;
        }
        else
        {
            // NTCP2 spec format (12 bytes): TMin(1), TMax(1), RMin(1), RMax(1), TDummy(2), RDummy(2), TDelay(2), RDelay(2)
            TMin = data.ReadByte();
            TMax = data.ReadByte();
            RMin = data.ReadByte();
            RMax = data.ReadByte();
            TDummy = data.ReadUInt16BigEndian();
            RDummy = data.ReadUInt16BigEndian();
            TDelay = data.ReadUInt16BigEndian();
            RDelay = data.ReadUInt16BigEndian();
        }

        // Ignore more_options for now (spec says TBD)
        if (data.Remaining > 0) data.ReadBlock(data.Remaining);
    }
}

/// <summary>
///     RouterInfo Block (Type 2)
///     Used in SessionConfirmed message and data phase
/// </summary>
public class NTCP2RouterInfoBlock : NTCP2Block
{
    public override NTCP2BlockType BlockType => NTCP2BlockType.RouterInfo;
    public I2PRouterInfo RouterInfo { get; set; }
    public byte Flags { get; set; } // bit 0: flood, bit 1: unused (was gzip in SSU2)

    public override byte[] Serialize()
    {
        // Serialize RouterInfo
        var riStream = new ArrayBufferWriter<byte>();
        RouterInfo.Write(riStream);
        var riBytes = riStream.WrittenSpan.ToArray();

        var result = new byte[1 + riBytes.Length];
        result[0] = Flags;
        Array.Copy(riBytes, 0, result, 1, riBytes.Length);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        if (data.Remaining < 1)
            throw new Exception($"Invalid RouterInfo block size: {data.Remaining}");

        Flags = data.ReadByte();
        var riData = data.ReadBlock(data.Remaining - 1);
        RouterInfo = new I2PRouterInfo(new I2PBufferCursor(riData), false);
    }
}

/// <summary>
///     I2NP Message Block (Type 3)
///     Per NTCP2 spec
/// </summary>
public class NTCP2I2NPBlock : NTCP2Block
{
    public override NTCP2BlockType BlockType => NTCP2BlockType.I2NP;
    public byte MessageType { get; set; }
    public uint MessageId { get; set; }
    public uint Expiration { get; set; }
    public byte[] Message { get; set; }

    public override byte[] Serialize()
    {
        var result = new byte[9 + Message.Length]; // 1 type + 4 msgid + 4 exp + message

        result[0] = MessageType;
        var msgIdBytes = BufUtils.Flip32B(MessageId);
        Array.Copy(msgIdBytes, 0, result, 1, 4);
        var expBytes = BufUtils.Flip32B(Expiration);
        Array.Copy(expBytes, 0, result, 5, 4);
        Array.Copy(Message, 0, result, 9, Message.Length);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        if (data.Remaining < 9)
            throw new Exception($"Invalid I2NP block size: {data.Remaining}");

        MessageType = data.ReadByte();
        MessageId = data.ReadUInt32BigEndian();
        Expiration = data.ReadUInt32BigEndian();
        Message = data.ReadBlock(data.Remaining - 9).ToByteArray();
    }
}

/// <summary>
///     Termination Block (Type 4)
///     Per NTCP2 spec
/// </summary>
public class NTCP2TerminationBlock : NTCP2Block
{
    public override NTCP2BlockType BlockType => NTCP2BlockType.Termination;
    public ulong ValidPacketsReceived { get; set; }
    public NTCP2TerminationReason Reason { get; set; }
    public byte[] AdditionalData { get; set; }

    public override byte[] Serialize()
    {
        var result = new byte[1 + 8 + (AdditionalData?.Length ?? 0)];

        // Valid packets received (8 bytes, big endian)
        var packetsBytes = BufUtils.Flip64B(ValidPacketsReceived);
        Array.Copy(packetsBytes, 0, result, 0, 8);

        // Reason (1 byte)
        result[8] = (byte)Reason;

        if (AdditionalData != null && AdditionalData.Length > 0)
            Array.Copy(AdditionalData, 0, result, 9, AdditionalData.Length);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        if (data.Remaining < 9)
            throw new Exception($"Invalid Termination block size: {data.Remaining}");

        // Valid packets received (8 bytes, big endian)
        ValidPacketsReceived = data.ReadUInt64BigEndian();

        // Reason (1 byte)
        Reason = (NTCP2TerminationReason)data.ReadByte();

        if (data.Remaining > 0) AdditionalData = data.ReadBlock(data.Remaining).ToByteArray();
    }
}

public enum NTCP2TerminationReason : byte
{
    NormalClose = 0,
    TerminationReceived = 1,
    IdleTimeout = 2,
    RouterShutdown = 3,
    DataPhaseAeadFailure = 4,
    IncompatibleOptions = 5,
    IncompatibleSignatureType = 6,
    ClockSkew = 7,
    PaddingViolation = 8,
    AeadFramingError = 9,
    PayloadFormatError = 10,
    SessionRequestError = 11,
    SessionCreatedError = 12,
    SessionConfirmedError = 13,
    Timeout = 14,
    RouterInfoSignatureFailure = 15,
    InvalidSParameter = 16,
    Banned = 17
}

/// <summary>
///     Padding Block (Type 254)
/// </summary>
public class NTCP2PaddingBlock : NTCP2Block
{
    public NTCP2PaddingBlock(int length)
    {
        Length = length;
    }

    public override NTCP2BlockType BlockType => NTCP2BlockType.Padding;
    public int Length { get; set; }

    public override byte[] Serialize()
    {
        var result = new byte[Length];
        // Padding data is random or zeros
        var random = new Random();
        random.NextBytes(result);
        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        Length = data.Remaining;
        data.Seek(Length); // Skip padding data
    }
}