using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     SSU2 Block Definitions
///     Per SSU2 spec lines 2571-2601
/// </summary>
public enum SSU2BlockType : byte
{
    DateTime = 0,
    Options = 1,
    RouterInfo = 2,
    I2NP = 3,
    FirstFragment = 4,
    FollowOnFragment = 5,
    Termination = 6,
    RelayRequest = 7,
    RelayResponse = 8,
    RelayIntro = 9,
    PeerTest = 10,
    NextNonce = 11,
    ACK = 12,
    Address = 13,

    // 14 reserved
    RelayTagRequest = 15,
    RelayTag = 16,
    NewToken = 17,
    PathChallenge = 18,
    PathResponse = 19,
    FirstPacketNumber = 20,
    Congestion = 21,

    // 224-253 reserved for experimental
    Padding = 254
    // 255 reserved for future extension
}

/// <summary>
///     SSU2 Block base class
/// </summary>
public abstract class SSU2Block
{
    public abstract SSU2BlockType BlockType { get; }
    public abstract byte[] Serialize();
    public abstract void Parse(I2PBufferCursor data);
}

/// <summary>
///     DateTime Block (Type 0)
///     Per spec lines 2619-2640
/// </summary>
public class DateTimeBlock : SSU2Block
{
    public DateTimeBlock()
    {
        Timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    public DateTimeBlock(uint timestamp)
    {
        Timestamp = timestamp;
    }

    public override SSU2BlockType BlockType => SSU2BlockType.DateTime;
    public uint Timestamp { get; set; } // Unix timestamp in seconds

    public override byte[] Serialize()
    {
        var result = new byte[7]; // 1 type + 2 size + 4 timestamp
        result[0] = (byte)BlockType;
        result[1] = 0; // Size high byte
        result[2] = 4; // Size low byte
        var timestampBytes = BufUtils.Flip32B(Timestamp);
        Array.Copy(timestampBytes, 0, result, 3, 4);
        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size != 4)
            throw new Exception($"Invalid DateTime block size: {size}");
        Timestamp = data.ReadUInt32BigEndian();
    }
}

/// <summary>
///     Options Block (Type 1)
///     Per spec lines 2642-2696
/// </summary>
public class OptionsBlock : SSU2Block
{
    public override SSU2BlockType BlockType => SSU2BlockType.Options;

    public byte TMin { get; set; } // Transmit min padding
    public byte TMax { get; set; } // Transmit max padding
    public byte RMin { get; set; } // Receive min padding
    public byte RMax { get; set; } // Receive max padding
    public ushort TDummy { get; set; } // Max dummy traffic willing to send (bytes/sec)
    public ushort RDummy { get; set; } // Requested dummy traffic (bytes/sec)
    public ushort TDelay { get; set; } // Max intra-message delay (ms)
    public ushort RDelay { get; set; } // Requested intra-message delay (ms)

    public override byte[] Serialize()
    {
        var result = new byte[15]; // 1 type + 2 size + 12 data
        result[0] = (byte)BlockType;
        result[1] = 0; // Size high byte
        result[2] = 12; // Size low byte (minimum)
        result[3] = TMin;
        result[4] = TMax;
        result[5] = RMin;
        result[6] = RMax;
        var tDummyBytes = BufUtils.Flip16B(TDummy);
        Array.Copy(tDummyBytes, 0, result, 7, 2);
        var rDummyBytes = BufUtils.Flip16B(RDummy);
        Array.Copy(rDummyBytes, 0, result, 9, 2);
        var tDelayBytes = BufUtils.Flip16B(TDelay);
        Array.Copy(tDelayBytes, 0, result, 11, 2);
        var rDelayBytes = BufUtils.Flip16B(RDelay);
        Array.Copy(rDelayBytes, 0, result, 13, 2);
        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size < 12)
            throw new Exception($"Invalid Options block size: {size}");

        TMin = data.ReadByte();
        TMax = data.ReadByte();
        RMin = data.ReadByte();
        RMax = data.ReadByte();
        TDummy = data.ReadUInt16BigEndian();
        RDummy = data.ReadUInt16BigEndian();
        TDelay = data.ReadUInt16BigEndian();
        RDelay = data.ReadUInt16BigEndian();

        // Skip any additional options
        if (size > 12)
            data.Seek(size - 12);
    }
}

/// <summary>
///     Address Block (Type 13)
///     Per spec lines 2589
/// </summary>
public class AddressBlock : SSU2Block
{
    public override SSU2BlockType BlockType => SSU2BlockType.Address;
    public byte[] IPAddress { get; set; } // 4 bytes (IPv4) or 16 bytes (IPv6)
    public ushort Port { get; set; }

    public override byte[] Serialize()
    {
        var isIPv6 = IPAddress.Length == 16;
        var size = isIPv6 ? 18 : 6; // IPv6: 16+2, IPv4: 4+2
        var result = new byte[3 + size];

        result[0] = (byte)BlockType;
        result[1] = (byte)(size >> 8);
        result[2] = (byte)(size & 0xFF);

        Array.Copy(IPAddress, 0, result, 3, IPAddress.Length);
        var portBytes = BufUtils.Flip16B(Port);
        Array.Copy(portBytes, 0, result, 3 + IPAddress.Length, 2);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size != 6 && size != 18)
            throw new Exception($"Invalid Address block size: {size}");

        var ipLen = size - 2;
        IPAddress = data.ReadBlock(ipLen).ToByteArray();
        Port = data.ReadUInt16BigEndian();
    }
}

/// <summary>
///     ACK Block (Type 12)
///     Per spec lines 1458-1507: ACK ranges for received packets
///     Format: 1-byte ACK count, then for each ACK range:
///     4-byte packet number "through" (end of range, big endian)
///     1-byte "ACKs" (number of additional contiguous packets, 0 = 1 packet)
/// </summary>
public class AckBlock : SSU2Block
{
    public override SSU2BlockType BlockType => SSU2BlockType.ACK;
    public List<AckRange> Ranges { get; set; } = new();

    public override byte[] Serialize()
    {
        if (Ranges.Count == 0)
            // Empty ACK block: type + size + 1 byte count = 0
            return new byte[] { (byte)BlockType, 0, 1, 0 };

        // Calculate size: 1 byte count + (4 bytes through + 1 byte acks) per range
        var dataSize = 1 + Ranges.Count * 5;
        var result = new byte[3 + dataSize];

        result[0] = (byte)BlockType;
        result[1] = (byte)(dataSize >> 8);
        result[2] = (byte)(dataSize & 0xFF);
        result[3] = (byte)Math.Min(Ranges.Count, 255);

        var offset = 4;
        foreach (var range in Ranges.Take(255))
        {
            // 4-byte "through" (packet number at end of range)
            var throughBytes = BufUtils.Flip32B(range.End);
            Array.Copy(throughBytes, 0, result, offset, 4);
            offset += 4;

            // 1-byte "ACKs" (additional packets: count - 1)
            result[offset++] = (byte)Math.Min(range.Count - 1, 255);
        }

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size < 1)
            return;

        var ackCount = data.ReadByte();
        Ranges = new List<AckRange>();

        for (var i = 0; i < ackCount; i++)
        {
            var through = data.ReadUInt32BigEndian();
            var acks = data.ReadByte();

            // "through" is the end, "acks" is count-1
            var end = through;
            var start = end - acks;

            Ranges.Add(new AckRange { Start = start, End = end });
        }
    }
}

/// <summary>
///     Termination Block (Type 6)
///     Per spec lines 2908-2966
/// </summary>
public class TerminationBlock : SSU2Block
{
    public override SSU2BlockType BlockType => SSU2BlockType.Termination;
    public ulong ValidPacketsReceived { get; set; }
    public TerminationReason Reason { get; set; }
    public byte[] AdditionalData { get; set; }

    public override byte[] Serialize()
    {
        var dataSize = 8 + 1 + (AdditionalData?.Length ?? 0);
        var result = new byte[3 + dataSize];

        result[0] = (byte)BlockType;
        result[1] = (byte)(dataSize >> 8);
        result[2] = (byte)(dataSize & 0xFF);

        // Write valid packets received (8 bytes, big endian)
        for (var i = 0; i < 8; i++) result[3 + i] = (byte)((ValidPacketsReceived >> (56 - i * 8)) & 0xFF);

        result[11] = (byte)Reason;

        if (AdditionalData != null && AdditionalData.Length > 0)
            Array.Copy(AdditionalData, 0, result, 12, AdditionalData.Length);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size < 9)
            throw new Exception($"Invalid Termination block size: {size}");

        // Read valid packets received (8 bytes, big endian)
        ValidPacketsReceived = 0;
        for (var i = 0; i < 8; i++) ValidPacketsReceived = (ValidPacketsReceived << 8) | data.ReadByte();

        Reason = (TerminationReason)data.ReadByte();

        if (size > 9) AdditionalData = data.ReadBlock(size - 9).ToByteArray();
    }
}

public enum TerminationReason : byte
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
    Banned = 17,
    BadToken = 18,
    ConnectionLimits = 19,
    IncompatibleVersion = 20,
    WrongNetId = 21,
    ReplacedByNewSession = 22
}

/// <summary>
///     Padding Block (Type 254)
///     Per spec
/// </summary>
public class PaddingBlock : SSU2Block
{
    public PaddingBlock(int length)
    {
        Length = length;
    }

    public override SSU2BlockType BlockType => SSU2BlockType.Padding;
    public int Length { get; set; }

    public override byte[] Serialize()
    {
        var result = new byte[3 + Length];
        result[0] = (byte)BlockType;
        result[1] = (byte)(Length >> 8);
        result[2] = (byte)(Length & 0xFF);
        // Padding data is random or zeros
        result.Randomize(3, Length);
        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        Length = data.ReadUInt16BigEndian();
        data.Seek(Length); // Skip padding data
    }
}

/// <summary>
///     I2NP Message Block (Type 3)
///     Per spec lines 2780-2816
/// </summary>
public class I2NPBlock : SSU2Block
{
    public override SSU2BlockType BlockType => SSU2BlockType.I2NP;
    public byte MessageType { get; set; }
    public uint MessageId { get; set; }
    public uint Expiration { get; set; }
    public byte[] Message { get; set; }

    public override byte[] Serialize()
    {
        var dataSize = 9 + Message.Length; // 1 type + 4 msgid + 4 exp + message
        var result = new byte[3 + dataSize];

        result[0] = (byte)BlockType;
        result[1] = (byte)(dataSize >> 8);
        result[2] = (byte)(dataSize & 0xFF);
        result[3] = MessageType;
        var msgIdBytes = BufUtils.Flip32B(MessageId);
        Array.Copy(msgIdBytes, 0, result, 4, 4);
        var expBytes = BufUtils.Flip32B(Expiration);
        Array.Copy(expBytes, 0, result, 8, 4);
        Array.Copy(Message, 0, result, 12, Message.Length);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size < 9)
            throw new Exception($"Invalid I2NP block size: {size}");

        MessageType = data.ReadByte();
        MessageId = data.ReadUInt32BigEndian();
        Expiration = data.ReadUInt32BigEndian();
        Message = data.ReadBlock(size - 9).ToByteArray();
    }
}

/// <summary>
///     First Fragment Block (Type 4)
///     Per spec lines 2818-2861
/// </summary>
public class FirstFragmentBlock : SSU2Block
{
    public override SSU2BlockType BlockType => SSU2BlockType.FirstFragment;
    public byte MessageType { get; set; }
    public uint MessageId { get; set; }
    public uint Expiration { get; set; }
    public byte[] PartialMessage { get; set; }

    public override byte[] Serialize()
    {
        var dataSize = 9 + PartialMessage.Length;
        var result = new byte[3 + dataSize];

        result[0] = (byte)BlockType;
        result[1] = (byte)(dataSize >> 8);
        result[2] = (byte)(dataSize & 0xFF);
        result[3] = MessageType;
        var msgIdBytes = BufUtils.Flip32B(MessageId);
        Array.Copy(msgIdBytes, 0, result, 4, 4);
        var expBytes = BufUtils.Flip32B(Expiration);
        Array.Copy(expBytes, 0, result, 8, 4);
        Array.Copy(PartialMessage, 0, result, 12, PartialMessage.Length);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size < 9)
            throw new Exception($"Invalid FirstFragment block size: {size}");

        MessageType = data.ReadByte();
        MessageId = data.ReadUInt32BigEndian();
        Expiration = data.ReadUInt32BigEndian();
        PartialMessage = data.ReadBlock(size - 9).ToByteArray();
    }
}

/// <summary>
///     Follow-on Fragment Block (Type 5)
///     Per spec lines 2864-2905
/// </summary>
public class FollowOnFragmentBlock : SSU2Block
{
    public override SSU2BlockType BlockType => SSU2BlockType.FollowOnFragment;
    public byte FragmentInfo { get; set; } // bits 7-1: frag num, bit 0: isLast
    public uint MessageId { get; set; }
    public byte[] PartialMessage { get; set; }

    public int FragmentNumber => FragmentInfo >> 1;
    public bool IsLast => (FragmentInfo & 1) == 1;

    public override byte[] Serialize()
    {
        var dataSize = 5 + PartialMessage.Length;
        var result = new byte[3 + dataSize];

        result[0] = (byte)BlockType;
        result[1] = (byte)(dataSize >> 8);
        result[2] = (byte)(dataSize & 0xFF);
        result[3] = FragmentInfo;
        var msgIdBytes = BufUtils.Flip32B(MessageId);
        Array.Copy(msgIdBytes, 0, result, 4, 4);
        Array.Copy(PartialMessage, 0, result, 8, PartialMessage.Length);

        return result;
    }

    public override void Parse(I2PBufferCursor data)
    {
        var size = data.ReadUInt16BigEndian();
        if (size < 5)
            throw new Exception($"Invalid FollowOnFragment block size: {size}");

        FragmentInfo = data.ReadByte();
        MessageId = data.ReadUInt32BigEndian();
        PartialMessage = data.ReadBlock(size - 5).ToByteArray();
    }
}