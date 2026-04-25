using System;
using System.Collections.Generic;

namespace I2PCore.SessionLayer.Streaming;

/// <summary>
///     I2P Streaming Protocol Packet
///     Implements the packet format per the I2P Streaming spec.
///     Header layout:
///     [0..3]   sendStreamID (big-endian)
///     [4..7]   receiveStreamID (big-endian)
///     [8..11]  sequenceNumber (big-endian)
///     [12..15] ackThrough (big-endian)
///     [16]     nackCount
///     [17..17+4*nackCount-1] NACKs (4 bytes each, big-endian)
///     [+0]     resendDelay (1 byte)
///     [+1..+2] flags (2 bytes, big-endian)
///     [+3..+4] optionSize (2 bytes, big-endian)
///     [+5..+5+optionSize-1] options
///     remainder: payload
/// </summary>
public class StreamingPacket
{
    // Flags
    public const ushort FLAG_SYNCHRONIZE = 0x0001;
    public const ushort FLAG_CLOSE = 0x0002;
    public const ushort FLAG_RESET = 0x0004;
    public const ushort FLAG_SIGNATURE_INCLUDED = 0x0008;
    public const ushort FLAG_SIGNATURE_REQUESTED = 0x0010;
    public const ushort FLAG_FROM_INCLUDED = 0x0020;
    public const ushort FLAG_DELAY_REQUESTED = 0x0040;
    public const ushort FLAG_MAX_PACKET_SIZE_INCLUDED = 0x0080;
    public const ushort FLAG_PROFILE_INTERACTIVE = 0x0100;
    public const ushort FLAG_ECHO = 0x0200;
    public const ushort FLAG_NO_ACK = 0x0400;
    public const ushort FLAG_OFFLINE_SIGNATURE = 0x0800;

    public uint SendStreamId { get; set; }
    public uint ReceiveStreamId { get; set; }
    public uint SequenceNumber { get; set; }
    public uint AckThrough { get; set; }
    public List<uint> NACKs { get; set; } = new();
    public byte ResendDelay { get; set; }
    public ushort Flags { get; set; }
    public byte[] OptionData { get; set; } = Array.Empty<byte>();
    public byte[] Payload { get; set; } = Array.Empty<byte>();

    // Send tracking
    public long SendTime { get; set; }
    public bool Resent { get; set; }

    public bool IsSYN => (Flags & FLAG_SYNCHRONIZE) != 0;
    public bool IsClose => (Flags & FLAG_CLOSE) != 0;
    public bool IsReset => (Flags & FLAG_RESET) != 0;
    public bool IsNoAck => (Flags & FLAG_NO_ACK) != 0;
    public bool IsEcho => (Flags & FLAG_ECHO) != 0;
    public bool HasSignature => (Flags & FLAG_SIGNATURE_INCLUDED) != 0;
    public bool HasFrom => (Flags & FLAG_FROM_INCLUDED) != 0;
    public bool HasMaxPacketSize => (Flags & FLAG_MAX_PACKET_SIZE_INCLUDED) != 0;
    public bool HasDelayRequested => (Flags & FLAG_DELAY_REQUESTED) != 0;

    /// <summary>
    ///     Parse a streaming packet from raw bytes
    /// </summary>
    public static StreamingPacket Parse(byte[] data)
    {
        if (data == null || data.Length < 22)
            throw new ArgumentException("Streaming packet too short");

        var pkt = new StreamingPacket();
        var offset = 0;

        pkt.SendStreamId = ReadBE32(data, offset);
        offset += 4;
        pkt.ReceiveStreamId = ReadBE32(data, offset);
        offset += 4;
        pkt.SequenceNumber = ReadBE32(data, offset);
        offset += 4;
        pkt.AckThrough = ReadBE32(data, offset);
        offset += 4;

        var nackCount = data[offset++];
        pkt.NACKs = new List<uint>(nackCount);
        for (var i = 0; i < nackCount; i++)
        {
            pkt.NACKs.Add(ReadBE32(data, offset));
            offset += 4;
        }

        pkt.ResendDelay = data[offset++];
        pkt.Flags = ReadBE16(data, offset);
        offset += 2;

        var optionSize = ReadBE16(data, offset);
        offset += 2;
        if (offset + optionSize > data.Length)
            throw new ArgumentException("Streaming packet option data overflows");

        pkt.OptionData = new byte[optionSize];
        Array.Copy(data, offset, pkt.OptionData, 0, optionSize);
        offset += optionSize;

        // Remaining is payload
        var payloadLen = data.Length - offset;
        if (payloadLen > 0)
        {
            pkt.Payload = new byte[payloadLen];
            Array.Copy(data, offset, pkt.Payload, 0, payloadLen);
        }

        return pkt;
    }

    /// <summary>
    ///     Serialize this packet to bytes
    /// </summary>
    public byte[] ToByteArray()
    {
        var nackBytes = NACKs.Count * 4;
        var headerSize = 4 + 4 + 4 + 4 + 1 + nackBytes + 1 + 2 + 2 + OptionData.Length;
        var totalSize = headerSize + Payload.Length;
        var result = new byte[totalSize];
        var offset = 0;

        WriteBE32(result, offset, SendStreamId);
        offset += 4;
        WriteBE32(result, offset, ReceiveStreamId);
        offset += 4;
        WriteBE32(result, offset, SequenceNumber);
        offset += 4;
        WriteBE32(result, offset, AckThrough);
        offset += 4;

        result[offset++] = (byte)NACKs.Count;
        foreach (var nack in NACKs)
        {
            WriteBE32(result, offset, nack);
            offset += 4;
        }

        result[offset++] = ResendDelay;
        WriteBE16(result, offset, Flags);
        offset += 2;
        WriteBE16(result, offset, (ushort)OptionData.Length);
        offset += 2;

        Array.Copy(OptionData, 0, result, offset, OptionData.Length);
        offset += OptionData.Length;

        Array.Copy(Payload, 0, result, offset, Payload.Length);

        return result;
    }

    private static uint ReadBE32(byte[] data, int offset)
    {
        return (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
    }

    private static ushort ReadBE16(byte[] data, int offset)
    {
        return (ushort)((data[offset] << 8) | data[offset + 1]);
    }

    private static void WriteBE32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value >> 24);
        data[offset + 1] = (byte)(value >> 16);
        data[offset + 2] = (byte)(value >> 8);
        data[offset + 3] = (byte)value;
    }

    private static void WriteBE16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value >> 8);
        data[offset + 1] = (byte)value;
    }
}