using System;
using System.Buffers;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Data;

public class BuildRequestRecord : I2PType
{
    public const int Length = 222;

    private readonly uint ReducedHash;

    public I2PByteBlock Data;

    public BuildRequestRecord()
    {
        Data = new I2PByteBlock(new byte[Length]);
        ReducedHash = CreateReducedHash();
    }

    public BuildRequestRecord(I2PBufferCursor buf)
    {
        Data = buf.ReadBlock(Length);
        ReducedHash = CreateReducedHash();
    }

    public I2PTunnelId ReceiveTunnel
    {
        get => new(Data.ReadUInt32BigEndian(0));
        set => Data.WriteUInt32BigEndian(value, 0);
    }

    public I2PIdentHash OurIdent
    {
        get => new(new I2PBufferCursor(Data.BaseArray, Data.BaseArrayOffset + 4, 32));
        set => Data.CopyFrom(value.Hash, 4);
    }

    public I2PTunnelId NextTunnel
    {
        get => new(Data.ReadUInt32BigEndian(36));
        set => Data.WriteUInt32BigEndian(value, 36);
    }

    public I2PIdentHash NextIdent
    {
        get => new(new I2PBufferCursor(Data.BaseArray, Data.BaseArrayOffset + 40, 32));
        set => Data.CopyFrom(value.Hash, 40);
    }

    public I2PByteBlock LayerKey => Data.Slice(72, 32);
    public I2PByteBlock IvKey => Data.Slice(104, 32);

    public I2PSessionKey ReplyKey
    {
        get => new(new I2PBufferCursor(Data.BaseArray, Data.BaseArrayOffset + 136, 32));
        set => Data.CopyFrom(value.Key, 136);
    }

    public I2PByteBlock ReplyKeyBuf => Data.Slice(136, 32);
    public I2PByteBlock ReplyIv => Data.Slice(168, 16);

    public byte Flag
    {
        get => Data.ReadByte(184);
        set => Data.WriteByte(value, 184);
    }

    public uint RequestTimeVal
    {
        get => Data.ReadUInt32BigEndian(185);
        set => Data.WriteUInt32BigEndian(value, 185);
    }

    public DateTime RequestTime
    {
        get => I2PDate.RefDate.AddHours(RequestTimeVal);
        set => RequestTimeVal = (uint)Math.Truncate((value - I2PDate.RefDate).TotalHours);
    }

    public uint SendMessageId
    {
        get => Data.ReadUInt32BigEndian(189);
        set => Data.WriteUInt32BigEndian(value, 189);
    }

    public I2PByteBlock Padding => Data.Slice(193, 29);

    /// <summary>
    ///     Is inbound gateway.
    /// </summary>
    public bool FromAnyone
    {
        get => (Flag & 0x80) != 0;
        set
        {
            if (ToAnyone && value)
                throw new InvalidOperationException("Both To and From anyone cannot be set at the same time!");
            Flag = (byte)((Flag & 0x7F) | (value ? 0x80 : 0));
        }
    }

    /// <summary>
    ///     Is outbound endpoint.
    /// </summary>
    public bool ToAnyone
    {
        get => (Flag & 0x40) != 0;
        set
        {
            if (FromAnyone && value)
                throw new InvalidOperationException("Both To and From anyone cannot be set at the same time!");
            Flag = (byte)((Flag & 0xBF) | (value ? 0x40 : 0));
        }
    }

    void I2PType.Write(IBufferWriter<byte> dest)
    {
        dest.WriteBlock(Data);
    }

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("BuildRequestRecord");
        result.AppendLine($"ReceiveTunnel : {ReceiveTunnel}");
        result.AppendLine($"OurIdent      : {OurIdent}");
        result.AppendLine($"NextTunnel    : {NextTunnel}");
        result.AppendLine($"NextIdent     : {NextIdent}");
        result.AppendLine($"Flag          : 0x{Flag:X2}");
        result.AppendLine($"ToAnyone      : {ToAnyone}");
        result.AppendLine($"FromAnyone    : {FromAnyone}");
        result.AppendLine($"RequestTime   : {RequestTime}");
        result.AppendLine($"SendMessageId : {SendMessageId}");

        return result.ToString();
    }

    /// <summary>
    ///     High probability to match with similar route.
    /// </summary>
    /// <returns></returns>
    public uint GetReducedHash()
    {
        return ReducedHash;
    }

    private uint CreateReducedHash()
    {
        var result = TickCounter.Now.Ticks / 20000;

        if (FromAnyone)
        {
            result ^= NextIdent.GetHashCode();
            return (uint)result;
        }

        if (ToAnyone)
        {
            result ^= NextIdent.GetHashCode();
            return (uint)result;
        }

        result ^= NextIdent.GetHashCode();
        result ^= NextTunnel.GetHashCode();
        return (uint)result;
    }

    public uint GetHash()
    {
        return (uint)Data.GetHashCode();
    }
}