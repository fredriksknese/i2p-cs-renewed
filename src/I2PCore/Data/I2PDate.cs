using System;
using System.Buffers;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PDate : I2PType, IComparable, IComparable<I2PDate>
{
    public static readonly I2PDate Zero = new(0);

    public static readonly DateTime RefDate = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private ulong DateMilliseconds;

    private I2PDate()
    {
    }

    /// <summary>
    ///     Set value explicitly.
    /// </summary>
    /// <param name="val">Milliseconds since Jan 1st 1970.</param>
    public I2PDate(ulong val)
    {
        DateMilliseconds = val;
    }

    public I2PDate(I2PBufferCursor reader)
    {
        DateMilliseconds = reader.ReadUInt64BigEndian();
    }

    public I2PDate(I2PDate date)
    {
        DateMilliseconds = date.DateMilliseconds;
    }

    public I2PDate(DateTime dt)
    {
        DateMilliseconds = (ulong)(dt - RefDate).TotalMilliseconds;
    }

    public static I2PDate Now => new(DateTime.UtcNow);

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteUInt64BigEndian(DateMilliseconds);
    }

    public int CompareTo(object obj)
    {
        if (obj is null) return 1;
        var other = obj as I2PDate;
        if (other is null) return 1;
        if (DateMilliseconds == other.DateMilliseconds) return 0;
        return DateMilliseconds > other.DateMilliseconds ? 1 : -1;
    }

    public int CompareTo(I2PDate other)
    {
        if (other is null) return 1;
        if (DateMilliseconds == other.DateMilliseconds) return 0;
        return DateMilliseconds > other.DateMilliseconds ? 1 : -1;
    }

    public void Write(I2PBufferCursor dest)
    {
        dest.WriteUInt64BigEndian(DateMilliseconds);
    }

    public void Poke(I2PByteBlock dest, int offset)
    {
        dest.WriteUInt64BigEndian(DateMilliseconds, offset);
    }

    public ulong Nudge()
    {
        return ++DateMilliseconds;
    }

    public override string ToString()
    {
        return (RefDate + new TimeSpan((long)DateMilliseconds * 10000)).ToString();
    }

    public static explicit operator DateTime(I2PDate date)
    {
        return RefDate + TimeSpan.FromMilliseconds(date.DateMilliseconds);
    }

    public static explicit operator ulong(I2PDate date)
    {
        return date.DateMilliseconds;
    }
}