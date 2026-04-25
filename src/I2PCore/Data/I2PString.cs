using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PString : I2PType
{
    private readonly string Str = "";

    public I2PString()
    {
    }

    public I2PString(I2PString src)
    {
        Str = src.Str;
    }

    public I2PString(string src)
    {
        Str = src;
    }

    public I2PString(Stream src, char[] skipchars)
    {
        Read(src, skipchars);
    }

    public I2PString(I2PBufferCursor buf)
    {
        var len = buf.ReadByte();
        Str = Encoding.UTF8.GetString(buf.BaseArray, buf.BaseArrayOffset, len);
        buf.Seek(len);
    }

    public byte[] GetBytes => Encoding.UTF8.GetBytes(Str);

    public void Write(IBufferWriter<byte> dest)
    {
        var bytes = Encoding.UTF8.GetBytes(Str);
        var l = (byte)Math.Min(255, bytes.Length);
        dest.WriteByte(l);
        dest.WriteBytes(bytes.AsSpan(0, l));
    }

    internal int CompareTo(I2PString other)
    {
        return string.CompareOrdinal(Str, other.Str);
    }

    public void Read(Stream src, char[] skipchars)
    {
        var len = (int)StreamUtils.ReadInt8(src);
        while (skipchars != null && skipchars.Any(c => len == (long)c)) len = StreamUtils.ReadInt8(src);

        var buf = new byte[len];
        var read = src.Read(buf, 0, len);
        if (read != len) throw new EndOfStreamEncounteredException();
        Encoding.UTF8.GetString(buf);
    }

    public override string ToString()
    {
        return Str ?? "[I2PString]";
    }

    public static bool operator ==(I2PString stl, string str)
    {
        return StringComparer.InvariantCulture.Compare(stl?.Str, str) == 0;
    }

    public static bool operator !=(I2PString stl, string str)
    {
        return StringComparer.InvariantCulture.Compare(stl?.Str, str) != 0;
    }

    public override bool Equals(object obj)
    {
        if (obj is I2PString) return Str == ((I2PString)obj)?.Str;
        if (obj is string) return this == (string)obj;
        return false;
    }

    public override int GetHashCode()
    {
        return Str.GetHashCode();
    }
}