using System;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.ECIES;

/// <summary>
///     ECIES session tag (8 bytes for Proposal 144)
/// </summary>
public class SessionTag : IEquatable<SessionTag>
{
    public const int Length = 8;
    private readonly byte[] _data;

    public SessionTag(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        if (data.Length == Length)
        {
            _data = (byte[])data.Clone();
        }
        else if (data.Length > Length)
        {
            // Truncate from the beginning (per i2pd/spec usage of first 8 bytes)
            _data = new byte[Length];
            Array.Copy(data, 0, _data, 0, Length);
        }
        else
        {
            throw new ArgumentException($"Session tag must be at least {Length} bytes", nameof(data));
        }
    }

    public bool Equals(SessionTag other)
    {
        if (other is null) return false;
        return _data.SequenceEqual(other._data);
    }

    public static SessionTag Generate()
    {
        return new SessionTag(BufUtils.RandomBytes(Length));
    }

    public byte[] ToByteArray()
    {
        return (byte[])_data.Clone();
    }

    public override bool Equals(object obj)
    {
        return Equals(obj as SessionTag);
    }

    public override int GetHashCode()
    {
        return BitConverter.ToUInt64(_data, 0).GetHashCode();
    }

    public static bool operator ==(SessionTag left, SessionTag right)
    {
        if (left is null) return right is null;
        return left.Equals(right);
    }

    public static bool operator !=(SessionTag left, SessionTag right)
    {
        return !(left == right);
    }

    public override string ToString()
    {
        return BitConverter.ToString(_data).Replace("-", "");
    }
}