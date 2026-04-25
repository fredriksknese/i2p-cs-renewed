using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Math;

namespace I2PCore.Utils;

/// <summary>
///     Immutable-shape view over a byte[] with value equality, comparison, and hashing.
///     Replaces BufLen. The struct itself is readonly but the underlying bytes are mutable
///     (needed for in-place crypto).
/// </summary>
public readonly struct I2PByteBlock : IEquatable<I2PByteBlock>, IComparable<I2PByteBlock>,
    IEnumerable<byte>, IFormattable
{
    public I2PByteBlock(byte[] data)
    {
        BaseArray = data ?? throw new ArgumentNullException(nameof(data));
        BaseArrayOffset = 0;
        Length = data.Length;
    }

    public I2PByteBlock(byte[] data, int offset)
    {
        BaseArray = data ?? throw new ArgumentNullException(nameof(data));
        BaseArrayOffset = offset;
        Length = data.Length - offset;
    }

    public I2PByteBlock(byte[] data, int offset, int length)
    {
        BaseArray = data ?? throw new ArgumentNullException(nameof(data));
        BaseArrayOffset = offset;
        Length = Math.Min(length, data.Length - offset);
    }

    /// <summary>True when this block has a backing array (default structs do not).</summary>
    public bool IsEmpty => BaseArray is null;

    public int Length { get; }

    /// <summary>Read-only span over the block's bytes.</summary>
    public ReadOnlySpan<byte> Span => new(BaseArray, BaseArrayOffset, Length);

    /// <summary>Writable span — use for in-place crypto, randomization, etc.</summary>
    public Span<byte> MutableSpan => new(BaseArray, BaseArrayOffset, Length);

    /// <summary>The underlying byte array. Required for BouncyCastle interop.</summary>
    public byte[] BaseArray { get; }

    /// <summary>Offset into BaseArray where this block starts.</summary>
    public int BaseArrayOffset { get; }

    public byte this[int index]
    {
        get => BaseArray[BaseArrayOffset + index];
        set => BaseArray[BaseArrayOffset + index] = value;
    }

    // ── Big-endian peek/poke (replaces PeekFlip / PokeFlip) ──

    public ulong ReadUInt64BigEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(new ReadOnlySpan<byte>(BaseArray, BaseArrayOffset + offset, 8));
    }

    public uint ReadUInt32BigEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(BaseArray, BaseArrayOffset + offset, 4));
    }

    public ushort ReadUInt16BigEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt16BigEndian(new ReadOnlySpan<byte>(BaseArray, BaseArrayOffset + offset, 2));
    }

    public void WriteUInt64BigEndian(ulong value, int offset)
    {
        BinaryPrimitives.WriteUInt64BigEndian(new Span<byte>(BaseArray, BaseArrayOffset + offset, 8), value);
    }

    public void WriteUInt32BigEndian(uint value, int offset)
    {
        BinaryPrimitives.WriteUInt32BigEndian(new Span<byte>(BaseArray, BaseArrayOffset + offset, 4), value);
    }

    public void WriteUInt16BigEndian(ushort value, int offset)
    {
        BinaryPrimitives.WriteUInt16BigEndian(new Span<byte>(BaseArray, BaseArrayOffset + offset, 2), value);
    }

    // ── Little-endian peek/poke (replaces Peek32 / Poke32 etc.) ──

    public ulong ReadUInt64LittleEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(BaseArray, BaseArrayOffset + offset, 8));
    }

    public uint ReadUInt32LittleEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(BaseArray, BaseArrayOffset + offset, 4));
    }

    public ushort ReadUInt16LittleEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(BaseArray, BaseArrayOffset + offset, 2));
    }

    public void WriteUInt64LittleEndian(ulong value, int offset)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(new Span<byte>(BaseArray, BaseArrayOffset + offset, 8), value);
    }

    public void WriteUInt32LittleEndian(uint value, int offset)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(BaseArray, BaseArrayOffset + offset, 4), value);
    }

    public void WriteUInt16LittleEndian(ushort value, int offset)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(new Span<byte>(BaseArray, BaseArrayOffset + offset, 2), value);
    }

    // ── Single byte ──

    public byte ReadByte(int offset)
    {
        return BaseArray[BaseArrayOffset + offset];
    }

    public void WriteByte(byte value, int offset)
    {
        BaseArray[BaseArrayOffset + offset] = value;
    }

    // ── Bulk read/write ──

    public void Peek(byte[] dest, int srcOffset, int destOffset, int count)
    {
        Array.Copy(BaseArray, BaseArrayOffset + srcOffset, dest, destOffset, count);
    }

    public byte[] PeekBytes(int offset, int count)
    {
        var result = new byte[count];
        Array.Copy(BaseArray, BaseArrayOffset + offset, result, 0, count);
        return result;
    }

    public void CopyFrom(ReadOnlySpan<byte> source, int destOffset)
    {
        source.CopyTo(new Span<byte>(BaseArray, BaseArrayOffset + destOffset, source.Length));
    }

    public void CopyFrom(I2PByteBlock source, int destOffset)
    {
        Array.Copy(source.BaseArray, source.BaseArrayOffset, BaseArray, BaseArrayOffset + destOffset, source.Length);
    }

    public void CopyFrom(I2PByteBlock source, int destOffset, int maxlen)
    {
        Array.Copy(source.BaseArray, source.BaseArrayOffset, BaseArray, BaseArrayOffset + destOffset,
            Math.Min(maxlen, source.Length));
    }

    public void CopyTo(Span<byte> destination)
    {
        Span.CopyTo(destination);
    }

    public void CopyTo(byte[] dest, int destOffset)
    {
        Array.Copy(BaseArray, BaseArrayOffset, dest, destOffset, Length);
    }

    // ── Slice / Clone / Convert ──

    public I2PByteBlock Slice(int offset)
    {
        return new I2PByteBlock(BaseArray, BaseArrayOffset + offset, Length - offset);
    }

    public I2PByteBlock Slice(int offset, int length)
    {
        return new I2PByteBlock(BaseArray, BaseArrayOffset + offset, length);
    }

    public I2PByteBlock Clone()
    {
        var copy = new byte[Length];
        Array.Copy(BaseArray, BaseArrayOffset, copy, 0, Length);
        return new I2PByteBlock(copy);
    }

    public static I2PByteBlock Clone(byte[] buf, int offset, int length)
    {
        var copy = new byte[length];
        Array.Copy(buf, offset, copy, 0, length);
        return new I2PByteBlock(copy);
    }

    public byte[] ToByteArray()
    {
        if (BaseArrayOffset == 0 && Length == BaseArray.Length) return BaseArray;
        return PeekBytes(0, Length);
    }

    public byte[] ToArray()
    {
        return ToByteArray();
    }

    public BigInteger ToBigInteger()
    {
        return new BigInteger(1, BaseArray, BaseArrayOffset, Length);
    }

    public string ToEncoding(Encoding enc)
    {
        return enc.GetString(BaseArray, BaseArrayOffset, Length);
    }

    // ── Writer integration ──

    public void WriteTo(IBufferWriter<byte> writer)
    {
        var span = writer.GetSpan(Length);
        Span.CopyTo(span);
        writer.Advance(Length);
    }

    // ── Check if two blocks share the same underlying array ──

    public static bool SameBuffer(I2PByteBlock left, I2PByteBlock right)
    {
        return ReferenceEquals(left.BaseArray, right.BaseArray);
    }

    // ── Equality (deep byte comparison) ──

    public bool Equals(I2PByteBlock other)
    {
        if (Length != other.Length) return false;
        if (BaseArray is null && other.BaseArray is null) return true;
        if (BaseArray is null || other.BaseArray is null) return false;
        return Span.SequenceEqual(other.Span);
    }

    public bool Equals(byte[] other)
    {
        if (other is null) return false;
        if (Length != other.Length) return false;
        return Span.SequenceEqual(other);
    }

    public override bool Equals(object obj)
    {
        return obj is I2PByteBlock other && Equals(other);
    }

    public override int GetHashCode()
    {
        unchecked
        {
            const int p = 16777619;
            var hash = (int)2166136261;

            var end = BaseArrayOffset + Length;
            for (var i = BaseArrayOffset; i < end; ++i)
                hash = (hash ^ BaseArray[i]) * p;

            hash += hash << 13;
            hash ^= hash >> 7;
            hash += hash << 3;
            hash ^= hash >> 17;
            hash += hash << 5;
            return hash;
        }
    }

    // ── Comparison (lexicographic) ──

    public int CompareTo(I2PByteBlock other)
    {
        var len = Math.Min(Length, other.Length);
        for (var i = 0; i < len; ++i)
        {
            var c = BaseArray[BaseArrayOffset + i] - other.BaseArray[other.BaseArrayOffset + i];
            if (c != 0) return Math.Sign(c);
        }

        return Length.CompareTo(other.Length);
    }

    public static int Compare(I2PByteBlock b1, I2PByteBlock b2)
    {
        return b1.CompareTo(b2);
    }

    // ── Operators ──

    public static bool operator ==(I2PByteBlock left, I2PByteBlock right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(I2PByteBlock left, I2PByteBlock right)
    {
        return !left.Equals(right);
    }

    public static bool operator >(I2PByteBlock left, I2PByteBlock right)
    {
        return left.CompareTo(right) > 0;
    }

    public static bool operator <(I2PByteBlock left, I2PByteBlock right)
    {
        return left.CompareTo(right) < 0;
    }

    // ── IEnumerable<byte> ──

    public IEnumerator<byte> GetEnumerator()
    {
        for (var i = BaseArrayOffset; i < BaseArrayOffset + Length; ++i)
            yield return BaseArray[i];
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    // ── ToString / IFormattable ──

    public override string ToString()
    {
        return ToString("8", null);
    }

    public string ToString(string format, IFormatProvider formatProvider)
    {
        if (BaseArray is null) return "I2PByteBlock [null]";

        var maxlen = 8;
        if (int.TryParse(format, out var parsed)) maxlen = parsed;

        var sb = new StringBuilder();
        sb.Append($"I2PByteBlock [{BaseArrayOffset}], Length: {Length} [");

        for (var i = 0; i < Length && i < maxlen; ++i)
        {
            if (i > 0) sb.Append(',');
            sb.Append($"0x{BaseArray[BaseArrayOffset + i]:X2}");
        }

        sb.Append(']');
        return sb.ToString();
    }

    public string ToHexDump(int width = 16)
    {
        var sb = new StringBuilder();
        for (var lineStart = 0; lineStart < Length; lineStart += width)
        {
            sb.Append($"{lineStart:X4} : ");
            for (var col = 0; col < width; ++col)
            {
                var idx = lineStart + col;
                sb.Append(idx < Length ? $"{BaseArray[BaseArrayOffset + idx]:X2} " : "   ");
            }

            sb.Append("| ");
            for (var col = 0; col < width; ++col)
            {
                var idx = lineStart + col;
                if (idx < Length)
                {
                    var b = BaseArray[BaseArrayOffset + idx];
                    sb.Append(b > 30 ? (char)b : '.');
                }
                else
                {
                    sb.Append(' ');
                }
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }
}