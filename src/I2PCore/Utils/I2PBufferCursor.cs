using System;
using System.Buffers.Binary;
using Org.BouncyCastle.Math;

namespace I2PCore.Utils;

/// <summary>
///     Sequential reader/writer over a byte[] with an advancing position.
///     Replaces BufRef and BufRefLen. This is a class (not struct) so that
///     position state is shared when the same cursor is passed to chained
///     constructors (e.g. new I2PLease(reader) → new I2PIdentHash(reader)).
/// </summary>
public sealed class I2PBufferCursor
{
    private readonly int _end; // _start + total length

    // ── Constructors ──

    public I2PBufferCursor(byte[] data)
    {
        BaseArray = data ?? throw new ArgumentNullException(nameof(data));
        StartPosition = 0;
        _end = data.Length;
        Position = 0;
    }

    public I2PBufferCursor(byte[] data, int offset)
    {
        BaseArray = data ?? throw new ArgumentNullException(nameof(data));
        StartPosition = offset;
        _end = data.Length;
        Position = offset;
    }

    public I2PBufferCursor(byte[] data, int offset, int length)
    {
        BaseArray = data ?? throw new ArgumentNullException(nameof(data));
        StartPosition = offset;
        _end = offset + length;
        Position = offset;
    }

    public I2PBufferCursor(I2PByteBlock block)
    {
        BaseArray = block.BaseArray;
        StartPosition = block.BaseArrayOffset;
        _end = block.BaseArrayOffset + block.Length;
        Position = StartPosition;
    }

    // ── Properties ──

    /// <summary>Current read/write position in the underlying array.</summary>
    public int Position { get; private set; }

    /// <summary>The starting offset this cursor was created at.</summary>
    public int StartPosition { get; }

    /// <summary>Bytes remaining from current position to end.</summary>
    public int Remaining => _end - Position;

    /// <summary>Total length of the window this cursor covers.</summary>
    public int Length => _end - StartPosition;

    /// <summary>The underlying byte array. Required for BouncyCastle interop.</summary>
    public byte[] BaseArray { get; }

    /// <summary>Current offset in BaseArray. Same as Position.</summary>
    public int BaseArrayOffset => Position;

    public byte this[int index]
    {
        get => BaseArray[Position + index];
        set => BaseArray[Position + index] = value;
    }

    /// <summary>Returns an I2PByteBlock of the remaining bytes from current position, without advancing.</summary>
    public I2PByteBlock CurrentBlock => new(BaseArray, Position, Remaining);

    /// <summary>Create a sub-cursor sharing the same buffer, starting at current position + offset.</summary>
    public I2PBufferCursor CreateSubCursor(int offset)
    {
        return new I2PBufferCursor(BaseArray, Position + offset);
    }

    /// <summary>Create a sub-cursor sharing the same buffer, starting at current position + offset, with a length bound.</summary>
    public I2PBufferCursor CreateSubCursor(int offset, int length)
    {
        return new I2PBufferCursor(BaseArray, Position + offset, length);
    }

    // ── Position control ──

    public void Reset()
    {
        Position = StartPosition;
    }

    public int Seek(int offset)
    {
        Position += offset;
        return Position;
    }

    // ── Big-endian sequential reads (replaces ReadFlip*) ──

    public ulong ReadUInt64BigEndian()
    {
        var v = BinaryPrimitives.ReadUInt64BigEndian(new ReadOnlySpan<byte>(BaseArray, Position, 8));
        Position += 8;
        return v;
    }

    public uint ReadUInt32BigEndian()
    {
        var v = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(BaseArray, Position, 4));
        Position += 4;
        return v;
    }

    public ushort ReadUInt16BigEndian()
    {
        var v = BinaryPrimitives.ReadUInt16BigEndian(new ReadOnlySpan<byte>(BaseArray, Position, 2));
        Position += 2;
        return v;
    }

    // ── Little-endian sequential reads (replaces Read64/Read32/Read16) ──

    public ulong ReadUInt64LittleEndian()
    {
        var v = BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(BaseArray, Position, 8));
        Position += 8;
        return v;
    }

    public uint ReadUInt32LittleEndian()
    {
        var v = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(BaseArray, Position, 4));
        Position += 4;
        return v;
    }

    public ushort ReadUInt16LittleEndian()
    {
        var v = BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(BaseArray, Position, 2));
        Position += 2;
        return v;
    }

    // ── Single byte ──

    public byte ReadByte()
    {
        return BaseArray[Position++];
    }

    // ── Bulk reads ──

    public byte[] ReadBytes(int count)
    {
        var result = new byte[count];
        Array.Copy(BaseArray, Position, result, 0, count);
        Position += count;
        return result;
    }

    public int ReadBytes(byte[] dest, int destOffset, int count)
    {
        Array.Copy(BaseArray, Position, dest, destOffset, count);
        Position += count;
        return count;
    }

    /// <summary>Returns an I2PByteBlock view into the same underlying buffer and advances position.</summary>
    public I2PByteBlock ReadBlock(int length)
    {
        var block = new I2PByteBlock(BaseArray, Position, length);
        Position += length;
        return block;
    }

    public BigInteger ReadBigInteger(int length)
    {
        var result = new BigInteger(1, BaseArray, Position, length);
        Position += length;
        return result;
    }

    // ── Big-endian sequential writes (replaces WriteFlip*) ──

    public void WriteUInt64BigEndian(ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(new Span<byte>(BaseArray, Position, 8), value);
        Position += 8;
    }

    public void WriteUInt32BigEndian(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(new Span<byte>(BaseArray, Position, 4), value);
        Position += 4;
    }

    public void WriteUInt16BigEndian(ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(new Span<byte>(BaseArray, Position, 2), value);
        Position += 2;
    }

    // ── Little-endian sequential writes ──

    public void WriteUInt64LittleEndian(ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(new Span<byte>(BaseArray, Position, 8), value);
        Position += 8;
    }

    public void WriteUInt32LittleEndian(uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(BaseArray, Position, 4), value);
        Position += 4;
    }

    public void WriteUInt16LittleEndian(ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(new Span<byte>(BaseArray, Position, 2), value);
        Position += 2;
    }

    // ── Single byte write ──

    public void WriteByte(byte value)
    {
        BaseArray[Position++] = value;
    }

    // ── Bulk writes ──

    public int WriteBytes(byte[] src)
    {
        if (src.Length == 0) return 0;
        Array.Copy(src, 0, BaseArray, Position, src.Length);
        Position += src.Length;
        return src.Length;
    }

    public int WriteBytes(ReadOnlySpan<byte> src)
    {
        if (src.Length == 0) return 0;
        src.CopyTo(new Span<byte>(BaseArray, Position, src.Length));
        Position += src.Length;
        return src.Length;
    }

    public int WriteBlock(I2PByteBlock src)
    {
        Array.Copy(src.BaseArray, src.BaseArrayOffset, BaseArray, Position, src.Length);
        Position += src.Length;
        return src.Length;
    }

    // ── Peek/Poke at offset (non-advancing) ──

    public ulong PeekUInt64BigEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(new ReadOnlySpan<byte>(BaseArray, Position + offset, 8));
    }

    public uint PeekUInt32BigEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(BaseArray, Position + offset, 4));
    }

    public ushort PeekUInt16BigEndian(int offset)
    {
        return BinaryPrimitives.ReadUInt16BigEndian(new ReadOnlySpan<byte>(BaseArray, Position + offset, 2));
    }

    public byte PeekByte(int offset)
    {
        return BaseArray[Position + offset];
    }

    public void PokeUInt32BigEndian(uint value, int offset)
    {
        BinaryPrimitives.WriteUInt32BigEndian(new Span<byte>(BaseArray, Position + offset, 4), value);
    }

    public void PokeUInt16BigEndian(ushort value, int offset)
    {
        BinaryPrimitives.WriteUInt16BigEndian(new Span<byte>(BaseArray, Position + offset, 2), value);
    }

    public void PokeByte(byte value, int offset)
    {
        BaseArray[Position + offset] = value;
    }

    public void PokeBytes(byte[] src, int offset)
    {
        Array.Copy(src, 0, BaseArray, Position + offset, src.Length);
    }

    public void PokeBytes(byte[] src, int offset, int maxlen)
    {
        Array.Copy(src, 0, BaseArray, Position + offset, Math.Min(maxlen, src.Length));
    }

    public void PokeBlock(I2PByteBlock src, int offset)
    {
        Array.Copy(src.BaseArray, src.BaseArrayOffset, BaseArray, Position + offset, src.Length);
    }

    public void PokeBlock(I2PByteBlock src, int offset, int maxlen)
    {
        Array.Copy(src.BaseArray, src.BaseArrayOffset, BaseArray, Position + offset, Math.Min(maxlen, src.Length));
    }

    // ── Distance / Arithmetic ──

    /// <summary>
    ///     Compute the distance between this cursor's position and another cursor's position.
    ///     Both must share the same underlying buffer.
    /// </summary>
    public int DistanceFrom(I2PBufferCursor other)
    {
        if (!ReferenceEquals(BaseArray, other.BaseArray))
            throw new InvalidOperationException("Can only compute distance between cursors on the same buffer.");
        return Position - other.Position;
    }

    /// <summary>Distance from a saved position value.</summary>
    public int DistanceFrom(int savedPosition)
    {
        return Position - savedPosition;
    }

    /// <summary>Create a block covering bytes from savedPosition to current position.</summary>
    public I2PByteBlock BlockSince(int savedPosition)
    {
        return new I2PByteBlock(BaseArray, savedPosition, Position - savedPosition);
    }

    /// <summary>
    ///     Create a block covering bytes from savedPosition-padding to current position+padding,
    ///     for the I2NP SetBuffer pattern that includes header space.
    /// </summary>
    public I2PByteBlock BlockSince(int savedPosition, int prePadding)
    {
        return new I2PByteBlock(BaseArray, savedPosition - prePadding, Position - savedPosition + prePadding);
    }

    // ── Conversion helpers ──

    public byte[] ToArray()
    {
        var len = Remaining;
        var result = new byte[len];
        Array.Copy(BaseArray, Position, result, 0, len);
        return result;
    }

    public byte[] ToByteArray()
    {
        if (StartPosition == 0 && Position == 0 && Remaining == BaseArray.Length) return BaseArray;
        var result = new byte[Remaining];
        Array.Copy(BaseArray, Position, result, 0, Remaining);
        return result;
    }

    public override string ToString()
    {
        return $"I2PBufferCursor [{StartPosition}:{Position}], Remaining: {Remaining}";
    }
}