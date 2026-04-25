using System;
using System.Buffers.Binary;
using Org.BouncyCastle.Math;

namespace I2PCore.Utils
{
    /// <summary>
    /// Sequential reader/writer over a byte[] with an advancing position.
    /// Replaces BufRef and BufRefLen. This is a class (not struct) so that
    /// position state is shared when the same cursor is passed to chained
    /// constructors (e.g. new I2PLease(reader) → new I2PIdentHash(reader)).
    /// </summary>
    public sealed class I2PBufferCursor
    {
        private readonly byte[] _buffer;
        private readonly int _start;
        private readonly int _end;   // _start + total length
        private int _position;

        // ── Constructors ──

        public I2PBufferCursor( byte[] data )
        {
            _buffer = data ?? throw new ArgumentNullException( nameof( data ) );
            _start = 0;
            _end = data.Length;
            _position = 0;
        }

        public I2PBufferCursor( byte[] data, int offset )
        {
            _buffer = data ?? throw new ArgumentNullException( nameof( data ) );
            _start = offset;
            _end = data.Length;
            _position = offset;
        }

        public I2PBufferCursor( byte[] data, int offset, int length )
        {
            _buffer = data ?? throw new ArgumentNullException( nameof( data ) );
            _start = offset;
            _end = offset + length;
            _position = offset;
        }

        public I2PBufferCursor( I2PByteBlock block )
        {
            _buffer = block.BaseArray;
            _start = block.BaseArrayOffset;
            _end = block.BaseArrayOffset + block.Length;
            _position = _start;
        }

        /// <summary>Create a sub-cursor sharing the same buffer, starting at current position + offset.</summary>
        public I2PBufferCursor CreateSubCursor( int offset )
            => new( _buffer, _position + offset );

        /// <summary>Create a sub-cursor sharing the same buffer, starting at current position + offset, with a length bound.</summary>
        public I2PBufferCursor CreateSubCursor( int offset, int length )
            => new( _buffer, _position + offset, length );

        // ── Properties ──

        /// <summary>Current read/write position in the underlying array.</summary>
        public int Position => _position;

        /// <summary>The starting offset this cursor was created at.</summary>
        public int StartPosition => _start;

        /// <summary>Bytes remaining from current position to end.</summary>
        public int Remaining => _end - _position;

        /// <summary>Total length of the window this cursor covers.</summary>
        public int Length => _end - _start;

        /// <summary>The underlying byte array. Required for BouncyCastle interop.</summary>
        public byte[] BaseArray => _buffer;

        /// <summary>Current offset in BaseArray. Same as Position.</summary>
        public int BaseArrayOffset => _position;

        public byte this[int index]
        {
            get => _buffer[_position + index];
            set => _buffer[_position + index] = value;
        }

        // ── Position control ──

        public void Reset() => _position = _start;
        public int Seek( int offset ) { _position += offset; return _position; }

        // ── Big-endian sequential reads (replaces ReadFlip*) ──

        public ulong ReadUInt64BigEndian()
        {
            var v = BinaryPrimitives.ReadUInt64BigEndian( new ReadOnlySpan<byte>( _buffer, _position, 8 ) );
            _position += 8;
            return v;
        }

        public uint ReadUInt32BigEndian()
        {
            var v = BinaryPrimitives.ReadUInt32BigEndian( new ReadOnlySpan<byte>( _buffer, _position, 4 ) );
            _position += 4;
            return v;
        }

        public ushort ReadUInt16BigEndian()
        {
            var v = BinaryPrimitives.ReadUInt16BigEndian( new ReadOnlySpan<byte>( _buffer, _position, 2 ) );
            _position += 2;
            return v;
        }

        // ── Little-endian sequential reads (replaces Read64/Read32/Read16) ──

        public ulong ReadUInt64LittleEndian()
        {
            var v = BinaryPrimitives.ReadUInt64LittleEndian( new ReadOnlySpan<byte>( _buffer, _position, 8 ) );
            _position += 8;
            return v;
        }

        public uint ReadUInt32LittleEndian()
        {
            var v = BinaryPrimitives.ReadUInt32LittleEndian( new ReadOnlySpan<byte>( _buffer, _position, 4 ) );
            _position += 4;
            return v;
        }

        public ushort ReadUInt16LittleEndian()
        {
            var v = BinaryPrimitives.ReadUInt16LittleEndian( new ReadOnlySpan<byte>( _buffer, _position, 2 ) );
            _position += 2;
            return v;
        }

        // ── Single byte ──

        public byte ReadByte()
        {
            return _buffer[_position++];
        }

        // ── Bulk reads ──

        public byte[] ReadBytes( int count )
        {
            var result = new byte[count];
            Array.Copy( _buffer, _position, result, 0, count );
            _position += count;
            return result;
        }

        public int ReadBytes( byte[] dest, int destOffset, int count )
        {
            Array.Copy( _buffer, _position, dest, destOffset, count );
            _position += count;
            return count;
        }

        /// <summary>Returns an I2PByteBlock view into the same underlying buffer and advances position.</summary>
        public I2PByteBlock ReadBlock( int length )
        {
            var block = new I2PByteBlock( _buffer, _position, length );
            _position += length;
            return block;
        }

        public BigInteger ReadBigInteger( int length )
        {
            var result = new BigInteger( 1, _buffer, _position, length );
            _position += length;
            return result;
        }

        /// <summary>Returns an I2PByteBlock of the remaining bytes from current position, without advancing.</summary>
        public I2PByteBlock CurrentBlock => new( _buffer, _position, Remaining );

        // ── Big-endian sequential writes (replaces WriteFlip*) ──

        public void WriteUInt64BigEndian( ulong value )
        {
            BinaryPrimitives.WriteUInt64BigEndian( new Span<byte>( _buffer, _position, 8 ), value );
            _position += 8;
        }

        public void WriteUInt32BigEndian( uint value )
        {
            BinaryPrimitives.WriteUInt32BigEndian( new Span<byte>( _buffer, _position, 4 ), value );
            _position += 4;
        }

        public void WriteUInt16BigEndian( ushort value )
        {
            BinaryPrimitives.WriteUInt16BigEndian( new Span<byte>( _buffer, _position, 2 ), value );
            _position += 2;
        }

        // ── Little-endian sequential writes ──

        public void WriteUInt64LittleEndian( ulong value )
        {
            BinaryPrimitives.WriteUInt64LittleEndian( new Span<byte>( _buffer, _position, 8 ), value );
            _position += 8;
        }

        public void WriteUInt32LittleEndian( uint value )
        {
            BinaryPrimitives.WriteUInt32LittleEndian( new Span<byte>( _buffer, _position, 4 ), value );
            _position += 4;
        }

        public void WriteUInt16LittleEndian( ushort value )
        {
            BinaryPrimitives.WriteUInt16LittleEndian( new Span<byte>( _buffer, _position, 2 ), value );
            _position += 2;
        }

        // ── Single byte write ──

        public void WriteByte( byte value )
        {
            _buffer[_position++] = value;
        }

        // ── Bulk writes ──

        public int WriteBytes( byte[] src )
        {
            if ( src.Length == 0 ) return 0;
            Array.Copy( src, 0, _buffer, _position, src.Length );
            _position += src.Length;
            return src.Length;
        }

        public int WriteBytes( ReadOnlySpan<byte> src )
        {
            if ( src.Length == 0 ) return 0;
            src.CopyTo( new Span<byte>( _buffer, _position, src.Length ) );
            _position += src.Length;
            return src.Length;
        }

        public int WriteBlock( I2PByteBlock src )
        {
            Array.Copy( src.BaseArray, src.BaseArrayOffset, _buffer, _position, src.Length );
            _position += src.Length;
            return src.Length;
        }

        // ── Peek/Poke at offset (non-advancing) ──

        public ulong PeekUInt64BigEndian( int offset )
            => BinaryPrimitives.ReadUInt64BigEndian( new ReadOnlySpan<byte>( _buffer, _position + offset, 8 ) );

        public uint PeekUInt32BigEndian( int offset )
            => BinaryPrimitives.ReadUInt32BigEndian( new ReadOnlySpan<byte>( _buffer, _position + offset, 4 ) );

        public ushort PeekUInt16BigEndian( int offset )
            => BinaryPrimitives.ReadUInt16BigEndian( new ReadOnlySpan<byte>( _buffer, _position + offset, 2 ) );

        public byte PeekByte( int offset ) => _buffer[_position + offset];

        public void PokeUInt32BigEndian( uint value, int offset )
            => BinaryPrimitives.WriteUInt32BigEndian( new Span<byte>( _buffer, _position + offset, 4 ), value );

        public void PokeUInt16BigEndian( ushort value, int offset )
            => BinaryPrimitives.WriteUInt16BigEndian( new Span<byte>( _buffer, _position + offset, 2 ), value );

        public void PokeByte( byte value, int offset ) => _buffer[_position + offset] = value;

        public void PokeBytes( byte[] src, int offset )
            => Array.Copy( src, 0, _buffer, _position + offset, src.Length );

        public void PokeBytes( byte[] src, int offset, int maxlen )
            => Array.Copy( src, 0, _buffer, _position + offset, Math.Min( maxlen, src.Length ) );

        public void PokeBlock( I2PByteBlock src, int offset )
            => Array.Copy( src.BaseArray, src.BaseArrayOffset, _buffer, _position + offset, src.Length );

        public void PokeBlock( I2PByteBlock src, int offset, int maxlen )
            => Array.Copy( src.BaseArray, src.BaseArrayOffset, _buffer, _position + offset, Math.Min( maxlen, src.Length ) );

        // ── Distance / Arithmetic ──

        /// <summary>Compute the distance between this cursor's position and another cursor's position.
        /// Both must share the same underlying buffer.</summary>
        public int DistanceFrom( I2PBufferCursor other )
        {
            if ( !ReferenceEquals( _buffer, other._buffer ) )
                throw new InvalidOperationException( "Can only compute distance between cursors on the same buffer." );
            return _position - other._position;
        }

        /// <summary>Distance from a saved position value.</summary>
        public int DistanceFrom( int savedPosition ) => _position - savedPosition;

        /// <summary>Create a block covering bytes from savedPosition to current position.</summary>
        public I2PByteBlock BlockSince( int savedPosition )
            => new( _buffer, savedPosition, _position - savedPosition );

        /// <summary>Create a block covering bytes from savedPosition-padding to current position+padding,
        /// for the I2NP SetBuffer pattern that includes header space.</summary>
        public I2PByteBlock BlockSince( int savedPosition, int prePadding )
            => new( _buffer, savedPosition - prePadding, _position - savedPosition + prePadding );

        // ── Conversion helpers ──

        public byte[] ToArray()
        {
            var len = Remaining;
            var result = new byte[len];
            Array.Copy( _buffer, _position, result, 0, len );
            return result;
        }

        public byte[] ToByteArray()
        {
            if ( _start == 0 && _position == 0 && Remaining == _buffer.Length ) return _buffer;
            var result = new byte[Remaining];
            Array.Copy( _buffer, _position, result, 0, Remaining );
            return result;
        }

        public override string ToString()
        {
            return $"I2PBufferCursor [{_start}:{_position}], Remaining: {Remaining}";
        }
    }
}
