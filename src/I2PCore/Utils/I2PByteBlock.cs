using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Math;

namespace I2PCore.Utils
{
    /// <summary>
    /// Immutable-shape view over a byte[] with value equality, comparison, and hashing.
    /// Replaces BufLen. The struct itself is readonly but the underlying bytes are mutable
    /// (needed for in-place crypto).
    /// </summary>
    public readonly struct I2PByteBlock : IEquatable<I2PByteBlock>, IComparable<I2PByteBlock>,
        IEnumerable<byte>, IFormattable
    {
        private readonly byte[] _array;
        private readonly int _offset;
        private readonly int _length;

        public I2PByteBlock( byte[] data )
        {
            _array = data ?? throw new ArgumentNullException( nameof( data ) );
            _offset = 0;
            _length = data.Length;
        }

        public I2PByteBlock( byte[] data, int offset )
        {
            _array = data ?? throw new ArgumentNullException( nameof( data ) );
            _offset = offset;
            _length = data.Length - offset;
        }

        public I2PByteBlock( byte[] data, int offset, int length )
        {
            _array = data ?? throw new ArgumentNullException( nameof( data ) );
            _offset = offset;
            _length = Math.Min( length, data.Length - offset );
        }

        /// <summary>True when this block has a backing array (default structs do not).</summary>
        public bool IsEmpty => _array is null;

        public int Length => _length;

        /// <summary>Read-only span over the block's bytes.</summary>
        public ReadOnlySpan<byte> Span => new( _array, _offset, _length );

        /// <summary>Writable span — use for in-place crypto, randomization, etc.</summary>
        public Span<byte> MutableSpan => new( _array, _offset, _length );

        /// <summary>The underlying byte array. Required for BouncyCastle interop.</summary>
        public byte[] BaseArray => _array;

        /// <summary>Offset into BaseArray where this block starts.</summary>
        public int BaseArrayOffset => _offset;

        public byte this[int index]
        {
            get => _array[_offset + index];
            set => _array[_offset + index] = value;
        }

        // ── Big-endian peek/poke (replaces PeekFlip / PokeFlip) ──

        public ulong ReadUInt64BigEndian( int offset )
            => BinaryPrimitives.ReadUInt64BigEndian( new ReadOnlySpan<byte>( _array, _offset + offset, 8 ) );

        public uint ReadUInt32BigEndian( int offset )
            => BinaryPrimitives.ReadUInt32BigEndian( new ReadOnlySpan<byte>( _array, _offset + offset, 4 ) );

        public ushort ReadUInt16BigEndian( int offset )
            => BinaryPrimitives.ReadUInt16BigEndian( new ReadOnlySpan<byte>( _array, _offset + offset, 2 ) );

        public void WriteUInt64BigEndian( ulong value, int offset )
            => BinaryPrimitives.WriteUInt64BigEndian( new Span<byte>( _array, _offset + offset, 8 ), value );

        public void WriteUInt32BigEndian( uint value, int offset )
            => BinaryPrimitives.WriteUInt32BigEndian( new Span<byte>( _array, _offset + offset, 4 ), value );

        public void WriteUInt16BigEndian( ushort value, int offset )
            => BinaryPrimitives.WriteUInt16BigEndian( new Span<byte>( _array, _offset + offset, 2 ), value );

        // ── Little-endian peek/poke (replaces Peek32 / Poke32 etc.) ──

        public ulong ReadUInt64LittleEndian( int offset )
            => BinaryPrimitives.ReadUInt64LittleEndian( new ReadOnlySpan<byte>( _array, _offset + offset, 8 ) );

        public uint ReadUInt32LittleEndian( int offset )
            => BinaryPrimitives.ReadUInt32LittleEndian( new ReadOnlySpan<byte>( _array, _offset + offset, 4 ) );

        public ushort ReadUInt16LittleEndian( int offset )
            => BinaryPrimitives.ReadUInt16LittleEndian( new ReadOnlySpan<byte>( _array, _offset + offset, 2 ) );

        public void WriteUInt64LittleEndian( ulong value, int offset )
            => BinaryPrimitives.WriteUInt64LittleEndian( new Span<byte>( _array, _offset + offset, 8 ), value );

        public void WriteUInt32LittleEndian( uint value, int offset )
            => BinaryPrimitives.WriteUInt32LittleEndian( new Span<byte>( _array, _offset + offset, 4 ), value );

        public void WriteUInt16LittleEndian( ushort value, int offset )
            => BinaryPrimitives.WriteUInt16LittleEndian( new Span<byte>( _array, _offset + offset, 2 ), value );

        // ── Single byte ──

        public byte ReadByte( int offset ) => _array[_offset + offset];
        public void WriteByte( byte value, int offset ) => _array[_offset + offset] = value;

        // ── Bulk read/write ──

        public void Peek( byte[] dest, int srcOffset, int destOffset, int count )
            => Array.Copy( _array, _offset + srcOffset, dest, destOffset, count );

        public byte[] PeekBytes( int offset, int count )
        {
            var result = new byte[count];
            Array.Copy( _array, _offset + offset, result, 0, count );
            return result;
        }

        public void CopyFrom( ReadOnlySpan<byte> source, int destOffset )
            => source.CopyTo( new Span<byte>( _array, _offset + destOffset, source.Length ) );

        public void CopyFrom( I2PByteBlock source, int destOffset )
            => Array.Copy( source._array, source._offset, _array, _offset + destOffset, source._length );

        public void CopyFrom( I2PByteBlock source, int destOffset, int maxlen )
            => Array.Copy( source._array, source._offset, _array, _offset + destOffset, Math.Min( maxlen, source._length ) );

        public void CopyTo( Span<byte> destination )
            => Span.CopyTo( destination );

        public void CopyTo( byte[] dest, int destOffset )
            => Array.Copy( _array, _offset, dest, destOffset, _length );

        // ── Slice / Clone / Convert ──

        public I2PByteBlock Slice( int offset )
            => new( _array, _offset + offset, _length - offset );

        public I2PByteBlock Slice( int offset, int length )
            => new( _array, _offset + offset, length );

        public I2PByteBlock Clone()
        {
            var copy = new byte[_length];
            Array.Copy( _array, _offset, copy, 0, _length );
            return new I2PByteBlock( copy );
        }

        public static I2PByteBlock Clone( byte[] buf, int offset, int length )
        {
            var copy = new byte[length];
            Array.Copy( buf, offset, copy, 0, length );
            return new I2PByteBlock( copy );
        }

        public byte[] ToByteArray()
        {
            if ( _offset == 0 && _length == _array.Length ) return _array;
            return PeekBytes( 0, _length );
        }

        public byte[] ToArray() => ToByteArray();

        public BigInteger ToBigInteger()
            => new( 1, _array, _offset, _length );

        public string ToEncoding( Encoding enc )
            => enc.GetString( _array, _offset, _length );

        // ── Writer integration ──

        public void WriteTo( IBufferWriter<byte> writer )
        {
            var span = writer.GetSpan( _length );
            Span.CopyTo( span );
            writer.Advance( _length );
        }

        // ── Check if two blocks share the same underlying array ──

        public static bool SameBuffer( I2PByteBlock left, I2PByteBlock right )
            => ReferenceEquals( left._array, right._array );

        // ── Equality (deep byte comparison) ──

        public bool Equals( I2PByteBlock other )
        {
            if ( _length != other._length ) return false;
            if ( _array is null && other._array is null ) return true;
            if ( _array is null || other._array is null ) return false;
            return Span.SequenceEqual( other.Span );
        }

        public bool Equals( byte[] other )
        {
            if ( other is null ) return false;
            if ( _length != other.Length ) return false;
            return Span.SequenceEqual( other );
        }

        public override bool Equals( object obj )
            => obj is I2PByteBlock other && Equals( other );

        public override int GetHashCode()
        {
            unchecked
            {
                const int p = 16777619;
                int hash = (int)2166136261;

                var end = _offset + _length;
                for ( int i = _offset; i < end; ++i )
                    hash = ( hash ^ _array[i] ) * p;

                hash += hash << 13;
                hash ^= hash >> 7;
                hash += hash << 3;
                hash ^= hash >> 17;
                hash += hash << 5;
                return hash;
            }
        }

        // ── Comparison (lexicographic) ──

        public int CompareTo( I2PByteBlock other )
        {
            var len = Math.Min( _length, other._length );
            for ( int i = 0; i < len; ++i )
            {
                var c = _array[_offset + i] - other._array[other._offset + i];
                if ( c != 0 ) return Math.Sign( c );
            }
            return _length.CompareTo( other._length );
        }

        public static int Compare( I2PByteBlock b1, I2PByteBlock b2 ) => b1.CompareTo( b2 );

        // ── Operators ──

        public static bool operator ==( I2PByteBlock left, I2PByteBlock right ) => left.Equals( right );
        public static bool operator !=( I2PByteBlock left, I2PByteBlock right ) => !left.Equals( right );
        public static bool operator >( I2PByteBlock left, I2PByteBlock right ) => left.CompareTo( right ) > 0;
        public static bool operator <( I2PByteBlock left, I2PByteBlock right ) => left.CompareTo( right ) < 0;

        // ── IEnumerable<byte> ──

        public IEnumerator<byte> GetEnumerator()
        {
            for ( int i = _offset; i < _offset + _length; ++i )
                yield return _array[i];
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        // ── ToString / IFormattable ──

        public override string ToString() => ToString( "8", null );

        public string ToString( string format, IFormatProvider formatProvider )
        {
            if ( _array is null ) return "I2PByteBlock [null]";

            int maxlen = 8;
            if ( int.TryParse( format, out var parsed ) ) maxlen = parsed;

            var sb = new StringBuilder();
            sb.Append( $"I2PByteBlock [{_offset}], Length: {_length} [" );

            for ( int i = 0; i < _length && i < maxlen; ++i )
            {
                if ( i > 0 ) sb.Append( ',' );
                sb.Append( $"0x{_array[_offset + i]:X2}" );
            }
            sb.Append( ']' );
            return sb.ToString();
        }

        public string ToHexDump( int width = 16 )
        {
            var sb = new StringBuilder();
            for ( int lineStart = 0; lineStart < _length; lineStart += width )
            {
                sb.Append( $"{lineStart:X4} : " );
                for ( int col = 0; col < width; ++col )
                {
                    var idx = lineStart + col;
                    sb.Append( idx < _length ? $"{_array[_offset + idx]:X2} " : "   " );
                }
                sb.Append( "| " );
                for ( int col = 0; col < width; ++col )
                {
                    var idx = lineStart + col;
                    if ( idx < _length )
                    {
                        var b = _array[_offset + idx];
                        sb.Append( b > 30 ? (char)b : '.' );
                    }
                    else
                    {
                        sb.Append( ' ' );
                    }
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }
    }
}
