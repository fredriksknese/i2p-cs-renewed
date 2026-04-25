using System;
using System.Buffers;
using System.Buffers.Binary;

namespace I2PCore.Utils
{
    /// <summary>
    /// Extension methods on IBufferWriter&lt;byte&gt; for writing primitives in big-endian
    /// and little-endian formats. Replaces the BufRefStream.Write + BufUtils.Flip*B pattern.
    /// </summary>
    public static class BufferWriterExtensions
    {
        // ── Big-endian writes ──

        public static void WriteUInt64BigEndian( this IBufferWriter<byte> writer, ulong value )
        {
            var span = writer.GetSpan( 8 );
            BinaryPrimitives.WriteUInt64BigEndian( span, value );
            writer.Advance( 8 );
        }

        public static void WriteUInt32BigEndian( this IBufferWriter<byte> writer, uint value )
        {
            var span = writer.GetSpan( 4 );
            BinaryPrimitives.WriteUInt32BigEndian( span, value );
            writer.Advance( 4 );
        }

        public static void WriteUInt16BigEndian( this IBufferWriter<byte> writer, ushort value )
        {
            var span = writer.GetSpan( 2 );
            BinaryPrimitives.WriteUInt16BigEndian( span, value );
            writer.Advance( 2 );
        }

        // ── Little-endian writes ──

        public static void WriteUInt64LittleEndian( this IBufferWriter<byte> writer, ulong value )
        {
            var span = writer.GetSpan( 8 );
            BinaryPrimitives.WriteUInt64LittleEndian( span, value );
            writer.Advance( 8 );
        }

        public static void WriteUInt32LittleEndian( this IBufferWriter<byte> writer, uint value )
        {
            var span = writer.GetSpan( 4 );
            BinaryPrimitives.WriteUInt32LittleEndian( span, value );
            writer.Advance( 4 );
        }

        public static void WriteUInt16LittleEndian( this IBufferWriter<byte> writer, ushort value )
        {
            var span = writer.GetSpan( 2 );
            BinaryPrimitives.WriteUInt16LittleEndian( span, value );
            writer.Advance( 2 );
        }

        // ── Single byte ──

        public static void WriteByte( this IBufferWriter<byte> writer, byte value )
        {
            var span = writer.GetSpan( 1 );
            span[0] = value;
            writer.Advance( 1 );
        }

        // ── Bulk writes ──

        public static void WriteBytes( this IBufferWriter<byte> writer, ReadOnlySpan<byte> data )
        {
            if ( data.IsEmpty ) return;
            var span = writer.GetSpan( data.Length );
            data.CopyTo( span );
            writer.Advance( data.Length );
        }

        public static void WriteBytes( this IBufferWriter<byte> writer, byte[] data )
        {
            if ( data is null || data.Length == 0 ) return;
            var span = writer.GetSpan( data.Length );
            data.AsSpan().CopyTo( span );
            writer.Advance( data.Length );
        }

        public static void WriteBlock( this IBufferWriter<byte> writer, I2PByteBlock block )
        {
            if ( block.Length == 0 ) return;
            var span = writer.GetSpan( block.Length );
            block.Span.CopyTo( span );
            writer.Advance( block.Length );
        }

        /// <summary>Write another writer's content.</summary>
        public static void WriteFrom( this IBufferWriter<byte> writer, ArrayBufferWriter<byte> source )
        {
            writer.WriteBytes( source.WrittenSpan );
        }
    }
}
