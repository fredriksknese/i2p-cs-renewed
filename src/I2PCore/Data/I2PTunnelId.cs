using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2PTunnelId : I2PType
    {
        public static readonly I2PTunnelId Zero = new( (uint)0 );

        /// <summary>
        /// Tunnel IDs are written in big-endian (network byte order) per I2P spec.
        /// </summary>
        private uint Id;

        public I2PTunnelId()
        {
            Id = BufUtils.RandomUint();
        }

        public I2PTunnelId( UInt32 id )
        {
            Id = id;
        }

        public I2PTunnelId( I2PTunnelId src )
        {
            Id = src.Id;
        }

        public I2PTunnelId( I2PBufferCursor buf )
        {
            Id = buf.ReadUInt32BigEndian();
        }

        public void Write( IBufferWriter<byte> dest )
        {
            dest.WriteUInt32BigEndian( Id );
        }

        public void Write( I2PBufferCursor dest )
        {
            dest.WriteUInt32BigEndian( Id );
        }

        public override string ToString()
        {
            return $"I2PTunnelId: {Id}";
        }

        public static bool operator ==( I2PTunnelId left, I2PTunnelId right )
        {
            if ( left is null && right is null ) return true;
            if ( left is null || right is null ) return false;
            return left.Id == right.Id;
        }

        public static bool operator !=( I2PTunnelId left, I2PTunnelId right )
        {
            return !( left == right );
        }

        public override bool Equals( object obj )
        {
            if ( obj is null ) return false;
            if ( !( obj is I2PTunnelId ) ) return false;
            return this == (I2PTunnelId)obj;
        }

        public override int GetHashCode()
        {
            return (int)Id;
        }

        public static implicit operator uint( I2PTunnelId tid )
        {
            return tid.Id;
        }

        public static implicit operator I2PTunnelId( uint tid )
        {
            return new I2PTunnelId( tid );
        }
    }
}
