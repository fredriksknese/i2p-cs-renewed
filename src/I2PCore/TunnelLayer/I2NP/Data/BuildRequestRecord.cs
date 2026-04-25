using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public class BuildRequestRecord: I2PType
    {
        public const int Length = 222;

        public I2PByteBlock Data;

        private uint ReducedHash;

        public BuildRequestRecord()
        {
            Data = new I2PByteBlock( new byte[Length] );
            ReducedHash = CreateReducedHash();
        }

        public BuildRequestRecord( I2PBufferCursor buf )
        {
            Data = buf.ReadBlock( Length );
            ReducedHash = CreateReducedHash();
        }

        public I2PTunnelId ReceiveTunnel { get { return new I2PTunnelId( Data.ReadUInt32BigEndian( 0 ) ); } set { Data.WriteUInt32BigEndian( value, 0 ); } }
        public I2PIdentHash OurIdent { get { return new I2PIdentHash( new I2PBufferCursor( Data.BaseArray, Data.BaseArrayOffset + 4, 32 ) ); } set { Data.CopyFrom( value.Hash, 4 ); } }
        public I2PTunnelId NextTunnel { get { return new I2PTunnelId( Data.ReadUInt32BigEndian( 36 ) ); } set { Data.WriteUInt32BigEndian( value, 36 ); } }
        public I2PIdentHash NextIdent { get { return new I2PIdentHash( new I2PBufferCursor( Data.BaseArray, Data.BaseArrayOffset + 40, 32 ) ); } set { Data.CopyFrom( value.Hash, 40 ); } }
        public I2PByteBlock LayerKey { get { return Data.Slice( 72, 32 ); } }
        public I2PByteBlock IvKey { get { return Data.Slice( 104, 32 ); } }
        public I2PSessionKey ReplyKey { get { return new I2PSessionKey( new I2PBufferCursor( Data.BaseArray, Data.BaseArrayOffset + 136, 32 ) ); } set { Data.CopyFrom( value.Key, 136 ); } }
        public I2PByteBlock ReplyKeyBuf { get { return Data.Slice( 136, 32 ); } }
        public I2PByteBlock ReplyIv { get { return Data.Slice( 168, 16 ); } }
        public byte Flag { get { return Data.ReadByte( 184 ); } set { Data.WriteByte( value, 184 ); } }

        public uint RequestTimeVal { get { return Data.ReadUInt32BigEndian( 185 ); } set { Data.WriteUInt32BigEndian( value, 185 ); } }
        public DateTime RequestTime
        {
            get
            {
                return I2PDate.RefDate.AddHours( RequestTimeVal );
            }
            set
            {
                RequestTimeVal = (uint)Math.Truncate( ( value - I2PDate.RefDate ).TotalHours );
            }
        }

        public uint SendMessageId { get { return Data.ReadUInt32BigEndian( 189 ); } set { Data.WriteUInt32BigEndian( value, 189 ); } }
        public I2PByteBlock Padding { get { return Data.Slice( 193, 29 ); } }

        /// <summary>
        /// Is inbound gateway.
        /// </summary>
        public bool FromAnyone
        {
            get
            {
                return ( Flag & 0x80 ) != 0;
            }
            set
            {
                if ( ToAnyone && value ) throw new InvalidOperationException( "Both To and From anyone cannot be set at the same time!" );
                Flag = (byte)( ( Flag & 0x7F ) | ( value ? 0x80 : 0 ) );
            }
        }

        /// <summary>
        /// Is outbound endpoint.
        /// </summary>
        public bool ToAnyone
        {
            get
            {
                return ( Flag & 0x40 ) != 0;
            }
            set
            {
                if ( FromAnyone && value ) throw new InvalidOperationException( "Both To and From anyone cannot be set at the same time!" );
                Flag = (byte)( ( Flag & 0xBF ) | ( value ? 0x40 : 0 ) );
            }
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine(  "BuildRequestRecord" );
            result.AppendLine( $"ReceiveTunnel : {ReceiveTunnel}" );
            result.AppendLine( $"OurIdent      : {OurIdent}" );
            result.AppendLine( $"NextTunnel    : {NextTunnel}" );
            result.AppendLine( $"NextIdent     : {NextIdent}" );
            result.AppendLine( $"Flag          : 0x{Flag:X2}" );
            result.AppendLine( $"ToAnyone      : {ToAnyone}" );
            result.AppendLine( $"FromAnyone    : {FromAnyone}" );
            result.AppendLine( $"RequestTime   : {RequestTime}" );
            result.AppendLine( $"SendMessageId : {SendMessageId}" );

            return result.ToString();
        }

        /// <summary>
        /// High probability to match with similar route.
        /// </summary>
        /// <returns></returns>
        public uint GetReducedHash()
        {
            return ReducedHash;
        }

        private uint CreateReducedHash()
        {
            var result = TickCounter.Now.Ticks / 20000;

            if ( FromAnyone )
            {
                result ^= NextIdent.GetHashCode();
                return (uint)result;
            }
            else if ( ToAnyone )
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

        void I2PType.Write( IBufferWriter<byte> dest )
        {
            dest.WriteBlock( Data );
        }
    }
}
