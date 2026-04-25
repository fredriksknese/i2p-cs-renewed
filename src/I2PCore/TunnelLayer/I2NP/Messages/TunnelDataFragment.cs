using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class TunnelDataFragment
    {
        private I2PBufferCursor Data;

        public byte Flag { get { return Data[0]; } set { Data[0] = value; } }

        public bool InitialFragment
        {
            get
            {
                return ( Flag & 0x80 ) == 0;
            }
            set
            {
                Flag = (byte)( ( Flag & 0x7F ) | ( value ? 0 : 0x80 ) );
            }
        }

        public bool FollowOnFragment { get { return !InitialFragment; } set { InitialFragment = !value; } }

        public bool Fragmented
        {
            get
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                return ( Flag & 0x08 ) != 0;
            }
            set
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                Flag = (byte)( ( Flag & 0xF7 ) | ( value ? 0x08 : 0 ) );
            }
        }

        public TunnelMessage.DeliveryTypes Delivery
        {
            get
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                return (TunnelMessage.DeliveryTypes)( Flag & (byte)TunnelMessage.DeliveryTypes.Unused );
            }
            set
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                Flag = (byte)( ( Flag & ~(byte)TunnelMessage.DeliveryTypes.Unused ) | (byte)value );
            }
        }

        public bool ExtendedOptions
        {
            get
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                return ( Flag & 0x04 ) != 0;
            }
            set
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                Flag = (byte)( ( Flag & 0xFB ) | ( value ? 0x04 : 0 ) );
            }
        }

        public bool Delayed
        {
            get
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                return ( Flag & 0x10 ) != 0;
            }
            set
            {
                if ( FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is Follow On Fragment" );
                Flag = (byte)( ( Flag & 0xEF ) | ( value ? 0x10 : 0 ) );
            }
        }

        private I2PByteBlock TunnelRef;
        public I2PTunnelId Tunnel { get { return new I2PTunnelId( new I2PBufferCursor( TunnelRef ) ); } set { value.Write( new I2PBufferCursor( TunnelRef ) ); } }

        private I2PByteBlock ToHashRef;
        public I2PByteBlock ToHash { get { return ToHashRef; } }

        private I2PBufferCursor DelayRef;
        public byte Delay { get { return DelayRef[0]; } set { DelayRef[0] = value; } }

        // Follow on properties
        public byte FragmentNumber
        {
            get
            {
                if ( !FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is not Follow On Fragment" );
                return (byte)( ( Flag & 0x7E ) >> 1 );
            }
            set
            {
                if ( !FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is not Follow On Fragment" );
                Flag = (byte)( ( Flag & 0x7E ) | ( value << 1 ) );
            }
        }

        public bool LastFragment
        {
            get
            {
                if ( !FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is not Follow On Fragment" );
                return ( Flag & 0x01 ) != 0;
            }
            set
            {
                if ( !FollowOnFragment ) throw new ArgumentException( "TunnelDataFragment is not Follow On Fragment" );
                Flag = (byte)( ( Flag & 0xFE ) | ( value ? 0x01 : 0 ) );
            }
        }

        // Shared properties

        private I2PBufferCursor MessageIdRef;
        public uint MessageId { get { return MessageIdRef.PeekUInt32BigEndian( 0 ); } set { MessageIdRef.PokeUInt32BigEndian( value, 0 ); } }

        private I2PByteBlock PayloadRef;
        public I2PBufferCursor Payload { get { return new I2PBufferCursor( PayloadRef ); } }

        public TunnelDataFragment( I2PBufferCursor buf )
        {
            Data = new I2PBufferCursor( buf.BaseArray, buf.BaseArrayOffset );

            var reader = buf;
            reader.Seek( 1 ); // Flag

            if ( InitialFragment )
            {
                switch ( Delivery )
                {
                    case TunnelMessage.DeliveryTypes.Local:
                        if ( Delayed )
                        {
                            DelayRef = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset, 1 );
                            reader.Seek( 1 );
                        }
                        if ( Fragmented )
                        {
                            MessageIdRef = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset, 4 );
                            reader.Seek( 4 );
                        }
                        if ( ExtendedOptions )
                        {
                            var len = reader.ReadByte();
                            reader.Seek( len );
                        }
                        break;

                    case TunnelMessage.DeliveryTypes.Router:
                        ToHashRef = reader.ReadBlock( 32 );

                        if ( Delayed )
                        {
                            DelayRef = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset, 1 );
                            reader.Seek( 1 );
                        }
                        if ( Fragmented )
                        {
                            MessageIdRef = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset, 4 );
                            reader.Seek( 4 );
                        }
                        if ( ExtendedOptions )
                        {
                            var len = reader.ReadByte();
                            reader.Seek( len );
                        }
                        break;

                    case TunnelMessage.DeliveryTypes.Tunnel:
                        TunnelRef = reader.ReadBlock( 4 );
                        ToHashRef = reader.ReadBlock( 32 );

                        if ( Delayed )
                        {
                            DelayRef = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset, 1 );
                            reader.Seek( 1 );
                        }
                        if ( Fragmented )
                        {
                            MessageIdRef = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset, 4 );
                            reader.Seek( 4 );
                        }
                        if ( ExtendedOptions )
                        {
                            var len = reader.ReadByte();
                            reader.Seek( len );
                        }
                        break;

                    default:
                        Logging.LogWarning( $"TunnelDataFragment: Unknown delivery type {Delivery}" );
                        // Skip the payload to avoid corruption
                        var payloadlen2 = reader.ReadUInt16BigEndian();
                        reader.Seek( payloadlen2 );
                        return;
                }
            }
            else
            {
                // Follow on
                MessageIdRef = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset, 4 );
                reader.Seek( 4 );
            }

            var payloadlen = reader.ReadUInt16BigEndian();
            PayloadRef = reader.ReadBlock( payloadlen );
        }
    }
}
