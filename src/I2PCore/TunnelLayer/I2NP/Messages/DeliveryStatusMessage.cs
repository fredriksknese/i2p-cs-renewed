using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PCore.Data;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public sealed class DeliveryStatusMessage : I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.DeliveryStatus; } }

        public uint StatusMessageId
        {
            get
            {
                return Payload.ReadUInt32BigEndian( 0 );
            }
            set
            {
                Payload.WriteUInt32BigEndian( value, 0 );
            }
        }

        public I2PDate Timestamp { get { return new I2PDate( new I2PBufferCursor( Payload.BaseArray, Payload.BaseArrayOffset + 4 ) ); } set { value.Poke( Payload, 4 ); } }

        public DeliveryStatusMessage()
        {
            AllocateBuffer( 12 );
            Timestamp = new I2PDate( DateTime.UtcNow );
            StatusMessageId = I2NpMessage.GenerateMessageId();
        }

        public DeliveryStatusMessage( uint msgid )
        {
            AllocateBuffer( 12 );
            Timestamp = new I2PDate( DateTime.UtcNow );
            StatusMessageId = msgid;
        }

        public DeliveryStatusMessage( ulong networkid )
        {
            AllocateBuffer( 12 );
            Payload.WriteUInt64BigEndian( networkid, 4 );
            StatusMessageId = BufUtils.RandomUint();
        }

        public DeliveryStatusMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );
            reader.Seek( 12 );
            SetBuffer( start, reader );
        }

        public bool IsNetworkId( ulong networkid )
        {
            return Payload.ReadUInt64BigEndian( 4 ) == networkid;
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendFormat( "DeliveryStatus MessageId: {0}, Timestamp: {1}.", StatusMessageId, Timestamp );

            return result.ToString();
        }
    }
}
