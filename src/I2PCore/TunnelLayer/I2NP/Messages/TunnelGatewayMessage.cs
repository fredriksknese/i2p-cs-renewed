using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class TunnelGatewayMessage : I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.TunnelGateway; } }

        public TunnelGatewayMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );
            reader.Seek( 6 + reader.PeekUInt16BigEndian( 4 ) );
            SetBuffer( start, reader );
        }

        public TunnelGatewayMessage( I2NpMessage message, I2PTunnelId outtunnel )
        {
            var msg = message.CreateHeader16.HeaderAndPayload;
            AllocateBuffer( 6 + msg.Length );

            TunnelId = outtunnel;
            GatewayMessageLength = (ushort)msg.Length;
            // TODO: Remove mem copy
            Payload.CopyFrom( msg, 6 );
        }

        public uint TunnelId
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

        public ushort GatewayMessageLength
        {
            get
            {
                return Payload.ReadUInt16BigEndian( 4 );
            }
            set
            {
                Payload.WriteUInt16BigEndian( value, 4 );
            }
        }

        public I2PByteBlock GatewayMessage
        {
            get
            {
                return Payload.Slice( 6, GatewayMessageLength );
            }
        }

        protected MessageTypes GatewayMessageType
        {
            get
            {
                return (I2NpMessage.MessageTypes)GatewayMessage.ReadByte( 0 );
            }
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "TunnelGateway" );
            result.AppendLine( "TunnelId:          : " + TunnelId.ToString() );
            result.AppendLine( "GatewayMessageType : " + GatewayMessageType.ToString() + " ( " + GatewayMessageLength.ToString() + " bytes )" );

            return result.ToString();
        }

    }
}
