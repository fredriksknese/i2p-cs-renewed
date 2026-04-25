using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class DataMessage : I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.Data; } }

        public DataMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );
            reader.Seek( (int)reader.ReadUInt32BigEndian() );
            SetBuffer( start, reader );
        }

        public DataMessage( I2PByteBlock data )
        {
            AllocateBuffer( 4 + data.Length );
            Payload.WriteUInt32BigEndian( (uint)data.Length, 0 );
            Payload.CopyFrom( data, 4 );
        }

        public uint DataMessagePayloadLength
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

        public I2PByteBlock DataMessagePayload
        {
            get
            {
                return Payload.Slice( 4, (int)DataMessagePayloadLength );
            }
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( $"DataMessage bytes: {Payload.Length}" );

            return result.ToString();
        }
    }
}
