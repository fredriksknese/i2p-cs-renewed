using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages
{
    public class MessagePayloadMessage: I2CpMessage
    {
        public ushort SessionId;
        public uint MessageId;
        public I2PByteBlock Payload;

        public MessagePayloadMessage( ushort sessionid, uint msgid, I2PByteBlock data )
            : base( ProtocolMessageType.MessagePayload )
        {
            SessionId = sessionid;
            MessageId = msgid;
            Payload = data;
        }

        public override void Write( ArrayBufferWriter<byte> dest )
        {
            var header = new byte[10];
            var writer = new I2PBufferCursor( header );
            writer.WriteUInt16BigEndian( SessionId );
            writer.WriteUInt32BigEndian( MessageId );
            writer.WriteUInt32BigEndian( (uint)Payload.Length );

            dest.Write( header );
            dest.WriteBlock( Payload );
        }

        public override string ToString()
        {
            return $"{GetType().Name} {SessionId} {MessageId} {Payload}";
        }
    }
}
