using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using System.IO;
using I2PCore.Utils;

namespace I2P.I2CP.Messages
{
    public class ReceiveMessageEndMessage: I2CpMessage
    {
        public ushort SessionId;
        public uint MessageId;

        public ReceiveMessageEndMessage( ushort sessionid, uint msgid )
            : base( ProtocolMessageType.RecvMessageEnd )
        {
            SessionId = sessionid;
            MessageId = msgid;
        }

        public ReceiveMessageEndMessage( I2PBufferCursor reader )
            : base( ProtocolMessageType.RecvMessageEnd )
        {
            SessionId = reader.ReadUInt16BigEndian();
            MessageId = reader.ReadUInt32BigEndian();
        }

        public override void Write( ArrayBufferWriter<byte> dest )
        {
            var header = new byte[6];
            var writer = new I2PBufferCursor( header );
            writer.WriteUInt16BigEndian( SessionId );
            writer.WriteUInt32BigEndian( MessageId );
            dest.Write( header );
        }
    }
}
