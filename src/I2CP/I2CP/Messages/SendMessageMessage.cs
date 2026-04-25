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
    public class SendMessageMessage : I2CpMessage
    {
        public ushort SessionId;
        public I2PDestination Destination;
        public I2PByteBlock Payload;
        public uint Nonce;

        public SendMessageMessage( I2PBufferCursor reader )
            : base( ProtocolMessageType.SendMessage )
        {
            SessionId = reader.ReadUInt16BigEndian();
            Destination = new I2PDestination( reader );
            var len = reader.ReadUInt32BigEndian();
            Payload = reader.ReadBlock( (int)len );
            Nonce = reader.ReadUInt32BigEndian();
        }

        public override void Write( ArrayBufferWriter<byte> dest )
        {
            dest.WriteUInt16BigEndian( SessionId );
            Destination.Write( dest );
            dest.WriteUInt32BigEndian( (uint)Payload.Length );
            dest.WriteBlock( Payload );
            dest.WriteUInt32BigEndian( Nonce );
        }
    }
}
