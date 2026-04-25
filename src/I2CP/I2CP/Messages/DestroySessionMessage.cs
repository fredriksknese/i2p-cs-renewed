using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;

namespace I2P.I2CP.Messages
{
    public class DestroySessionMessage : I2CpMessage
    {
        public ushort SessionId;

        public DestroySessionMessage( ushort sessid )
            : base( ProtocolMessageType.DestroySession )
        {
            SessionId = sessid;
        }

        public DestroySessionMessage( I2PBufferCursor reader )
            : base( ProtocolMessageType.DestroySession )
        {
            SessionId = reader.ReadUInt16BigEndian();
        }

        public override void Write( ArrayBufferWriter<byte> dest )
        {
            dest.WriteUInt16BigEndian( SessionId );
        }
    }
}
