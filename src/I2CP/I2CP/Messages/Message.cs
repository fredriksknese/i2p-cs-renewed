using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using I2PCore.Utils;
using I2PCore.Data;

namespace I2P.I2CP.Messages
{
    public abstract class I2CpMessage
    {
        public enum PayloadFormat : byte
        {
            Streaming = 6,
            Datagram = 17, 
            Raw = 18,
        };

        public enum ProtocolMessageType : byte
        {
            CreateSession = 1,
            ReconfigSession = 2,
            DestroySession = 3,
            CreateLs = 4,
            SendMessage = 5,
            RecvMessageBegin = 6,
            RecvMessageEnd = 7,
            GetBwLimits = 8,
            SessionStatus = 20,
            RequestLs = 21,
            MessageStatus = 22,
            BwLimits = 23,
            ReportAbuse = 29,
            Disconnect = 30,
            MessagePayload = 31,
            GetDate = 32,
            SetDate = 33,
            DestLookup = 34,
            DestReply = 35,
            SendMessageExpires = 36,
            RequestVarLs = 37,
            HostLookup = 38,
            HostLookupReply = 39,
            CreateLeaseSet2MessageDeprecated = 40,
            CreateLeaseSet2Message = 41,
        }

        public readonly ProtocolMessageType MessageType;

        protected I2CpMessage( ProtocolMessageType msgtype )
        {
            MessageType = msgtype;
        }

        public abstract void Write( ArrayBufferWriter<byte> dest );

        /*
        public void WriteMessage( ArrayBufferWriter<byte> dest, params I2PType[] fields )
        {
            var buf = new ArrayBufferWriter<byte>();
            foreach ( var field in fields ) field.Write( buf );

            dest.WriteUInt32BigEndian( (uint)buf.WrittenCount );
            dest.WriteByte( (byte)MessageType );
            dest.Write( buf );
        }
        */

        public byte[] ToByteArray()
        {
            var buf = new ArrayBufferWriter<byte>();
            Write( buf );
            return buf.WrittenSpan.ToArray();
        }

        public override string ToString()
        {
            return GetType().Name;
        }
    }
}
