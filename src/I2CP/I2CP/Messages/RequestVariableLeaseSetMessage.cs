using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages
{
    public class RequestVariableLeaseSetMessage: I2CpMessage
    {
        public ushort SessionId;
        public List<ILease> Leases = new();

        public RequestVariableLeaseSetMessage( ushort sessionid, IEnumerable<ILease> leases )
            : base( ProtocolMessageType.RequestVarLs )
        {
            SessionId = sessionid;
            Leases.AddRange( leases );
        }

        public RequestVariableLeaseSetMessage( I2PBufferCursor reader )
            : base( ProtocolMessageType.RequestVarLs )
        {
            SessionId = reader.ReadUInt16BigEndian();
            var leases = reader.ReadByte();
            for ( int i = 0; i < leases; ++i )
            {
                Leases.Add( new I2PLease( reader ) );
            }
        }

        public override void Write( ArrayBufferWriter<byte> dest )
        {
            var header = new byte[3];
            var writer = new I2PBufferCursor( header );
            writer.WriteUInt16BigEndian( SessionId );
            writer.WriteByte( (byte)Leases.Count );
            dest.Write( header );

            foreach( var ls in Leases )
            {
                ls.TunnelGw.Write( dest );
                ls.TunnelId.Write( dest );
                new I2PDate( ls.Expire ).Write( dest );
            }
        }
    }
}
