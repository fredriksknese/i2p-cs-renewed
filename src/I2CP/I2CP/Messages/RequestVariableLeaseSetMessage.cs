using System;
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

        public RequestVariableLeaseSetMessage( BufRef reader )
            : base( ProtocolMessageType.RequestVarLs )
        {
            SessionId = reader.ReadFlip16();
            var leases = reader.Read8();
            for ( int i = 0; i < leases; ++i )
            {
                Leases.Add( new I2PLease( reader ) );
            }
        }

        public override void Write( BufRefStream dest )
        {
            var header = new byte[3];
            var writer = new BufRefLen( header );
            writer.WriteFlip16( SessionId );
            writer.Write8( (byte)Leases.Count );
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
