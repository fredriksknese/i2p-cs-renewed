using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Math;

namespace I2P.I2CP.Messages
{
    public class CreateLeaseSetMessage: I2CpMessage
    {
        public ushort SessionId;
        public BufLen DsaPrivateSigningKey;
        public I2PPrivateKey PrivateKey;
        public I2PLeaseSet Leases;

        public CreateLeaseSetMessage( 
            I2PDestination dest,
            ushort sessionid, 
            I2PLeaseSet ls,
            List<I2PLease> leases ): base( ProtocolMessageType.CreateLs )
        {
            SessionId = sessionid;
            Leases = ls;
        }

        public CreateLeaseSetMessage( BufRef reader, I2CpSession session ) 
                : base( ProtocolMessageType.CreateLs )
        {
            SessionId = reader.ReadFlip16();

            var cert = session.SessionIds[SessionId].Config.Destination.Certificate;

            DsaPrivateSigningKey = reader.ReadBufLen( 20 );

            PrivateKey = new I2PPrivateKey( reader, cert );
            Leases = new I2PLeaseSet( reader );
        }

        private static readonly byte[] TwentyBytes = { 0, 0, 0, 0, 0, 0, 0, 0, 
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public override void Write( BufRefStream dest )
        {
            dest.Write( (BufRefLen)BufUtils.Flip16Bl( SessionId ) );
            dest.Write( TwentyBytes );
            PrivateKey.Write( dest );
            Leases.Write( dest );
        }
    }
}
