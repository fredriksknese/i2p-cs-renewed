using System;
using System.Buffers;
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
        public I2PByteBlock DsaPrivateSigningKey;
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

        public CreateLeaseSetMessage( I2PBufferCursor reader, I2CpSession session ) 
                : base( ProtocolMessageType.CreateLs )
        {
            SessionId = reader.ReadUInt16BigEndian();

            var cert = session.SessionIds[SessionId].Config.Destination.Certificate;

            DsaPrivateSigningKey = reader.ReadBlock( 20 );

            PrivateKey = new I2PPrivateKey( reader, cert );
            Leases = new I2PLeaseSet( reader );
        }

        private static readonly byte[] TwentyBytes = { 0, 0, 0, 0, 0, 0, 0, 0, 
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public override void Write( ArrayBufferWriter<byte> dest )
        {
            dest.WriteUInt16BigEndian( SessionId );
            dest.Write( TwentyBytes );
            PrivateKey.Write( dest );
            Leases.Write( dest );
        }
    }
}
