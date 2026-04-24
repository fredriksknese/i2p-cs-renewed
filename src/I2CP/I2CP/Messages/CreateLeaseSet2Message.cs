using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Math;

namespace I2P.I2CP.Messages
{
    public class CreateLeaseSet2Message: I2CpMessage
    {
        public ushort SessionId;
        public I2PSigningPrivateKey DsaPrivateSigningKey;
        public IList<I2PPrivateKey> PrivateKeys;
        public I2PLeaseSet Leases;
        public I2PLeaseSet2 Leases2;

        public CreateLeaseSet2Message( BufRef reader, I2CpSession session ) 
                : base( ProtocolMessageType.CreateLeaseSet2Message )
        {
            SessionId = reader.ReadFlip16();

            var lstype = reader.Read8();
            switch( lstype )
            {
                case 1: // LS
                    Leases = new I2PLeaseSet( reader );
                    break;

                case 3: // LS2
                    Leases2 = new I2PLeaseSet2( reader );
                    break;

                case 5: // Encrypted LS2
                    Logging.LogWarning( "CreateLeaseSet2Message: Encrypted LS2 (type 5) received but parsing not yet supported" );
                    break;

                case 7: // Meta LS2
                    Logging.LogWarning( "CreateLeaseSet2Message: Meta LS2 (type 7) received but parsing not yet supported" );
                    break;
            }

            PrivateKeys = new List<I2PPrivateKey>();
            var privkeycount = reader.Read8();
            for( int i = 0; i < privkeycount; ++i )
            {
                var etype = (I2PPublicKey.KeyTypes)reader.ReadFlip16();
                var keylen = reader.ReadFlip16();
                PrivateKeys.Add( new I2PPrivateKey( reader, new I2PCertificate( etype, keylen ) ) );
            }
        }

        public override void Write( BufRefStream dest )
        {
            dest.Write( BufUtils.Flip16B( SessionId ) );

            if ( Leases2 != null )
            {
                dest.Write( (byte)3 ); // LS2 type
                Leases2.Write( dest );
            }
            else if ( Leases != null )
            {
                dest.Write( (byte)1 ); // LS type
                Leases.Write( dest );
            }

            dest.Write( (byte)(PrivateKeys?.Count ?? 0) );
            if ( PrivateKeys != null )
            {
                foreach ( var pk in PrivateKeys )
                {
                    dest.Write( BufUtils.Flip16B( (ushort)pk.Certificate.PublicKeyType ) );
                    dest.Write( BufUtils.Flip16B( (ushort)pk.KeySizeBytes ) );
                    pk.Write( dest );
                }
            }
        }
    }
}
