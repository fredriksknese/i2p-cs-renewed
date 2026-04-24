using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class GarlicMessage : I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.Garlic; } }

        public BufLen Data
        {
            get
            {
                // Garlic messages ALWAYS have a 4-byte big-endian length prefix in their body.
                // This applies to both legacy ElGamal and modern ECIES (Proposal 144) messages.
                if ( Payload.Length < 4 ) return Payload;
                return new BufLen( Payload, 4 );
            }
        }

        public BufLen EgData => Data;

        public GarlicMessage( BufRef reader )
        {
            var start = new BufRef( reader );
            
            // Standard I2NP Garlic message always has a 4-byte big-endian length prefix
            var len = (int)reader.ReadFlip32();
            reader.Seek( len );

            SetBuffer( start, reader );
        }

        /// <summary>
        /// Create a GarlicMessage with raw payload data.
        /// Automatically adds the required 4-byte big-endian length prefix.
        /// </summary>
        public GarlicMessage( byte[] data )
        {
            AllocateBuffer( 4 + data.Length );
            var writer = new BufRefLen( Payload );
            writer.WriteFlip32( (uint)data.Length );
            writer.Write( data );
        }
    }
}
