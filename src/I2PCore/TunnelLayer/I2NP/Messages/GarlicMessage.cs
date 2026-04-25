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

        public I2PByteBlock Data
        {
            get
            {
                // Garlic messages ALWAYS have a 4-byte big-endian length prefix in their body.
                // This applies to both legacy ElGamal and modern ECIES (Proposal 144) messages.
                if ( Payload.Length < 4 ) return Payload;
                return Payload.Slice( 4 );
            }
        }

        public I2PByteBlock EgData => Data;

        public GarlicMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );

            // Standard I2NP Garlic message always has a 4-byte big-endian length prefix
            var len = (int)reader.ReadUInt32BigEndian();
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
            var writer = new I2PBufferCursor( Payload );
            writer.WriteUInt32BigEndian( (uint)data.Length );
            writer.WriteBytes( data );
        }
    }
}
