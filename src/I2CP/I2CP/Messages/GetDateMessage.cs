using I2PCore.Data;
using System.Buffers;
using I2PCore.Utils;

namespace I2P.I2CP.Messages
{
    public class GetDateMessage: I2CpMessage
    {
        public I2PString Version;
        public I2PMapping Mapping;

        public GetDateMessage( string ver, I2PMapping map )
            : base( ProtocolMessageType.GetDate )
        {
            Version = new I2PString( ver );
            Mapping = map;
        }

        public GetDateMessage( I2PBufferCursor reader )
            : base( ProtocolMessageType.GetDate )
        {
            Version = new I2PString( reader );

            // As of release 0.9.11, the authentication [Mapping] may be included, with the keys i2cp.username and i2cp.password.
            if ( reader.Remaining > 0 )
            {
                Mapping = new I2PMapping( reader );
            }
        }

        public override void Write( ArrayBufferWriter<byte> dest )
        {
            Version.Write( dest );

            if ( Mapping != null )
            {
                Mapping.Write( dest );
            }
        }
    }
}
