using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class TunnelBuildMessage: I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.TunnelBuild; } }

        public List<AesEgBuildRequestRecord> Records = new();

        public TunnelBuildMessage( BufRef reader )
        {
            var start = new BufRef( reader );
            for ( int i = 0; i < 8; ++i )
            {
                var r = new AesEgBuildRequestRecord( reader );
                Records.Add( r );
            }
            SetBuffer( start, reader );
        }

        // Clones records
        public TunnelBuildMessage( IEnumerable<AesEgBuildRequestRecord> records )
        {
            var hops = (byte)records.Count();
            if ( hops > 8 ) throw new ArgumentException( "TunnelBuildMessage can only contain 8 records" );

            AllocateBuffer( 1 + 8 * AesEgBuildRequestRecord.Length );
            var writer = new BufRefLen( Payload );
            foreach ( var rec in records )
            {
                Records.Add( rec );
                writer.Write( rec.Data );
            }
        }

        private TunnelBuildMessage()
        {
            AllocateBuffer( 1 + 8 * AesEgBuildRequestRecord.Length );
            var writer = new BufRefLen( Payload );
            for ( int i = 0; i < 8; ++i ) Records.Add( new AesEgBuildRequestRecord( writer ) );
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "TunnelBuild" );
            for ( int i = 0; i < Records.Count; ++i )
            {
                result.Append( Records[i].ToString() );
            }

            return result.ToString();
        }
    }
}
