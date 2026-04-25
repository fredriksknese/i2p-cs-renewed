using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class VariableTunnelBuildReplyMessage: I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.VariableTunnelBuildReply; } }

        public List<BuildResponseRecord> ResponseRecords;

        public VariableTunnelBuildReplyMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );
            ResponseRecords = new List<BuildResponseRecord>();

            byte count = reader.ReadByte();
            for ( int i = 0; i < count; ++i ) ResponseRecords.Add( new BuildResponseRecord( reader ) );
            SetBuffer( start, reader );
        }

        public VariableTunnelBuildReplyMessage( IEnumerable<BuildResponseRecord> recs, uint msgid )
        {
            AllocateBuffer( 1 + recs.Count() * EgBuildRequestRecord.Length );
            ResponseRecords = new List<BuildResponseRecord>( recs );

            MessageId = msgid;

            // TODO: Remove mem copy
            var writer = new I2PBufferCursor( Payload );
            writer.WriteByte( (byte)recs.Count() );
            foreach ( var rec in ResponseRecords ) writer.WriteBlock( rec.Payload );
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "VariableTunnelBuildReply" );
            if ( ResponseRecords != null )
            {
                foreach ( var one in ResponseRecords )
                {
                    result.AppendLine( one.ToString() );
                }
            }

            return result.ToString();
        }
    }
}
