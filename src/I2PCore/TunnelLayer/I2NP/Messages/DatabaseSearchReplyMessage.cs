using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class DatabaseSearchReplyMessage : I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.DatabaseSearchReply; } }

        public readonly I2PIdentHash Key;
        public readonly List<I2PIdentHash> Peers = new();
        public readonly I2PIdentHash From;

        /// <summary>
        /// Create a DatabaseSearchReply message to send
        /// </summary>
        public DatabaseSearchReplyMessage( I2PIdentHash key, IEnumerable<I2PIdentHash> peers, I2PIdentHash from )
        {
            Key = key;
            From = from;
            if ( peers != null )
                Peers.AddRange( peers );

            // Build binary form
            AllocateBuffer( 32 + 1 + Peers.Count * 32 + 32 );
            var writer = new I2PBufferCursor( Payload );

            writer.WriteBlock( Key.Hash );
            writer.WriteByte( (byte)Peers.Count );
            foreach ( var peer in Peers )
                writer.WriteBlock( peer.Hash );
            writer.WriteBlock( From.Hash );
        }

        public DatabaseSearchReplyMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );

            Key = new I2PIdentHash( reader );

            var peercount = reader.ReadByte();
            for ( int i = 0; i < peercount; ++i )
            {
                Peers.Add( new I2PIdentHash( reader ) );
            }

            From = new I2PIdentHash( reader );

            SetBuffer( start, reader );
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "DatabaseSearchReplyMessage" );
            result.AppendLine( "Peer count   : " + ( Peers == null ? "(null)" : Peers.Count.ToString() ) );

            foreach ( var one in Peers )
            {
                result.AppendLine( one.ToString() );
            }

            return result.ToString();
        }
    }
}
