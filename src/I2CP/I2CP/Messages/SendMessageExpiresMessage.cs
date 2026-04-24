using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using System.IO;
using I2PCore.Utils;

namespace I2P.I2CP.Messages
{
    public class SendMessageExpiresMessage : I2CpMessage
    {
        public ushort SessionId;
        public I2PDestination Destination;
        public BufLen Payload;
        public uint Nonce;

        // Ignored
        private BufLen Flags;
        private DateTime Expiration;

        public SendMessageExpiresMessage( BufRefLen reader )
            : base( ProtocolMessageType.SendMessageExpires )
        {
            SessionId = reader.ReadFlip16();
            Destination = new I2PDestination( reader );
            var len = reader.ReadFlip32();
            Payload = reader.ReadBufLen( (int)len );
            Nonce = reader.ReadFlip32();
        }

        public override void Write( BufRefStream dest )
        {
            dest.Write( BufUtils.Flip16B( SessionId ) );
            Destination.Write( dest );
            dest.Write( BufUtils.Flip32B( (uint)Payload.Length ) );
            dest.Write( Payload );
            dest.Write( BufUtils.Flip32B( Nonce ) );
        }
    }
}
