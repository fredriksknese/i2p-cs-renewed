using System;
using System.Text;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PCore.Data;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    /// <summary>
    /// I2NP TunnelTest message (type 231).
    /// Same structure as DeliveryStatus: 4-byte msgID + 8-byte timestamp = 12 bytes.
    /// Used by i2pd for tunnel latency testing.
    /// </summary>
    public sealed class TunnelTestMessage : I2NpMessage
    {
        public override MessageTypes MessageType => MessageTypes.TunnelTest;

        public uint TestMessageId
        {
            get => Payload.PeekFlip32( 0 );
            set => Payload.PokeFlip32( value, 0 );
        }

        public I2PDate Timestamp
        {
            get => new I2PDate( new BufRefLen( Payload, 4 ) );
            set => value.Poke( Payload, 4 );
        }

        public TunnelTestMessage()
        {
            AllocateBuffer( 12 );
            Timestamp = new I2PDate( DateTime.UtcNow );
            TestMessageId = I2NpMessage.GenerateMessageId();
        }

        public TunnelTestMessage( uint msgid )
        {
            AllocateBuffer( 12 );
            Timestamp = new I2PDate( DateTime.UtcNow );
            TestMessageId = msgid;
        }

        public TunnelTestMessage( BufRef reader )
        {
            var start = new BufRef( reader );
            reader.Seek( 12 );
            SetBuffer( start, reader );
        }

        public override string ToString()
        {
            return $"TunnelTest MessageId: {TestMessageId}, Timestamp: {Timestamp}.";
        }
    }
}
