using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public class GarlicClove : I2PType
    {
        public GarlicCloveDelivery Delivery;
        public uint CloveId;
        public I2PDate Expiration;
        public I2NpMessage Message;

        public GarlicClove( I2PBufferCursor reader )
        {
            Delivery = GarlicCloveDelivery.CreateGarlicCloveDelivery( reader );
            Message = I2NpMessage.ReadHeader16( reader ).Message;
            CloveId = reader.ReadUInt32BigEndian();
            Expiration = new I2PDate( reader );
            reader.Seek( 3 ); // Cert
        }

        public GarlicClove( GarlicCloveDelivery delivery, I2PDate exp )
        {
            Delivery = delivery;
            Message = delivery.Message;
            CloveId = BufUtils.RandomUint();
            Expiration = exp;
        }

        public GarlicClove( GarlicCloveDelivery delivery )
        {
            Delivery = delivery;
            Message = delivery.Message;
            CloveId = BufUtils.RandomUint();
            Expiration = new I2PDate( DateTime.UtcNow + TimeSpan.FromMinutes( 5 ) );
        }

        private static readonly byte[] ThreeZero = new byte[] { 0, 0, 0 };

        public void Write( IBufferWriter<byte> dest )
        {
            Delivery.Write( dest );
            dest.WriteUInt32BigEndian( CloveId );
            Expiration.Write( dest );
            dest.WriteBytes( ThreeZero );
        }

        public override string ToString()
        {
            return $"{CloveId} {Delivery} {Message?.MessageType}";
        }
    }
}
