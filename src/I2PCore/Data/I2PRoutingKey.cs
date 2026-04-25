using System;
using System.Buffers;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2PRoutingKey: I2PType
    {
        private readonly I2PIdentHash Identity;
        private readonly DateTime TargetDate;

        public I2PRoutingKey( I2PIdentHash ident ) : this( ident, DateTime.UtcNow.Date )
        {
        }

        public I2PRoutingKey( I2PIdentHash ident, DateTime targetDate )
        {
            Identity = ident;
            TargetDate = targetDate.Date;
        }

        private I2PByteBlock HashCache;

        public I2PByteBlock Hash
        {
            get
            {
                if ( HashCache.Length != 0 ) return HashCache;

                HashCache = new I2PByteBlock( I2PHashSha256.GetHash( Identity.Hash, new I2PByteBlock( GenerateDtBuf( TargetDate ) ) ) );

                return HashCache;
            }
        }

        private static byte[] GenerateDtBuf( DateTime daynow )
        {
            return Encoding.ASCII.GetBytes( $"{daynow:yyyyMMdd}" );
        }

        public void Write( IBufferWriter<byte> dest )
        {
            dest.WriteBlock( Hash );
        }

        public override string ToString()
        {
            var hc = HashCache.Length != 0 ? FreenetBase64.Encode( new I2PByteBlock( HashCache.ToByteArray() ) ): "<null>";
            return $"I2PRoutingKey: TargetDate {TargetDate}, HashCache: {hc}.";
        }

        public byte this[int ix]
        {
            get { return Hash[ix]; }
        }


        /// <summary>
        /// Distance definitions is always between as stored floodfill IdentHash and a searched RoutingKey.
        /// Not between two routing keys.
        /// </summary>
        /// <returns></returns>
        public static I2PByteBlock operator ^( I2PIdentHash left, I2PRoutingKey right )
        {
            var result = new byte[32];
            var lhash = left.Hash;
            var rhash = right.Hash;
            for ( int i = 0; i < 32; ++i )
            {
                result[i] = (byte)( lhash[i] ^ rhash[i] );
            }
            return new I2PByteBlock( result );
        }
    }
}
