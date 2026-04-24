using System;
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

        private BufLen HashCache;

        public BufLen Hash
        {
            get
            {
                if ( HashCache != null ) return HashCache;

                HashCache = new BufLen( I2PHashSha256.GetHash( Identity.Hash, new BufLen( GenerateDtBuf( TargetDate ) ) ) );

                return HashCache;
            }
        }

        private static byte[] GenerateDtBuf( DateTime daynow )
        {
            return Encoding.ASCII.GetBytes( $"{daynow:yyyyMMdd}" );
        }

        public void Write( BufRefStream dest )
        {
            dest.Write( Hash );
        }

        public override string ToString()
        {
            var hc = HashCache != null ? FreenetBase64.Encode( new BufLen( HashCache ) ): "<null>";
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
        public static BufLen operator ^( I2PIdentHash left, I2PRoutingKey right )
        {
            var result = new byte[32];
            var lhash = left.Hash;
            var rhash = right.Hash;
            for ( int i = 0; i < 32; ++i )
            {
                result[i] = (byte)( lhash[i] ^ rhash[i] );
            }
            return new BufLen( result );
        }
    }
}
