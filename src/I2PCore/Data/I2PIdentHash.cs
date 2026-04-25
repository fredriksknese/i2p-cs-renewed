using System;
using System.Buffers;
using Org.BouncyCastle.Utilities.Encoders;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2PIdentHash: I2PType, IEquatable<I2PIdentHash>
    {
        public static readonly I2PIdentHash Zero = new(new I2PByteBlock(new byte[32]));

        public readonly I2PByteBlock Hash;
        private readonly int CachedHash;
        private readonly string Id32ShortField;

        private I2PIdentHash( I2PByteBlock hash )
        {
            Hash = hash;
            CachedHash = Hash.GetHashCode();
            Id32ShortField = $"[{BufUtils.ToBase32String( Hash ).Substring( 0, 5 )}]";
        }

        private static I2PByteBlock CreateRandomBuf( bool random )
        {
            var buf = new I2PByteBlock( new byte[32] );
            if ( random ) buf.Randomize();
            return buf;
        }

        public I2PIdentHash( bool random ): this( CreateRandomBuf( random ) )
        {
        }

        private static I2PByteBlock CreateBase32ParsedBuf( string base32Addr )
        {
            var st = base32Addr;
            if ( st.EndsWith( ".i2p", StringComparison.Ordinal ) ) st = st.Substring( 0, st.Length - 4 );
            if ( st.EndsWith( ".b32", StringComparison.Ordinal ) ) st = st.Substring( 0, st.Length - 4 );
            var buf = new I2PByteBlock( BufUtils.Base32ToByteArray( st ) );
            return buf;
        }

        public I2PIdentHash( string base32Addr ) : this( CreateBase32ParsedBuf( base32Addr ) )
        {
        }

        public I2PIdentHash( I2PBufferCursor buf ) : this( buf.ReadBlock( 32 ) )
        {
        }

        private static I2PByteBlock CreateKnCBuf( I2PKeysAndCert kns )
        {
            var ar = kns.ToByteArray();
            var buf = new I2PByteBlock( I2PHashSha256.GetHash( ar, 0, ar.Length ) );
            return buf;
        }

        public I2PIdentHash( I2PKeysAndCert kns ): this( CreateKnCBuf( kns ) )
        {
        }

        public string Id32Short
        {
            get
            {
                return Id32ShortField;
            }
        }

        public string Id32
        {
            get
            {
                return BufUtils.ToBase32String( Hash );
            }
        }

        public string Id64
        {
            get
            {
                return System.Text.Encoding.ASCII.GetString( UrlBase64.Encode( Hash.ToByteArray() ) );
            }
        }

        public I2PRoutingKey RoutingKey
        {
            get => GetRoutingKey( DateTime.UtcNow );
        }

        public I2PRoutingKey GetRoutingKey( DateTime targetDate )
        {
            return new I2PRoutingKey( this, targetDate );
        }

        public I2PByteBlock Hash16
        {
            get
            {
                return new I2PByteBlock( Hash.BaseArray, Hash.BaseArrayOffset, 16 );
            }
        }

        public void Write( IBufferWriter<byte> dest )
        {
            dest.WriteBlock( Hash );
        }

        public override string ToString()
        {
            return Id32;
        }

        public byte this[int ix]
        {
            get { return Hash[ix]; }
        }

        public static bool operator == ( I2PIdentHash left, I2PIdentHash right )
        {
            if ( left is null && right is null ) return true;
            if ( left is null || right is null ) return false;
            return left.Hash == right.Hash;
        }

        public static bool operator !=( I2PIdentHash left, I2PIdentHash right )
        {
            if ( left is null && right is null ) return false;
            if ( left is null || right is null ) return true;
            return left.Hash != right.Hash;
        }

        public override bool Equals( object obj )
        {
            if ( obj is null ) return false;
            if ( !( obj is I2PIdentHash other ) ) return false;
            return Hash == other.Hash;
        }

        #region IEquatable<I2PIdentHash> Members
        public bool Equals( I2PIdentHash other )
        {
            if ( other is null ) return false;
            return Hash == other.Hash;
        }
        #endregion

        public override int GetHashCode()
        {
            return CachedHash;
        }

        public int CompareTo( I2PIdentHash other )
        {
            for ( int i = 0; i < 32; ++i )
            {
                if ( Hash[i] < other.Hash[i] ) return -1;
                if ( Hash[i] > other.Hash[i] ) return 1;
            }
            return 0;
        }

        public static bool operator <( I2PIdentHash left, I2PIdentHash right )
        {
            if ( left is null || right is null ) return false;
            for ( int i = 0; i < 32; ++i )
            {
                if ( left[i] < right[i] ) return true;
                if ( left[i] > right[i] ) return false;
            }
            return false;
        }

        public static bool operator >( I2PIdentHash left, I2PIdentHash right )
        {
            if ( left is null || right is null ) return false;
            for ( int i = 0; i < 32; ++i )
            {
                if ( left[i] < right[i] ) return false;
                if ( left[i] > right[i] ) return true;
            }
            return false;
        }

        public static Org.BouncyCastle.Math.BigInteger operator ^( I2PIdentHash left, I2PIdentHash right )
        {
            if ( left is null || right is null ) return null;
            var xor = new byte[32];
            for ( int i = 0; i < 32; ++i ) xor[i] = (byte)( left[i] ^ right[i] );
            return new Org.BouncyCastle.Math.BigInteger( 1, xor );
        }
    }
}
