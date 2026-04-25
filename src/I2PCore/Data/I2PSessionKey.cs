using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data
{
    /// <summary>
    /// This structure is used for symmetric AES256 encryption and decryption.
    /// </summary>
    public class I2PSessionKey : I2PType, IComparable<I2PSessionKey>, IEqualityComparer<I2PSessionKey>
    {
        public readonly I2PByteBlock Key;

        public I2PSessionKey()
        {
            Key = new I2PByteBlock( BufUtils.RandomBytes( 32 ) );
        }

        public I2PSessionKey( byte[] buf )
        {
            Key = new I2PByteBlock( buf, 0, 32 );
        }

        public I2PSessionKey( I2PSessionKey src )
        {
            Key = src.Key;
        }

        public I2PSessionKey( I2PBufferCursor buf )
        {
            if ( buf is null )
            {
                throw new ArgumentException( "SessionKey must be 32 bytes" );
            }

            Key = buf.ReadBlock( 32 );

            if ( Key.Length != 32 )
            {
                throw new ArgumentException( "SessionKey must be 32 bytes" );
            }
        }

        public I2PSessionKey( I2PByteBlock buf )
        {
            if ( buf.Length != 32 )
            {
                throw new ArgumentException( "SessionKey must be 32 bytes" );
            }
            Key = buf;
        }

        public void Write( IBufferWriter<byte> dest )
        {
            dest.WriteBlock( Key );
        }

        public override bool Equals( object obj )
        {
            var sk = obj as I2PSessionKey;
            if ( obj is null || sk is null ) return false;
            return Key.Equals( sk.Key );
        }

        bool IEqualityComparer<I2PSessionKey>.Equals( I2PSessionKey x, I2PSessionKey y )
        {
            return x.Equals( y );
        }

        int IComparable<I2PSessionKey>.CompareTo( I2PSessionKey other )
        {
            return I2PByteBlock.Compare( Key, other.Key );
        }

        int IEqualityComparer<I2PSessionKey>.GetHashCode( I2PSessionKey obj )
        {
            return GetHashCode();
        }

        public static bool operator ==( I2PSessionKey left, I2PSessionKey right )
        {
            return Equals( left, right );
        }

        public static bool operator !=( I2PSessionKey left, I2PSessionKey right )
        {
            return !Equals( left, right );
        }

        public static bool operator >( I2PSessionKey left, I2PSessionKey right )
        {
            return I2PByteBlock.Compare( left.Key, right.Key ) > 0;
        }

        public static bool operator <( I2PSessionKey left, I2PSessionKey right )
        {
            return I2PByteBlock.Compare( left.Key, right.Key ) < 0;
        }

        public override int GetHashCode()
        {
            return Key.GetHashCode();
        }

        public override string ToString()
        {
            return $"{Key:h10}";
        }
    }
}
