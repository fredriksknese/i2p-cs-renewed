using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace I2PCore.Utils
{
    public class I2Phmacmd5Digest
    {
        private const int BlockLength = 32;

        private const ulong Ipad = 0x3636363636363636;
        private const ulong Opad = 0x5C5C5C5C5C5C5C5C;

        private readonly static byte[] Ipadbuf = {
            0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
            0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
            0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
            0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        };

        private readonly static byte[] Opadbuf = {
            0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
            0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
            0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
            0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
        };

        private readonly static byte[] Nullpad = new byte[16];

        public static byte[] Generate( I2PByteBlock msg, I2PByteBlock key )
        {
            return Generate( new I2PByteBlock[] { msg }, key );
        }

        public static byte[] Generate( IEnumerable<I2PByteBlock> msg, I2PByteBlock key )
        {
            var result = new byte[16];
            Generate( msg, key, new I2PByteBlock( result ) );
            return result;
        }

        public static I2PByteBlock Generate( IEnumerable<I2PByteBlock> msg, I2PByteBlock key, I2PByteBlock dest )
        {
            if ( key.Length != 32 ) throw new NotImplementedException( "Only keys of 32 bits supported" );

            var m5 = new MD5Digest();
            var hash = new byte[m5.GetDigestSize()];
            var buf = new byte[BlockLength];

            var writer = new I2PBufferCursor( buf );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 0 ) ^ Ipad );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 1 * 8 ) ^ Ipad );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 2 * 8 ) ^ Ipad );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 3 * 8 ) ^ Ipad );

            m5.BlockUpdate( buf, 0, BlockLength );
            m5.BlockUpdate( Ipadbuf, 0, Ipadbuf.Length );
            foreach ( var one in msg ) m5.BlockUpdate( one.BaseArray, one.BaseArrayOffset, one.Length );
            m5.DoFinal( hash, 0 );

            writer = new I2PBufferCursor( buf );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 0 ) ^ Opad );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 1 * 8 ) ^ Opad );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 2 * 8 ) ^ Opad );
            writer.WriteUInt64LittleEndian( key.ReadUInt64LittleEndian( 3 * 8 ) ^ Opad );

            m5.Reset();
            m5.BlockUpdate( buf, 0, BlockLength );
            m5.BlockUpdate( Opadbuf, 0, Opadbuf.Length );
            m5.BlockUpdate( hash, 0, hash.Length );
            m5.BlockUpdate( Nullpad, 0, Nullpad.Length );
            if ( dest.Length < m5.GetDigestSize() ) throw new OverflowException( "Not enough dest buffer size for I2PHMACMD5Digest.Generate()!" );
            m5.DoFinal( dest.BaseArray, dest.BaseArrayOffset );
            return dest;
        }
    }
}
