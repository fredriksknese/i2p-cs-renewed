using System;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2Psu3Header: I2PType
    {
        public const string Su3MagicNumber = "I2Psu3";
        public enum Su3FileTypes : byte { Zip = 0x00 }
        public enum Su3ContentTypes : byte { SeedData = 0x03 }

        public I2Psu3Header( BufRef src )
        {
            Read( src );
        }

        public byte FileVersion { get; private set; }
        public ushort SignatureType { get; private set; }
        public ushort SignatureLength { get; private set; }
        public byte VersionLength { get; private set; }
        public BufLen Version { get; private set; }
        public byte SignerIdLength { get; private set; }
        public ulong ContentLength { get; private set; }
        public Su3FileTypes FileType { get; private set; }
        public Su3ContentTypes ContentType { get; private set; }
        public string SignerId { get; private set; }

        public void Read( BufRef reader )
        {
            // magic number and zero byte 6
            var magic = reader.ReadBufLen( 6 );
            _ = reader.Read8();
            var magicstr = magic.ToEncoding( Encoding.UTF8 );

            if ( magicstr != Su3MagicNumber )
            {
                throw new ArgumentException( "Not SU3 data." );
            }

            // su3 file format version
            FileVersion = reader.Read8();

            SignatureType = reader.ReadFlip16();
            SignatureLength = reader.ReadFlip16();
            _ = reader.Read8();
            VersionLength = reader.Read8();
            _ = reader.Read8();
            SignerIdLength = reader.Read8();
            ContentLength = reader.ReadFlip64();
            _ = reader.Read8();
            FileType = (Su3FileTypes)reader.Read8();
            _ = reader.Read8();
            ContentType = (Su3ContentTypes)reader.Read8();
            reader.Seek( 12 );
            Version = reader.ReadBufLen( VersionLength );
            SignerId = reader.ReadBufLen( SignerIdLength )
                .ToEncoding( Encoding.UTF8 ) ;
        }

        public void Write( BufRefStream dest )
        {
            // Magic number "I2Psu3" + zero byte
            dest.Write( Encoding.UTF8.GetBytes( Su3MagicNumber ) );
            dest.Write( (byte)0 );

            dest.Write( FileVersion );
            dest.Write( BufUtils.Flip16B( SignatureType ) );
            dest.Write( BufUtils.Flip16B( SignatureLength ) );
            dest.Write( (byte)0 );  // unused
            dest.Write( VersionLength );
            dest.Write( (byte)0 );  // unused
            dest.Write( SignerIdLength );

            var contentLenBytes = new byte[8];
            for ( int i = 7; i >= 0; i-- )
            {
                contentLenBytes[7 - i] = (byte)( ContentLength >> ( i * 8 ) );
            }
            dest.Write( contentLenBytes );

            dest.Write( (byte)0 );  // unused
            dest.Write( (byte)FileType );
            dest.Write( (byte)0 );  // unused
            dest.Write( (byte)ContentType );

            // 12 reserved bytes
            dest.Write( new byte[12] );

            // Version
            dest.Write( Version );

            // Signer ID
            dest.Write( Encoding.UTF8.GetBytes( SignerId ) );
        }
    }
}
