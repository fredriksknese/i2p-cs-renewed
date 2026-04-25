using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using I2PCore.SessionLayer;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public class EgBuildRequestRecord: I2PType
    {
        public const int Length = 528;

        public I2PByteBlock Data;

        public I2PByteBlock ToPeer16 { get { return Data.Slice( 0, 16 ); } }
        public I2PByteBlock EncryptedData { get { return Data.Slice( 16, Length - 16 ); } }

        public EgBuildRequestRecord( I2PBufferCursor buf )
        {
            Data = buf.ReadBlock( Length );
        }

        // The AesEGBuildRequestRecord has been decrypted to the degree ToPeer16 is readable.
        public EgBuildRequestRecord( AesEgBuildRequestRecord src )
        {
            Data = src.Data;
        }

        public EgBuildRequestRecord( I2PByteBlock dest, BuildRequestRecord src, I2PIdentHash topeer, I2PPublicKey key )
        {
            Data = dest;
            var writer = new I2PBufferCursor( Data );

            writer.WriteBlock( topeer.Hash16 );

            var datastart = writer.CurrentBlock;
            ElGamalCrypto.Encrypt( writer, src.Data, key, false );
        }

        public EgBuildRequestRecord( BuildRequestRecord src, I2PIdentHash topeer, I2PPublicKey key ):
            this( new I2PByteBlock( new byte[Length] ), src, topeer, key )
        {
        }

        public BuildRequestRecord Decrypt( I2PPrivateKey pkey )
        {
            return new BuildRequestRecord( new I2PBufferCursor( ElGamalCrypto.Decrypt( EncryptedData, pkey, false ) ) );
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "EGBuildRequestRecord" );
            result.AppendLine( "ToPeer16     : " + BufUtils.ToBase32String( ToPeer16 ) );

            return result.ToString();
        }

        void I2PType.Write( IBufferWriter<byte> dest )
        {
            dest.WriteBlock( Data );
        }
    }

}
