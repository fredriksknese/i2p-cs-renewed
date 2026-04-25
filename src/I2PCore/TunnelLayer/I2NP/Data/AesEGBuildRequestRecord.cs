using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public class AesEgBuildRequestRecord
    {
        public const int Length = 528;

        public I2PByteBlock Data;

        // Might be readable, or encrypted
        public I2PByteBlock ToPeer16 { get { return Data.Slice( 0, 16 ); } }

        public AesEgBuildRequestRecord( I2PBufferCursor buf )
        {
            Data = buf.ReadBlock( Length );
        }

        public AesEgBuildRequestRecord( I2PByteBlock dest, EgBuildRequestRecord src, BufferedBlockCipher cipher )
        {
            Data = dest;
            cipher.ProcessBytes( src.Data.BaseArray, src.Data.BaseArrayOffset, src.Data.Length, Data.BaseArray, Data.BaseArrayOffset );
        }

        public AesEgBuildRequestRecord( EgBuildRequestRecord src, BufferedBlockCipher cipher )
        {
            Data = new I2PByteBlock( cipher.ProcessBytes( src.Data.BaseArray, src.Data.BaseArrayOffset, src.Data.Length ) );
        }

        public AesEgBuildRequestRecord Clone()
        {
            return new AesEgBuildRequestRecord( new I2PBufferCursor( Data.Clone() ) );
        }

        public void Process( BufferedBlockCipher cipher )
        {
            cipher.ProcessBytes( Data );
        }

        public void Process( CbcBlockCipher cipher )
        {
            cipher.ProcessBytes( Data );
        }

        public override string ToString()
        {
            var result = new StringBuilder();
            result.AppendLine( "EGAesBuildRequestRecord " + BufUtils.ToBase32String( ToPeer16 ) );
            return result.ToString();
        }
    }

}
