using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto.Parameters;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2PHashSha256 : I2PType
    {
        private enum BuildMode { Constructor, BatchList, Signed }

        private BuildMode Mode;

        public byte[] Hash;

        private List<I2PType> Batch;

        public I2PHashSha256()
        {
            Mode = BuildMode.BatchList;
            Batch = new List<I2PType>();
        }

        public I2PHashSha256( byte[] buf )
        {
            Mode = BuildMode.Constructor;

            Hash = DoSign( buf );
        }

        private byte[] DoSign( byte[] buf )
        {
            return GetHash( buf, 0, buf.Length );
        }

        public static byte[] GetHash( params I2PByteBlock[] bufs )
        {
            var sha = new Sha256Digest();
            foreach ( var buf in bufs )
            {
                sha.BlockUpdate( buf.BaseArray, buf.BaseArrayOffset, buf.Length );
            }
            var hash = new byte[sha.GetDigestSize()];
            sha.DoFinal( hash, 0 );
            return hash;
        }

        public static byte[] GetHash( I2PByteBlock buf )
        {
            var sha = new Sha256Digest();
            sha.BlockUpdate( buf.BaseArray, buf.BaseArrayOffset, buf.Length );
            var hash = new byte[sha.GetDigestSize()];
            sha.DoFinal( hash, 0 );
            return hash;
        }

        public static byte[] GetHash( byte[] buf )
        {
            return GetHash( buf, 0, buf.Length );
        }

        public static byte[] GetHash( byte[] buf, int offset, int length )
        {
            var sha = new Sha256Digest();
            sha.BlockUpdate( buf, offset, length );
            var hash = new byte[sha.GetDigestSize()];
            sha.DoFinal( hash, 0 );
            return hash;
        }

        public void Add( I2PType data )
        {
            if ( Mode != BuildMode.BatchList ) throw new InvalidOperationException( "Cannot mix build modes" );
            Batch.Add( data );
        }

        private byte[] SignedData = null;
        public void Sign()
        {
            if ( Mode != BuildMode.BatchList ) throw new InvalidOperationException( "Cannot mix build modes" );

            var buf = new ArrayBufferWriter<byte>();
            foreach ( var data in Batch )
            {
                data.Write( buf );
            }

            SignedData = buf.WrittenSpan.ToArray();
            Hash = DoSign( SignedData );

            Mode = BuildMode.Signed;
        }

        public bool Verify( byte[] buf, int offset, int length )
        {
            if ( Mode != BuildMode.Signed ) throw new InvalidOperationException( "No signature available" );

            var hash = GetHash( buf, offset, length );
            return BufUtils.Equals( Hash, hash );
        }

        public void Write( IBufferWriter<byte> dest )
        {
            if ( SignedData == null ) throw new InvalidOperationException( "No signed data available" );
            dest.WriteBytes( SignedData );
            dest.WriteBytes( Hash );
        }

        public void WriteSigOnly( IBufferWriter<byte> dest )
        {
            dest.WriteBytes( Hash );
        }

        public void WriteContentOnly( IBufferWriter<byte> dest )
        {
            dest.WriteBytes( SignedData );
        }
    }
}
