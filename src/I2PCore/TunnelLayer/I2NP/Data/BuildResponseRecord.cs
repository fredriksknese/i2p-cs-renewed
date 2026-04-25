using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Utilities.Encoders;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public class BuildResponseRecord: I2PType
    {
        public enum RequestResponse : byte { Accept = 0, ProbabalisticReject = 10, TransientOverload = 20, Bandwidth = 30, Critical = 50 }
        public const RequestResponse DefaultErrorReply = RequestResponse.Bandwidth;

        public int Length { get => 528; }
        private I2PByteBlock Data;

        public BuildResponseRecord( I2PBufferCursor buf )
        {
            Data = buf.ReadBlock( Length );
        }

        public BuildResponseRecord( I2PByteBlock src )
        {
            if ( src.Length != Length ) throw new ArgumentException( "BuildResponseRecord needs a 528 byte record!" );
            Data = src;
        }

        public BuildResponseRecord( EgBuildRequestRecord request )
        {
            // Replace it
            Data = request.Data;
            Data.Randomize();
        }

        public BuildResponseRecord( AesEgBuildRequestRecord request )
        {
            // Reuse it
            Data = request.Data;
        }

        public RequestResponse Reply
        {
            get { return (RequestResponse)Data[527]; }
            set { Data[527] = (byte)value; }
        }

        public I2PByteBlock Payload
        {
            get { return Data.Slice( 0, Length ); }
        }

        public I2PByteBlock Hash
        {
            get { return Data.Slice( 0, 32 ); }
        }

        public I2PByteBlock HashedArea
        {
            get { return Data.Slice( 32, 496 ); }
        }

        public bool CheckHash()
        {
            var hash = I2PHashSha256.GetHash( HashedArea );
            return Hash.Equals( hash );
        }

        public void UpdateHash()
        {
            var hash = I2PHashSha256.GetHash( HashedArea );
            Hash.CopyFrom( new ReadOnlySpan<byte>( hash ), 0 );
        }

        public bool IsDestination( I2PIdentHash comp )
        {
            return comp.Hash16 == Data;
        }

        public void Write( IBufferWriter<byte> dest )
        {
            dest.WriteBlock( Data );
        }

        public override string ToString()
        {
            return Data.Length == 0
                ? "BuildResponseRecord Content: (null)"
                : $"BuildResponseRecord Content: Reply: {Reply}";
        }
    }
}
