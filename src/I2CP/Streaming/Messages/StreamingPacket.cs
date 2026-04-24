using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using I2PCore.Utils;
using I2PCore.Data;

namespace I2P.Streaming
{
    public class StreamingPacket
    {
        public const int Mtu = 1730;

        [Flags]
        public enum PacketFlags : ushort {
            Synchronize = 1 << 0,
            Close = 1 << 1,
            Reset = 1 << 2,
            SignatureIncluded = 1 << 3,
            SignatureRequested = 1 << 4,
            FromIncluded = 1 << 5,
            DelayRequested = 1 << 6,
            MaxPacketSizeIncluded = 1 << 7,
            ProfileInteractive = 1 << 8,
            Echo = 1 << 9,
            NoAck = 1 << 10,
            OfflineSignature = 1 << 11,
        }

        public uint ReceiveStreamId;
        public uint SendStreamId;
        public uint SequenceNumber;
        public uint AckTrhough;
        public List<uint> NacKs;
        public byte ResendDelay;
        public PacketFlags Flags;
        public BufLen Payload;

        public I2PDestination From;
        public I2PSigningPrivateKey SigningKey;
        public I2PSignature Signature;

        public StreamingPacket( PacketFlags flags )
        {
            Flags = flags;
        }

        public StreamingPacket( BufRefLen reader )
        {
            SendStreamId = reader.ReadFlip32();
            ReceiveStreamId = reader.ReadFlip32();
            SequenceNumber = reader.ReadFlip32();
            AckTrhough = reader.ReadFlip32();

            NacKs = new List<uint>();
            var nackcount = reader.Read8();
            for ( int i = 0; i < nackcount; ++i )
            {
                NacKs.Add( reader.ReadFlip32() );
            }

            ResendDelay = reader.Read8();

            Flags = (PacketFlags)reader.ReadFlip16();
            var optionsize = reader.ReadFlip16();

            // Options order
            // DELAY_REQUESTED
            // FROM_INCLUDED
            if ( ( Flags & PacketFlags.FromIncluded ) != 0 )
            {
                From = new I2PDestination( reader );
            }
            // MAX_PACKET_SIZE_INCLUDED
            if ( ( Flags & PacketFlags.MaxPacketSizeIncluded ) != 0 )
            {
                var mtu = reader.ReadFlip16();
            }
            // OFFLINE_SIGNATURE
            // SIGNATURE_INCLUDED
            if ( ( Flags & PacketFlags.SignatureIncluded ) != 0 )
            {
                Signature = new I2PSignature( reader, From.Certificate );
            }

            Payload = reader.ReadBufLen( reader.Length );
        }

        public void Write( BufRefStream dest )
        {
            // Not including options
            var headersize = 4 * 4 + 1 + NacKs.Count * 4 + 1 + 2 + 2;

            // Options
            var optionssize = ( Flags & PacketFlags.FromIncluded ) != 0 
                ? From.Size : 0;

            optionssize += ( Flags & PacketFlags.SignatureIncluded ) != 0
                ? From.SigningPublicKey.Certificate.SignatureLength
                : 0;

            optionssize += ( Flags & PacketFlags.MaxPacketSizeIncluded ) != 0
                ? 2 : 0;

            optionssize += ( Flags & PacketFlags.DelayRequested ) != 0
                ? 2 : 0;

            var header = new BufLen( new byte[headersize + optionssize] );
            var writer = new BufRefLen( header );

            writer.WriteFlip32( SendStreamId );
            writer.WriteFlip32( ReceiveStreamId );
            writer.WriteFlip32( SequenceNumber );
            writer.WriteFlip32( AckTrhough );

            writer.Write8( (byte)NacKs.Count );
            foreach ( var nak in NacKs )
            {
                writer.WriteFlip32( nak );
            }

            writer.Write8( ResendDelay );

            writer.WriteFlip16( (ushort)Flags );
            writer.WriteFlip16( (ushort)optionssize );

            // Options order
            // DELAY_REQUESTED
            // FROM_INCLUDED
            if ( ( Flags & PacketFlags.FromIncluded ) != 0 )
            {
                writer.Write( From.ToByteArray() );
            }
            // MAX_PACKET_SIZE_INCLUDED
            if ( ( Flags & PacketFlags.MaxPacketSizeIncluded ) != 0 )
            {
                writer.WriteFlip16( Mtu );
            }
            // OFFLINE_SIGNATURE
            // SIGNATURE_INCLUDED
            if ( ( Flags & PacketFlags.SignatureIncluded ) != 0 )
            {
                writer.Write( I2PSignature.DoSign( SigningKey, header ) );
            }

#if DEBUG
            if ( writer.Length != 0 )
            {
                throw new InvalidOperationException( "StreamingPacket Write buffer size error" );
            }
#endif

            dest.Write( (BufRefLen)header );
            dest.Write( (BufRefLen)Payload );
        }

        public override string ToString()
        {
            return $"{GetType().Name} {Flags} {From?.IdentHash.Id32Short} {ReceiveStreamId} {SendStreamId} {SequenceNumber} {AckTrhough}";
        }
    }
}
