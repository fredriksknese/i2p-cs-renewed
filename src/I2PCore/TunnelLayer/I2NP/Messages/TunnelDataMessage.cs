using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class TunnelDataMessage: I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.TunnelData; } }

        private I2PByteBlock FirstDeliveryInstruction;

        public TunnelDataMessage( I2PTunnelId desttunnel )
        {
            AllocateBuffer( DataLength + 4 );

            TunnelId = desttunnel;
            Iv.Randomize();
        }

        public TunnelDataMessage( byte[] data, I2PTunnelId tunnel )
        {
            var start = new I2PBufferCursor( data );
            var reader = new I2PBufferCursor( data );
            reader.Seek( 4 + DataLength );
            SetBuffer( start, reader );
            TunnelId = tunnel;

            UpdateFirstDeliveryInstructionPosition();
        }

        public TunnelDataMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );
            reader.Seek( 4 + DataLength );
            SetBuffer( start, reader );
        }

        public void UpdateFirstDeliveryInstructionPosition()
        {
            FirstDeliveryInstruction = FindTheZero( PaddingStart );
        }

        internal void SetFirstDeliveryInstructionPoint( I2PByteBlock di )
        {
            FirstDeliveryInstruction = di;
        }

        private static I2PByteBlock FindTheZero( I2PByteBlock start )
        {
            var result = new I2PBufferCursor( start );
            while ( result.ReadByte() != 0 ) ;
            return result.CurrentBlock;
        }

        public I2PTunnelId TunnelId
        {
            get
            {
                return new I2PTunnelId( Payload.ReadUInt32BigEndian( 0 ) );
            }
            set
            {
                Payload.WriteUInt32BigEndian( value, 0 );
            }
        }

        public I2PByteBlock Iv
        {
            get
            {
                return Payload.Slice( 4, 16 );
            }
            set
            {
                Payload.CopyFrom( value, 4 );
            }
        }

        public I2PByteBlock EncryptedWindow
        {
            get
            {
                return Payload.Slice( 20, 1008 );
            }
            set
            {
                Payload.CopyFrom( Payload, 20 );
            }
        }

        public I2PByteBlock Checksum
        {
            get
            {
                return Payload.Slice( 20, 4 );
            }
            set
            {
                Payload.CopyFrom( value, 20 );
            }
        }

        public I2PByteBlock PaddingStart
        {
            get
            {
                return Payload.Slice( 24, 1004 );
            }
            set
            {
                Payload.CopyFrom( value, 24 );
            }
        }

        public ushort DataLength
        {
            get
            {
                return 1024;
            }
        }

        public I2PByteBlock TunnelDataPayload
        {
            get
            {
                if ( FirstDeliveryInstruction.IsEmpty ) UpdateFirstDeliveryInstructionPosition();
                return FirstDeliveryInstruction;
            }
        }

        public override string ToString()
        {
            return $"{GetType().Name}: {TunnelId}";
        }

        public static IEnumerable<TunnelDataMessage> MakeFragments( IEnumerable<TunnelMessage> messages, I2PTunnelId desttunnel )
        {
            var padcalc = CalculatePadding( messages, desttunnel );

            foreach ( var one in padcalc.TdMessages )
            {
                var writer = new I2PBufferCursor( one.TunnelDataInstance.Payload );

                writer.Seek( 24 ); // TunnelID, IV, Checksum of "Tunnel Message (Decrypted)"
                if ( one.PaddingNeeded > 0 )
                {
                    writer.WriteBytes( BufUtils.RandomNz( one.PaddingNeeded ) );
                }

                writer.WriteByte( 0 ); // The Zero
                one.TunnelDataInstance.SetFirstDeliveryInstructionPoint( writer.CurrentBlock );

                foreach ( var frag in one.Fragments )
                {
                    frag.Append( writer );
                }

                one.TunnelDataInstance.Checksum.CopyFrom(
                    new ReadOnlySpan<byte>( I2PHashSha256.GetHash(
                        one.TunnelDataInstance.FirstDeliveryInstruction,
                        one.TunnelDataInstance.Iv ), 0, 4 ), 0 );

                if ( writer.Remaining != 0 )
                {
                    Logging.LogCritical( "TunnelData: MakeFragments. Tunnel block is not filled!" );
                    throw new Exception( "TunnelData message not filled. Something is wrong." );
                }
            }

            return padcalc.TdMessages.Select( msg => msg.TunnelDataInstance );
        }

        internal class TunnelDataConstructionInfo
        {
            internal TunnelDataConstructionInfo( I2PTunnelId desttunnel )
            {
                TunnelDataInstance = new TunnelDataMessage( desttunnel );
            }

            internal TunnelDataMessage TunnelDataInstance;
            internal int PaddingNeeded;
            internal List<TunnelDataFragmentCreation> Fragments = new();
        }

        internal class PaddingInfo
        {
            internal List<TunnelDataConstructionInfo> TdMessages = new();
        }

        private const int FreeSpaceInDataMessageBody =  1003; // 1028 - 4 - 16 - 4 - 1 (Zero)
        private const int FollowOnFragmentHeaderSize = 7; // 1 + 4 + 2

        // Minimum space left for payload to start a new fragment in a TunnelData block.
        private const int TunnelDataMessageFreeSpaceLowWatermark = 10;

        private static PaddingInfo CalculatePadding( IEnumerable<TunnelMessage> messages, I2PTunnelId desttunnel )
        {
            var result = new PaddingInfo();

            int tunneldatabufferavailable = FreeSpaceInDataMessageBody;
            var currenttdrecord = new TunnelDataConstructionInfo( desttunnel );
            result.TdMessages.Add( currenttdrecord );

            var lastix = messages.Count() - 1;
            var ix = 0;
            foreach( var one in messages )
            {
                var lastmessage = ix++ == lastix;

                var data = one.Message.CreateHeader16.HeaderAndPayload;
                var datareader = new I2PBufferCursor( data );

            nexttunneldatablock:

                int firstfragmentheadersize;
                bool fragmented = false;

                switch ( one.Delivery )
                {
                    case TunnelMessage.DeliveryTypes.Local:
                        firstfragmentheadersize = 3;
                        if ( data.Length + firstfragmentheadersize > tunneldatabufferavailable )
                        {
                            firstfragmentheadersize += 4; // Need message id
                            fragmented = true;
                        }
                        break;

                    case TunnelMessage.DeliveryTypes.Router:
                        firstfragmentheadersize = 35;
                        if ( data.Length + firstfragmentheadersize > tunneldatabufferavailable )
                        {
                            firstfragmentheadersize += 4; // Need message id
                            fragmented = true;
                        }
                        break;

                    case TunnelMessage.DeliveryTypes.Tunnel:
                        firstfragmentheadersize = 39;
                        if ( data.Length + firstfragmentheadersize > tunneldatabufferavailable )
                        {
                            firstfragmentheadersize += 4; // Need message id
                            fragmented = true;
                        }
                        break;

                    default:
                        Logging.LogWarning( $"TunnelDataMessage: Unknown delivery type {one.Delivery}" );
                        continue;
                }

                var freespace = tunneldatabufferavailable - firstfragmentheadersize;

                if ( freespace < TunnelDataMessageFreeSpaceLowWatermark )
                {
                    currenttdrecord.PaddingNeeded = tunneldatabufferavailable;

                    currenttdrecord = new TunnelDataConstructionInfo( desttunnel );
                    result.TdMessages.Add( currenttdrecord );
                    tunneldatabufferavailable = FreeSpaceInDataMessageBody;
                    goto nexttunneldatablock;
                }

                // Might fit, and have at least TUNNEL_DATA_MESSAGE_FREE_SPACE_LOW_WATERMARK bytes for payload.

                var useddata = fragmented ? freespace : datareader.Remaining;
                var usedspace = firstfragmentheadersize + useddata;

                currenttdrecord.Fragments.Add(
                    new TunnelDataFragmentCreation(
                        currenttdrecord.TunnelDataInstance,
                        one,
                        new I2PByteBlock( datareader.BaseArray, datareader.BaseArrayOffset, useddata ),
                        fragmented ) );

                datareader.Seek( useddata );

                tunneldatabufferavailable -= usedspace;

                int fragnr = 1;
                while ( datareader.Remaining > 0 )
                {
                    if ( tunneldatabufferavailable < TunnelDataMessageFreeSpaceLowWatermark + FollowOnFragmentHeaderSize )
                    {
                        currenttdrecord.PaddingNeeded = tunneldatabufferavailable;

                        currenttdrecord = new TunnelDataConstructionInfo( desttunnel );
                        result.TdMessages.Add( currenttdrecord );
                        tunneldatabufferavailable = FreeSpaceInDataMessageBody;
                    }

                    freespace = tunneldatabufferavailable - FollowOnFragmentHeaderSize;

                    if ( datareader.Remaining <= freespace )
                    {
                        currenttdrecord.Fragments.Add(
                            new TunnelDataFragmentFollowOn(
                                currenttdrecord.TunnelDataInstance,
                                one,
                                new I2PByteBlock( datareader.BaseArray, datareader.BaseArrayOffset, datareader.Remaining ),
                                fragnr++, true
                                ) );

                        tunneldatabufferavailable -= FollowOnFragmentHeaderSize + datareader.Remaining;
                        datareader.Seek( datareader.Remaining );

                        if ( lastmessage )
                        {
                            currenttdrecord.PaddingNeeded = tunneldatabufferavailable;
                            return result;
                        }
                    }
                    else
                    {
                        useddata = freespace;

                        currenttdrecord.Fragments.Add(
                            new TunnelDataFragmentFollowOn(
                                currenttdrecord.TunnelDataInstance,
                                one,
                                new I2PByteBlock( datareader.BaseArray, datareader.BaseArrayOffset, useddata ),
                                fragnr++,
                                false
                                ) );
                        datareader.Seek( useddata );

                        tunneldatabufferavailable = 0;
                    }
                }
            }

            currenttdrecord.PaddingNeeded = tunneldatabufferavailable;
            return result;
        }
    }
}
