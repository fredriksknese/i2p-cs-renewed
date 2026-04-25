using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public abstract partial class I2NpMessage
    {
        public enum MessageTypes
        {
            DatabaseStore = 1,
            DatabaseLookup = 2,
            DatabaseSearchReply = 3,
            DeliveryStatus = 10,
            Garlic = 11,
            TunnelData = 18,
            TunnelGateway = 19,
            Data = 20,
            TunnelBuild = 21,
            TunnelBuildReply = 22,
            VariableTunnelBuild = 23,
            VariableTunnelBuildReply = 24,
            ShortTunnelBuild = 25,
            ShortTunnelBuildReply = 26,
            TunnelTest = 231
        }

#if DEBUG
        protected enum HeaderStates { Invalid, Header16, Header5 }

        private HeaderStates HeaderStateField = HeaderStates.Invalid;
        protected HeaderStates HeaderState
        {
            get => HeaderStateField;
            set
            {
                if ( HeaderStateField == value ) return;
                HeaderStateField = value;
                HeaderStateChanged?.Invoke();
            }
        }

        internal event Action HeaderStateChanged;
        internal void PayloadChanged() => HeaderStateChanged?.Invoke();
#endif

        // Always allocated with space for a 16 byte header in front
        // Message payload starts at Payload.
        private I2PByteBlock Buf;

        public abstract MessageTypes MessageType { get; }

        private uint? MessageIdField;
        public virtual uint MessageId
        {
            get
            {
                if ( MessageIdField.HasValue )
                {
                    return MessageIdField.Value;
                }

                MessageIdField = GenerateMessageId();
                return MessageIdField.Value;
            }
            set
            {
                MessageIdField = value;
#if DEBUG
                HeaderState = HeaderStates.Invalid;
#endif
            }
        }

        private I2PDate ExpirationField = null;
        public I2PDate Expiration
        {
            get
            {
                if ( ExpirationField != null )
                {
                    return ExpirationField;
                }

                ExpirationField = DefaultI2NpExpiration();
                return ExpirationField;
            }
            set
            {
                ExpirationField = value;
#if DEBUG
                HeaderState = HeaderStates.Invalid;
#endif
            }
        }

        // SetBuffer assumes that there is 16 bytes extra available in front of the message buffer.
        // If a message with a (received) 5 byte header is accessed with Header16 you will get an out 
        // of range exception, or faulty data.
        protected void SetBuffer( I2PBufferCursor start, I2PBufferCursor reader )
        {
            Buf = new I2PByteBlock( start.BaseArray, start.BaseArrayOffset - I2NpMaxHeaderSize, reader.DistanceFrom( start ) + I2NpMaxHeaderSize );
#if DEBUG
            HeaderState = HeaderStates.Invalid;
#endif
        }

        protected void AllocateBuffer( int size )
        {
            Buf = new I2PByteBlock( new byte[size + I2NpMaxHeaderSize] );
#if DEBUG
            HeaderState = HeaderStates.Invalid;
#endif
        }

        public static T Clone<T>( T src ) where T : I2NpMessage
        {
            return (T)I2NpUtil.GetMessage( src.MessageType, new I2PBufferCursor( src.Buf.Clone().ToByteArray(), I2NpMaxHeaderSize ), src.MessageId );
        }

        protected I2PByteBlock Header5Buf 
        { 
            get 
            {
#if DEBUG
                HeaderState = HeaderStates.Header5;
#endif
                return Buf.Slice( I2NpMaxHeaderSize - 5 ); 
            } 
        }

        protected I2PByteBlock Header16Buf 
        { 
            get 
            {
#if DEBUG
                HeaderState = HeaderStates.Header16;
#endif
                return Buf; 
            } 
        }

        public I2PByteBlock Payload { get { return Buf.Slice( I2NpMaxHeaderSize ); } }

        public static Ii2NpHeader16 ReadHeader16( I2PBufferCursor reader )
        {
            return new I2NpHeader16( reader );
        }

        public Ii2NpHeader16 CreateHeader16
        {
            get
            {
                return new I2NpHeader16( this );
            }
        }

#if DEBUG
        protected static void DebugCheckMessageCreation( I2NpMessage msg )
        {
            if ( msg.Buf.IsEmpty )
            {
                throw new NotImplementedException( $"I2NPMessage: '{msg.GetType().Name}' " +
                    $"failed to set up a memory buffer" );
            }
        }
#endif

        private static ItemFilterWindow<uint> _recentMessageIds = new( TickSpan.Minutes( 10 ), 1 );
        public static uint GenerateMessageId()
        {
            int iter = 0;
            uint result;

            lock ( _recentMessageIds )
            {
                do
                {
                    result = BufUtils.RandomUint();
                } while ( result == 0 || ( _recentMessageIds.Count( result ) > 0 && ++iter < 100 ) );

                _recentMessageIds.Update( result );
            }
            return result;
        }

        public static I2PDate DefaultI2NpExpiration()
        {
            // Ref impl uses 1 minute DEFAULT_EXPIRATION_MS in I2NPMessageImpl.java
            // From I2Pd I2NPProtocol.h I2NP_MESSAGE_EXPIRATION_TIMEOUT
            return new I2PDate( DateTime.UtcNow.AddSeconds( 60 ) );
        }
    }
}
