using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

public interface Ii2NpHeader16 : Ii2NpHeader
{
    uint MessageId { get; set; }
    ushort PayloadLength { get; set; }
    byte PayloadChecksum { get; set; }
}

public partial class I2NpMessage
{
    public const int I2NpMaxHeaderSize = 16;

    protected sealed class I2NpHeader16 : Ii2NpHeader16
    {
        private const int HeaderLength = 16;

        private readonly I2PByteBlock Buf;

        private bool HeaderStateOk = true;

        private I2NpMessage MessageRefField;

        // Created from stream
        public I2NpHeader16(I2PBufferCursor reader)
        {
            Buf = reader.CurrentBlock;

            reader.Seek(HeaderLength);

            MessageRef = I2NpUtil.GetMessage(
                MessageType,
                reader,
                MessageId);

            MessageRef.Expiration = Expiration;
#if DEBUG
            DebugCheckMessageCreation(MessageRef);
#endif
        }

        // Created from I2PMessage
        public I2NpHeader16(I2NpMessage msg)
        {
            Buf = msg.Buf;

            MessageRef = msg;

            MessageType = msg.MessageType;
            Expiration = msg.Expiration;
            MessageId = msg.MessageId;

            PayloadLength = (ushort)msg.Payload.Length;

            var s = I2PHashSha256.GetHash(msg.Payload);
            PayloadChecksum = s[0];
#if DEBUG
            DebugCheckMessageCreation(MessageRef);
#endif
        }

        private I2NpMessage MessageRef
        {
            get => MessageRefField;
            set
            {
                MessageRefField = value;
#if DEBUG
                MessageRefField.HeaderStateChanged += HeaderStateInvalid;
#endif
            }
        }

        public MessageTypes MessageType
        {
            get => (MessageTypes)Buf.ReadByte(0);
            set => Buf.WriteByte((byte)value, 0);
        }

        public I2PByteBlock HeaderAndPayload
        {
            get
            {
                if (!HeaderStateOk)
                    throw new InvalidOperationException(
                        $"{this}: Message state have changed");
                return Buf;
            }
        }

        public uint MessageId
        {
            get => Buf.ReadUInt32BigEndian(1);
            set => Buf.WriteUInt32BigEndian(value, 1);
        }

        public I2PDate Expiration
        {
            get => new(Buf.ReadUInt64BigEndian(5));
            set => Buf.WriteUInt64BigEndian((ulong)value, 5);
        }

        public int Length => HeaderLength;

        public ushort PayloadLength
        {
            get => Buf.ReadUInt16BigEndian(13);
            set => Buf.WriteUInt16BigEndian(value, 13);
        }

        public byte PayloadChecksum
        {
            get => Buf.ReadByte(15);
            set => Buf.WriteByte(value, 15);
        }

        public I2NpMessage Message => MessageRef;

        public override string ToString()
        {
            return $"{GetType().Name} MessageId: {MessageId}";
        }

#if DEBUG
        private void HeaderStateInvalid()
        {
            HeaderStateOk = false;
        }
#endif

        public void Write(IBufferWriter<byte> dest)
        {
            dest.WriteBlock(HeaderAndPayload);
        }
    }
}