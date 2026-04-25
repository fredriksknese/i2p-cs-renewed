using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class SendMessageMessage : I2CpMessage
{
    public I2PDestination Destination;
    public uint Nonce;
    public I2PByteBlock Payload;
    public ushort SessionId;

    public SendMessageMessage(I2PBufferCursor reader)
        : base(ProtocolMessageType.SendMessage)
    {
        SessionId = reader.ReadUInt16BigEndian();
        Destination = new I2PDestination(reader);
        var len = reader.ReadUInt32BigEndian();
        Payload = reader.ReadBlock((int)len);
        Nonce = reader.ReadUInt32BigEndian();
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        dest.WriteUInt16BigEndian(SessionId);
        Destination.Write(dest);
        dest.WriteUInt32BigEndian((uint)Payload.Length);
        dest.WriteBlock(Payload);
        dest.WriteUInt32BigEndian(Nonce);
    }
}