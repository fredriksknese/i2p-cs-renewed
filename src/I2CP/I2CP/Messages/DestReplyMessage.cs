using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class DestReplyMessage : I2CpMessage
{
    public I2PDestination Destination;
    public I2PIdentHash Ident;

    // Success
    public DestReplyMessage(I2PDestination dest)
        : base(ProtocolMessageType.DestReply)
    {
        Destination = dest;
    }

    // Failure
    public DestReplyMessage(I2PIdentHash hash)
        : base(ProtocolMessageType.DestReply)
    {
        Ident = hash;
    }

    public DestReplyMessage(I2PBufferCursor reader)
        : base(ProtocolMessageType.DestReply)
    {
        Destination = null;
        Ident = null;

        if (reader.Remaining == 0) return;
        if (reader.Remaining == 32)
            Ident = new I2PIdentHash(reader);
        else
            Destination = new I2PDestination(reader);
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        if (Destination != null)
        {
            Destination.Write(dest);
            return;
        }

        Ident.Write(dest);
    }
}