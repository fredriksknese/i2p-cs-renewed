using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class SetDateMessage : I2CpMessage
{
    public I2PDate Date;
    public I2PString Version;

    public SetDateMessage(I2PDate date, I2PString ver)
        : base(ProtocolMessageType.SetDate)
    {
        Date = date;
        Version = ver;
    }

    public SetDateMessage(I2PBufferCursor data)
        : base(ProtocolMessageType.SetDate)
    {
        Date = new I2PDate(data);
        Version = new I2PString(data);
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        Date.Write(dest);
        Version.Write(dest);
    }
}