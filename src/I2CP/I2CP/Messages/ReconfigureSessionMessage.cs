using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class ReconfigureSessionMessage : I2CpMessage
{
    public I2PSessionConfig Config;
    public ushort SessionId;

    public ReconfigureSessionMessage(I2PSessionConfig cfg) : base(ProtocolMessageType.ReconfigSession)
    {
        Config = cfg;
    }

    public ReconfigureSessionMessage(I2PBufferCursor reader) : base(ProtocolMessageType.ReconfigSession)
    {
        SessionId = reader.ReadUInt16BigEndian();
        Config = new I2PSessionConfig(reader);
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        dest.WriteUInt16BigEndian(SessionId);
        Config.Write(dest);
    }

    public override string ToString()
    {
        return Config?.ToString();
    }
}