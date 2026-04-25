using System.Text;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

public class TunnelGatewayMessage : I2NpMessage
{
    public TunnelGatewayMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);
        reader.Seek(6 + reader.PeekUInt16BigEndian(4));
        SetBuffer(start, reader);
    }

    public TunnelGatewayMessage(I2NpMessage message, I2PTunnelId outtunnel)
    {
        var msg = message.CreateHeader16.HeaderAndPayload;
        AllocateBuffer(6 + msg.Length);

        TunnelId = outtunnel;
        GatewayMessageLength = (ushort)msg.Length;
        // TODO: Remove mem copy
        Payload.CopyFrom(msg, 6);
    }

    public override MessageTypes MessageType => MessageTypes.TunnelGateway;

    public uint TunnelId
    {
        get => Payload.ReadUInt32BigEndian(0);
        set => Payload.WriteUInt32BigEndian(value, 0);
    }

    public ushort GatewayMessageLength
    {
        get => Payload.ReadUInt16BigEndian(4);
        set => Payload.WriteUInt16BigEndian(value, 4);
    }

    public I2PByteBlock GatewayMessage => Payload.Slice(6, GatewayMessageLength);

    protected MessageTypes GatewayMessageType => (MessageTypes)GatewayMessage.ReadByte(0);

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("TunnelGateway");
        result.AppendLine("TunnelId:          : " + TunnelId);
        result.AppendLine("GatewayMessageType : " + GatewayMessageType + " ( " + GatewayMessageLength + " bytes )");

        return result.ToString();
    }
}