using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

public class TunnelDataFragmentCreation
{
    protected bool Fragmented;
    protected TunnelMessage SourceMessage;
    protected I2PByteBlock SourceMessageData;
    protected TunnelDataMessage TdInstance;

    public TunnelDataFragmentCreation(TunnelDataMessage td, TunnelMessage srcmsg, I2PByteBlock tmdata, bool fragmented)
    {
        TdInstance = td;
        SourceMessage = srcmsg;
        SourceMessageData = tmdata;
        Fragmented = fragmented;
    }

    public virtual void Append(I2PBufferCursor writer)
    {
        switch (SourceMessage.Delivery)
        {
            case TunnelMessage.DeliveryTypes.Local:
                writer.WriteByte((byte)((byte)TunnelMessage.DeliveryTypes.Local | (Fragmented ? 0x08 : 0)));
                if (Fragmented) writer.WriteUInt32BigEndian(SourceMessage.Message.MessageId);
                writer.WriteUInt16BigEndian((ushort)SourceMessageData.Length);
                writer.WriteBlock(SourceMessageData);
                break;

            case TunnelMessage.DeliveryTypes.Router:
                writer.WriteByte((byte)((byte)TunnelMessage.DeliveryTypes.Router | (Fragmented ? 0x08 : 0)));
                writer.WriteBlock(((TunnelMessageRouter)SourceMessage).Destination.Hash);
                if (Fragmented) writer.WriteUInt32BigEndian(SourceMessage.Message.MessageId);
                writer.WriteUInt16BigEndian((ushort)SourceMessageData.Length);
                writer.WriteBlock(SourceMessageData);
                break;

            case TunnelMessage.DeliveryTypes.Tunnel:
                writer.WriteByte((byte)((byte)TunnelMessage.DeliveryTypes.Tunnel | (Fragmented ? 0x08 : 0)));
                writer.WriteUInt32BigEndian(((TunnelMessageTunnel)SourceMessage).Tunnel);
                writer.WriteBlock(((TunnelMessageTunnel)SourceMessage).Destination.Hash);
                if (Fragmented) writer.WriteUInt32BigEndian(SourceMessage.Message.MessageId);
                writer.WriteUInt16BigEndian((ushort)SourceMessageData.Length);
                writer.WriteBlock(SourceMessageData);
                break;

            default:
                Logging.LogWarning($"TunnelDataFragmentCreation: Unknown delivery type {SourceMessage.Delivery}");
                return;
        }
    }
}

public class TunnelDataFragmentFollowOn : TunnelDataFragmentCreation
{
    private readonly int FragmentNumber;
    private readonly bool LastFragment;

    public TunnelDataFragmentFollowOn(TunnelDataMessage td, TunnelMessage srcmsg, I2PByteBlock tmdata, int fragnr,
        bool lastfrag)
        : base(td, srcmsg, tmdata, true)
    {
        FragmentNumber = fragnr;
        LastFragment = lastfrag;
    }

    public override void Append(I2PBufferCursor writer)
    {
        writer.WriteByte((byte)(0x80 | (FragmentNumber << 1) | (LastFragment ? 0x01 : 0x00)));
        writer.WriteUInt32BigEndian(SourceMessage.Message.MessageId);
        writer.WriteUInt16BigEndian((ushort)SourceMessageData.Length);
        writer.WriteBlock(SourceMessageData);
    }
}