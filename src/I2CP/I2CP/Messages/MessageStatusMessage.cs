using System.Buffers;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class MessageStatusMessage : I2CpMessage
{
    public enum MessageStatatuses : byte
    {
        Available = 0,
        Accepted = 1,
        BestEffortSuccess = 2,
        BestEffortFailure = 3,
        GuaranteedSuccess = 4,
        GuaranteedFailure = 5,
        LocalSuccess = 6,
        LocalFailure = 7,
        RouterFailure = 8,
        NetworkFailure = 9,
        BadSession = 10,
        BadMessage = 11,
        BadOptions = 12,
        OverflowFailure = 13,
        MessageExpired = 14,
        BadLocalLeaseset = 15,
        NoLocalTunnels = 16,
        UnsupportedEncryption = 17,
        BadDestination = 18,
        BadLeaseset = 19,
        ExpiredLeaseset = 20,
        NoLeaseset = 21
    }

    public uint AvailableMessageSize;
    public uint ClientNonce;
    public uint MessageId;
    public MessageStatatuses MessageStatus;
    public ushort SessionId;

    public MessageStatusMessage(
        ushort sessionid,
        uint messageid,
        MessageStatatuses messagestatus,
        uint availablemessagesize,
        uint clientnonce
    ) : base(ProtocolMessageType.MessageStatus)
    {
        SessionId = sessionid;
        MessageId = messageid;
        MessageStatus = messagestatus;
        AvailableMessageSize = availablemessagesize;
        ClientNonce = clientnonce;
    }

    public MessageStatusMessage(I2PBufferCursor reader)
        : base(ProtocolMessageType.MessageStatus)
    {
        SessionId = reader.ReadUInt16BigEndian();
        MessageId = reader.ReadUInt32BigEndian();
        MessageStatus = (MessageStatatuses)reader.ReadByte();
        AvailableMessageSize = reader.ReadUInt32BigEndian();
        ClientNonce = reader.ReadUInt32BigEndian();
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        var header = new byte[15];
        var writer = new I2PBufferCursor(header);
        writer.WriteUInt16BigEndian(SessionId);
        writer.WriteUInt32BigEndian(MessageId);
        writer.WriteByte((byte)MessageStatus);
        writer.WriteUInt32BigEndian(AvailableMessageSize);
        writer.WriteUInt32BigEndian(ClientNonce);
        dest.Write(header);
    }
}