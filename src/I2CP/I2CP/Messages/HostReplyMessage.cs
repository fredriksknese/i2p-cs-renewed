using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class HostReplyMessage : I2CpMessage
{
    public enum HostLookupResults : byte
    {
        Success = 0,
        Failure = 1,
        LookupPasswordRequired = 2,
        PrivateKeyRequired = 3,
        LookupPasswordAndPrivateKeyRequired = 4,
        LeasesetDecryptionFailure = 5
    }

    public I2PDestination Destination;
    public uint RequestId;
    public HostLookupResults ResultCode;

    public ushort SessionId;

    public HostReplyMessage(ushort sessid, uint reqid, HostLookupResults rescode)
        : base(ProtocolMessageType.HostLookupReply)
    {
        SessionId = sessid;
        RequestId = reqid;
        ResultCode = rescode;
    }

    public HostReplyMessage(ushort sessid, uint reqid, I2PDestination dest)
        : base(ProtocolMessageType.HostLookupReply)
    {
        SessionId = sessid;
        RequestId = reqid;
        ResultCode = HostLookupResults.Success;
        Destination = dest;
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        var header = new byte[7];
        var writer = new I2PBufferCursor(header);
        writer.WriteUInt16BigEndian(SessionId);
        writer.WriteUInt32BigEndian(RequestId);
        writer.WriteByte((byte)ResultCode);
        dest.Write(header);

        if (ResultCode == HostLookupResults.Success) Destination.Write(dest);
    }

    public override string ToString()
    {
        return $"{GetType().Name} {SessionId} {RequestId} {ResultCode} {Destination}";
    }
}