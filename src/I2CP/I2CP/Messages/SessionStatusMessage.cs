using System.Buffers;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class SessionStatusMessage : I2CpMessage
{
    public enum SessionStates : byte
    {
        Destroyed = 0,
        Created = 1,
        Updated = 2,
        Invalid = 3,
        Refused = 4,
        NoLeaseSet = 21
    }

    public ushort SessionId;
    public SessionStates SessionState;

    public SessionStatusMessage(ushort sessid, SessionStates state)
        : base(ProtocolMessageType.SessionStatus)
    {
        SessionId = sessid;
        SessionState = state;
    }

    public SessionStatusMessage(I2PBufferCursor reader)
        : base(ProtocolMessageType.SessionStatus)
    {
        SessionId = reader.ReadUInt16BigEndian();
        SessionState = (SessionStates)reader.ReadByte();
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        var header = new byte[3];
        var writer = new I2PBufferCursor(header);
        writer.WriteUInt16BigEndian(SessionId);
        writer.WriteByte((byte)SessionState);
        dest.Write(header);
    }
}