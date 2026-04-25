using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class HostLookupMessage : I2CpMessage
{
    public enum HostLookupTypes : byte
    {
        Hash = 0,
        HostName = 1
    }

    public I2PIdentHash Hash;
    public I2PString HostName;
    public uint RequestId;
    public HostLookupTypes RequestType;

    public ushort SessionId;
    public uint TimeoutMilliseconds;

    public HostLookupMessage(I2PBufferCursor reader)
        : base(ProtocolMessageType.HostLookup)
    {
        SessionId = reader.ReadUInt16BigEndian();
        RequestId = reader.ReadUInt32BigEndian();
        TimeoutMilliseconds = reader.ReadUInt32BigEndian();
        RequestType = (HostLookupTypes)reader.ReadByte();

        switch (RequestType)
        {
            case HostLookupTypes.Hash:
                Hash = new I2PIdentHash(reader);
                break;

            case HostLookupTypes.HostName:
                HostName = new I2PString(reader);
                break;
        }
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        dest.WriteUInt16BigEndian(SessionId);
        dest.WriteUInt32BigEndian(RequestId);
        dest.WriteUInt32BigEndian(TimeoutMilliseconds);
        dest.WriteByte((byte)RequestType);

        switch (RequestType)
        {
            case HostLookupTypes.Hash:
                Hash.Write(dest);
                break;

            case HostLookupTypes.HostName:
                HostName.Write(dest);
                break;
        }
    }

    public override string ToString()
    {
        return $"{GetType().Name} {SessionId} {RequestId} {Hash?.Id32Short} {HostName}";
    }
}