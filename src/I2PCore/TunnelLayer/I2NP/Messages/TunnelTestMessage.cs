using System;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Data;

/// <summary>
///     I2NP TunnelTest message (type 231).
///     Same structure as DeliveryStatus: 4-byte msgID + 8-byte timestamp = 12 bytes.
///     Used by i2pd for tunnel latency testing.
/// </summary>
public sealed class TunnelTestMessage : I2NpMessage
{
    public TunnelTestMessage()
    {
        AllocateBuffer(12);
        Timestamp = new I2PDate(DateTime.UtcNow);
        TestMessageId = GenerateMessageId();
    }

    public TunnelTestMessage(uint msgid)
    {
        AllocateBuffer(12);
        Timestamp = new I2PDate(DateTime.UtcNow);
        TestMessageId = msgid;
    }

    public TunnelTestMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);
        reader.Seek(12);
        SetBuffer(start, reader);
    }

    public override MessageTypes MessageType => MessageTypes.TunnelTest;

    public uint TestMessageId
    {
        get => Payload.ReadUInt32BigEndian(0);
        set => Payload.WriteUInt32BigEndian(value, 0);
    }

    public I2PDate Timestamp
    {
        get => new(new I2PBufferCursor(Payload.BaseArray, Payload.BaseArrayOffset + 4));
        set => value.Poke(Payload, 4);
    }

    public override string ToString()
    {
        return $"TunnelTest MessageId: {TestMessageId}, Timestamp: {Timestamp}.";
    }
}