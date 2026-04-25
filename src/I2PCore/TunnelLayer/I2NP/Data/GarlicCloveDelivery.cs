using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Data;

public abstract class GarlicCloveDelivery : I2PType
{
    [Flags]
    public enum DeliveryFlags : byte
    {
        // Optional, present if encrypt flag bit is set.
        // Unimplemented, never set, never present.
        Encrypted = 0x80,

        // Optional, present if delay included flag is set
        // Not fully implemented. Specifies the delay in seconds.
        Delay = 0x10
    }

    public enum DeliveryMethod : byte
    {
        Local = 0x00 << 5,
        Destination = 0x01 << 5,
        Router = 0x02 << 5,
        Tunnel = 0x03 << 5
    }

    public uint Delay; // Not used in current implementations
    public byte Flag;

    public I2NpMessage Message;

    public I2PSessionKey SessionKey; // Not used in current implementations

    protected GarlicCloveDelivery(DeliveryMethod mtd)
    {
        Flag = (byte)mtd;
    }

    protected GarlicCloveDelivery(I2NpMessage msg, DeliveryMethod mtd)
    {
        Message = msg;
        Flag = (byte)mtd;
    }

    public DeliveryMethod Delivery => (DeliveryMethod)(Flag & (0x03 << 5));

    public virtual void Write(IBufferWriter<byte> dest)
    {
        var flag = Flag;
        if (SessionKey != null) flag |= (byte)DeliveryFlags.Encrypted;
        if (Delay != 0) flag |= (byte)DeliveryFlags.Delay;
        dest.WriteByte(flag);

        if (SessionKey != null) SessionKey.Write(dest);
    }

    public static GarlicCloveDelivery CreateGarlicCloveDelivery(I2PBufferCursor reader)
    {
        var flag = reader.ReadByte();
        var deliv = (DeliveryMethod)(flag & (0x03 << 5));

        switch (deliv)
        {
            case DeliveryMethod.Local:
                return new GarlicCloveDeliveryLocal(reader, flag);

            case DeliveryMethod.Destination:
                return new GarlicCloveDeliveryDestination(reader, flag);

            case DeliveryMethod.Router:
                return new GarlicCloveDeliveryRouter(reader, flag);

            case DeliveryMethod.Tunnel:
                return new GarlicCloveDeliveryTunnel(reader, flag);

            default:
                Logging.LogWarning($"GarlicCloveDelivery: Unknown delivery method {deliv} in Garlic clove, skipping.");
                return null;
        }
    }

    public override string ToString()
    {
        return $"{GetType().Name} {Delivery} {Message?.GetType().Name}";
    }
}

public class GarlicCloveDeliveryLocal : GarlicCloveDelivery
{
    public GarlicCloveDeliveryLocal(I2NpMessage msg) : base(msg, DeliveryMethod.Local)
    {
    }

    public GarlicCloveDeliveryLocal(I2PBufferCursor reader, byte flag) : base(DeliveryMethod.Local)
    {
        Flag = flag;
        if ((Flag & (byte)DeliveryFlags.Encrypted) != 0) SessionKey = new I2PSessionKey(reader);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) Delay = reader.ReadUInt32BigEndian();
    }

    public override void Write(IBufferWriter<byte> dest)
    {
        base.Write(dest);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) dest.WriteUInt32BigEndian(0);
        dest.WriteBlock(Message.CreateHeader16.HeaderAndPayload);
    }
}

public class GarlicCloveDeliveryDestination : GarlicCloveDelivery
{
    public readonly I2PIdentHash Destination;

    public GarlicCloveDeliveryDestination(I2NpMessage msg, I2PIdentHash dest) : base(msg, DeliveryMethod.Destination)
    {
        Destination = dest;
    }

    public GarlicCloveDeliveryDestination(I2PBufferCursor reader, byte flag) : base(DeliveryMethod.Destination)
    {
        Flag = flag;
        if ((Flag & (byte)DeliveryFlags.Encrypted) != 0) SessionKey = new I2PSessionKey(reader);
        Destination = new I2PIdentHash(reader);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) Delay = reader.ReadUInt32BigEndian();
    }

    public override void Write(IBufferWriter<byte> dest)
    {
        base.Write(dest);
        Destination.Write(dest);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) dest.WriteUInt32BigEndian(0);
        dest.WriteBlock(Message.CreateHeader16.HeaderAndPayload);
    }
}

public class GarlicCloveDeliveryRouter : GarlicCloveDelivery
{
    public readonly I2PIdentHash Destination;

    public GarlicCloveDeliveryRouter(I2NpMessage msg, I2PIdentHash dest) : base(msg, DeliveryMethod.Router)
    {
        Destination = dest;
    }

    public GarlicCloveDeliveryRouter(I2PBufferCursor reader, byte flag) : base(DeliveryMethod.Router)
    {
        Flag = flag;
        if ((Flag & (byte)DeliveryFlags.Encrypted) != 0) SessionKey = new I2PSessionKey(reader);
        Destination = new I2PIdentHash(reader);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) Delay = reader.ReadUInt32BigEndian();
    }

    public override void Write(IBufferWriter<byte> dest)
    {
        base.Write(dest);
        Destination.Write(dest);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) dest.WriteUInt32BigEndian(0);
        dest.WriteBlock(Message.CreateHeader16.HeaderAndPayload);
    }
}

public class GarlicCloveDeliveryTunnel : GarlicCloveDelivery
{
    public readonly I2PIdentHash Destination;
    public readonly I2PTunnelId Tunnel;

    public GarlicCloveDeliveryTunnel(I2NpMessage msg, I2PIdentHash dest, I2PTunnelId tunnel)
        : base(msg, DeliveryMethod.Tunnel)
    {
        Destination = dest;
        Tunnel = tunnel;
    }

    public GarlicCloveDeliveryTunnel(I2NpMessage msg, InboundTunnel tunnel)
        : base(msg, DeliveryMethod.Tunnel)
    {
        Destination = tunnel.Destination;
        Tunnel = tunnel.GatewayTunnelId;
    }

    public GarlicCloveDeliveryTunnel(I2PBufferCursor reader, byte flag) : base(DeliveryMethod.Tunnel)
    {
        Flag = flag;
        if ((Flag & (byte)DeliveryFlags.Encrypted) != 0) SessionKey = new I2PSessionKey(reader);
        Destination = new I2PIdentHash(reader);
        Tunnel = new I2PTunnelId(reader);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) Delay = reader.ReadUInt32BigEndian();
    }

    public override void Write(IBufferWriter<byte> dest)
    {
        base.Write(dest);
        Destination.Write(dest);
        Tunnel.Write(dest);
        if ((Flag & (byte)DeliveryFlags.Delay) != 0) dest.WriteUInt32BigEndian(0);
        dest.WriteBlock(Message.CreateHeader16.HeaderAndPayload);
    }
}