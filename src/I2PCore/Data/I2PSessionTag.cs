using System;
using System.Buffers;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PSessionTag : I2PType, IEquatable<I2PSessionTag>
{
    public const int TagLength = 32;

    // Session tag lifespan.
    // "The session tags delivered successfully are remembered for a brief period (15 minutes currently)"
    // https://geti2p.net/en/docs/how/elgamal-aes
    public static readonly TickSpan TagLifetime = TickSpan.Minutes(15);
    public readonly TickCounter Created = TickCounter.Now;

    public readonly I2PByteBlock Value;

    public I2PSessionTag()
    {
        Value = new I2PByteBlock(BufUtils.RandomBytes(TagLength));
    }

    public I2PSessionTag(I2PBufferCursor buf)
    {
        Value = buf.ReadBlock(TagLength);
    }

    public I2PSessionTag(I2PBufferCursor buf, int tagsize)
    {
        Value = buf.ReadBlock(tagsize);
    }

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteBlock(Value);
    }

    public bool Equals(I2PSessionTag other)
    {
        if (other is null) return false;
        return Value == other.Value;
    }

    public override int GetHashCode()
    {
        return Value.GetHashCode();
    }
}