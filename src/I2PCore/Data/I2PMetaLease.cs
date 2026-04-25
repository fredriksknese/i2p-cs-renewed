using System;
using System.Buffers;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.Data;

/// <summary>
///     MetaLease structure for MetaLeaseSet.
///     Same as Lease2 but with flags and cost instead of tunnel_id.
///     Supported as of 0.9.38 (proposal 123).
/// </summary>
public class I2PMetaLease : I2PType, ILease
{
    [Flags]
    public enum MetaLeaseFlags : uint
    {
        None = 0,
        LeaseSetTypeMask = 0x0F,
        LeaseSet = 0x01,
        LeaseSet2 = 0x03,
        MetaLeaseSet = 0x05
    }

    public const int StructureSize = 40; // 32 + 3 + 1 + 4 bytes

    /// <summary>
    ///     Create a new MetaLease
    /// </summary>
    public I2PMetaLease(
        I2PIdentHash tunnelgw,
        MetaLeaseFlags flags,
        byte cost,
        I2PDateShort enddate)
    {
        TunnelGw = tunnelgw;
        Flags = flags;
        Cost = cost;
        EndDate = enddate;
    }

    /// <summary>
    ///     Parse MetaLease from buffer
    /// </summary>
    public I2PMetaLease(I2PBufferCursor reader)
    {
        TunnelGw = new I2PIdentHash(reader);

        // Read 3 bytes of flags (24 bits)
        uint flagsValue = 0;
        flagsValue |= (uint)reader.ReadByte() << 16;
        flagsValue |= (uint)reader.ReadByte() << 8;
        flagsValue |= reader.ReadByte();
        Flags = (MetaLeaseFlags)flagsValue;

        Cost = reader.ReadByte();
        EndDate = new I2PDateShort(reader);
    }

    public MetaLeaseFlags Flags { get; set; }
    public byte Cost { get; set; }
    public I2PDateShort EndDate { get; set; }

    public DatabaseStoreMessage.MessageContent LeaseSetType
    {
        get
        {
            var typeValue = (uint)Flags & (uint)MetaLeaseFlags.LeaseSetTypeMask;
            return typeValue switch
            {
                1 => DatabaseStoreMessage.MessageContent.LeaseSet,
                3 => DatabaseStoreMessage.MessageContent.LeaseSet2,
                5 => DatabaseStoreMessage.MessageContent.MetaLeaseSet,
                _ => DatabaseStoreMessage.MessageContent.LeaseSet
            };
        }
    }

    public void Write(IBufferWriter<byte> dest)
    {
        TunnelGw.Write(dest);

        // Write 3 bytes of flags
        var flagsValue = (uint)Flags;
        dest.WriteByte((byte)((flagsValue >> 16) & 0xFF));
        dest.WriteByte((byte)((flagsValue >> 8) & 0xFF));
        dest.WriteByte((byte)(flagsValue & 0xFF));

        dest.WriteByte(Cost);
        EndDate.Write(dest);
    }

    public I2PIdentHash TunnelGw { get; set; }

    // ILease.TunnelId - MetaLease doesn't have a tunnel ID, return zero
    public I2PTunnelId TunnelId => I2PTunnelId.Zero;

    // ILease implementation
    public DateTime Expire => (DateTime)EndDate;

    public override string ToString()
    {
        return $"MetaLease: GW {TunnelGw.Id32Short}, Type {LeaseSetType}, Cost {Cost}, Expires {EndDate}";
    }
}