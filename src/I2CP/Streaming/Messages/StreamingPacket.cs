using System;
using System.Buffers;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.Streaming;

public class StreamingPacket
{
    [Flags]
    public enum PacketFlags : ushort
    {
        Synchronize = 1 << 0,
        Close = 1 << 1,
        Reset = 1 << 2,
        SignatureIncluded = 1 << 3,
        SignatureRequested = 1 << 4,
        FromIncluded = 1 << 5,
        DelayRequested = 1 << 6,
        MaxPacketSizeIncluded = 1 << 7,
        ProfileInteractive = 1 << 8,
        Echo = 1 << 9,
        NoAck = 1 << 10,
        OfflineSignature = 1 << 11
    }

    public const int Mtu = 1730;
    public uint AckTrhough;
    public PacketFlags Flags;

    public I2PDestination From;
    public List<uint> NacKs;
    public I2PByteBlock Payload;

    public uint ReceiveStreamId;
    public byte ResendDelay;
    public uint SendStreamId;
    public uint SequenceNumber;
    public I2PSignature Signature;
    public I2PSigningPrivateKey SigningKey;

    public StreamingPacket(PacketFlags flags)
    {
        Flags = flags;
    }

    public StreamingPacket(I2PBufferCursor reader)
    {
        SendStreamId = reader.ReadUInt32BigEndian();
        ReceiveStreamId = reader.ReadUInt32BigEndian();
        SequenceNumber = reader.ReadUInt32BigEndian();
        AckTrhough = reader.ReadUInt32BigEndian();

        NacKs = new List<uint>();
        var nackcount = reader.ReadByte();
        for (var i = 0; i < nackcount; ++i) NacKs.Add(reader.ReadUInt32BigEndian());

        ResendDelay = reader.ReadByte();

        Flags = (PacketFlags)reader.ReadUInt16BigEndian();
        var optionsize = reader.ReadUInt16BigEndian();

        // Options order
        // DELAY_REQUESTED
        // FROM_INCLUDED
        if ((Flags & PacketFlags.FromIncluded) != 0) From = new I2PDestination(reader);
        // MAX_PACKET_SIZE_INCLUDED
        if ((Flags & PacketFlags.MaxPacketSizeIncluded) != 0)
        {
            var mtu = reader.ReadUInt16BigEndian();
        }

        // OFFLINE_SIGNATURE
        // SIGNATURE_INCLUDED
        if ((Flags & PacketFlags.SignatureIncluded) != 0) Signature = new I2PSignature(reader, From.Certificate);

        Payload = reader.ReadBlock(reader.Remaining);
    }

    public void Write(ArrayBufferWriter<byte> dest)
    {
        // Not including options
        var headersize = 4 * 4 + 1 + NacKs.Count * 4 + 1 + 2 + 2;

        // Options
        var optionssize = (Flags & PacketFlags.FromIncluded) != 0
            ? From.Size
            : 0;

        optionssize += (Flags & PacketFlags.SignatureIncluded) != 0
            ? From.SigningPublicKey.Certificate.SignatureLength
            : 0;

        optionssize += (Flags & PacketFlags.MaxPacketSizeIncluded) != 0
            ? 2
            : 0;

        optionssize += (Flags & PacketFlags.DelayRequested) != 0
            ? 2
            : 0;

        var header = new I2PByteBlock(new byte[headersize + optionssize]);
        var writer = new I2PBufferCursor(header);

        writer.WriteUInt32BigEndian(SendStreamId);
        writer.WriteUInt32BigEndian(ReceiveStreamId);
        writer.WriteUInt32BigEndian(SequenceNumber);
        writer.WriteUInt32BigEndian(AckTrhough);

        writer.WriteByte((byte)NacKs.Count);
        foreach (var nak in NacKs) writer.WriteUInt32BigEndian(nak);

        writer.WriteByte(ResendDelay);

        writer.WriteUInt16BigEndian((ushort)Flags);
        writer.WriteUInt16BigEndian((ushort)optionssize);

        // Options order
        // DELAY_REQUESTED
        // FROM_INCLUDED
        if ((Flags & PacketFlags.FromIncluded) != 0) writer.WriteBytes(From.ToByteArray());
        // MAX_PACKET_SIZE_INCLUDED
        if ((Flags & PacketFlags.MaxPacketSizeIncluded) != 0) writer.WriteUInt16BigEndian(Mtu);
        // OFFLINE_SIGNATURE
        // SIGNATURE_INCLUDED
        if ((Flags & PacketFlags.SignatureIncluded) != 0) writer.WriteBytes(I2PSignature.DoSign(SigningKey, header));

#if DEBUG
        if (writer.Length != 0) throw new InvalidOperationException("StreamingPacket Write buffer size error");
#endif

        dest.WriteBlock(header);
        dest.WriteBlock(Payload);
    }

    public override string ToString()
    {
        return
            $"{GetType().Name} {Flags} {From?.IdentHash.Id32Short} {ReceiveStreamId} {SendStreamId} {SequenceNumber} {AckTrhough}";
    }
}