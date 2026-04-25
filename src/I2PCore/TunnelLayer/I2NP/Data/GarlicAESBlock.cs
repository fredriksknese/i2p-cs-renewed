using System;
using System.Buffers;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Data;

public class GarlicAesBlock : I2PType
{
    public I2PByteBlock DataBuf;
    public I2PByteBlock Flag;
    public I2PSessionKey NewSessionKey;
    public I2PByteBlock Padding;
    public I2PByteBlock Payload;
    public I2PByteBlock PayloadHash;
    public I2PByteBlock PayloadSize;
    public I2PByteBlock TagCount;
    public List<I2PByteBlock> Tags = new();

    public GarlicAesBlock(I2PBufferCursor reader)
    {
        var startPos = reader.Position;

        TagCount = reader.ReadBlock(2);
        var tags = TagCount.ReadUInt16BigEndian(0);
        if (tags > 0)
        {
            if (tags * I2PSessionTag.TagLength > reader.Remaining + 2)
                throw new ArgumentException("GarlicAESBlock: Not enough data for the tags supplied.");
            for (var i = 0; i < tags; ++i) Tags.Add(reader.ReadBlock(I2PSessionTag.TagLength));
        }

        PayloadSize = reader.ReadBlock(4);
        PayloadHash = reader.ReadBlock(32);
        Flag = reader.ReadBlock(1);
        if (Flag[0] != 0) NewSessionKey = new I2PSessionKey(reader.ReadBlock(32));
        var pllen = PayloadSize.ReadUInt32BigEndian(0);
        if (pllen > reader.Remaining) throw new ArgumentException("GarlicAESBlock: Not enough data payload supplied.");
        Payload = reader.ReadBlock((int)pllen);
        Padding = reader.ReadBlock(BufUtils.Get16BytePadding(reader.DistanceFrom(startPos)));

        DataBuf = new I2PByteBlock(reader.BaseArray, startPos, reader.DistanceFrom(startPos));
    }

    public GarlicAesBlock(
        I2PBufferCursor reader,
        IList<I2PSessionTag> tags,
        I2PSessionKey newsessionkey,
        I2PBufferCursor payload)
    {
        var startPos = reader.Position;

        // Allocate
        TagCount = reader.ReadBlock(2);
        if (tags != null)
            for (var i = 0; i < tags.Count; ++i)
                Tags.Add(reader.ReadBlock(I2PSessionTag.TagLength));
        PayloadSize = reader.ReadBlock(4);
        PayloadHash = reader.ReadBlock(32);
        Flag = reader.ReadBlock(1);
        if (newsessionkey != null) NewSessionKey = new I2PSessionKey(reader.ReadBlock(32));
        var pllen = Math.Min(reader.Remaining, payload.Remaining);
        Payload = reader.ReadBlock(pllen);
        Padding = reader.ReadBlock(BufUtils.Get16BytePadding(reader.DistanceFrom(startPos)));

        // Write
        TagCount.WriteUInt16BigEndian((ushort)(tags == null ? 0 : tags.Count), 0);
        if (tags != null)
            for (var i = 0; i < tags.Count; ++i)
                Tags[i].CopyFrom(tags[i].Value, 0);
        Flag[0] = (byte)(newsessionkey != null ? 0x01 : 0);
        if (newsessionkey != null) NewSessionKey.Key.CopyFrom(newsessionkey.Key, 0);
        Payload.CopyFrom(new I2PByteBlock(payload.BaseArray, payload.BaseArrayOffset, pllen), 0);
        payload.Seek(pllen);
        PayloadSize.WriteUInt32BigEndian((uint)pllen, 0);
        PayloadHash.CopyFrom(new ReadOnlySpan<byte>(I2PHashSha256.GetHash(Payload)), 0);
        Padding.Randomize();

        DataBuf = new I2PByteBlock(reader.BaseArray, startPos, reader.DistanceFrom(startPos));
    }

    public int Length => DataBuf.Length;

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteBlock(DataBuf);
    }

    public bool VerifyPayloadHash()
    {
        return PayloadHash == new I2PByteBlock(I2PHashSha256.GetHash(Payload));
    }
}