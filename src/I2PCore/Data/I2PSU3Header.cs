using System;
using System.Buffers;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2Psu3Header : I2PType
{
    public enum Su3ContentTypes : byte
    {
        SeedData = 0x03
    }

    public enum Su3FileTypes : byte
    {
        Zip = 0x00
    }

    public const string Su3MagicNumber = "I2Psu3";

    public I2Psu3Header(I2PBufferCursor src)
    {
        Read(src);
    }

    public byte FileVersion { get; private set; }
    public ushort SignatureType { get; private set; }
    public ushort SignatureLength { get; private set; }
    public byte VersionLength { get; private set; }
    public I2PByteBlock Version { get; private set; }
    public byte SignerIdLength { get; private set; }
    public ulong ContentLength { get; private set; }
    public Su3FileTypes FileType { get; private set; }
    public Su3ContentTypes ContentType { get; private set; }
    public string SignerId { get; private set; }

    public void Write(IBufferWriter<byte> dest)
    {
        // Magic number "I2Psu3" + zero byte
        dest.WriteBytes(Encoding.UTF8.GetBytes(Su3MagicNumber));
        dest.WriteByte(0);

        dest.WriteByte(FileVersion);
        dest.WriteUInt16BigEndian(SignatureType);
        dest.WriteUInt16BigEndian(SignatureLength);
        dest.WriteByte(0); // unused
        dest.WriteByte(VersionLength);
        dest.WriteByte(0); // unused
        dest.WriteByte(SignerIdLength);

        var contentLenBytes = new byte[8];
        for (var i = 7; i >= 0; i--) contentLenBytes[7 - i] = (byte)(ContentLength >> (i * 8));
        dest.WriteBytes(contentLenBytes);

        dest.WriteByte(0); // unused
        dest.WriteByte((byte)FileType);
        dest.WriteByte(0); // unused
        dest.WriteByte((byte)ContentType);

        // 12 reserved bytes
        dest.WriteBytes(new byte[12]);

        // Version
        dest.WriteBlock(Version);

        // Signer ID
        dest.WriteBytes(Encoding.UTF8.GetBytes(SignerId));
    }

    public void Read(I2PBufferCursor reader)
    {
        // magic number and zero byte 6
        var magic = reader.ReadBlock(6);
        _ = reader.ReadByte();
        var magicstr = magic.ToEncoding(Encoding.UTF8);

        if (magicstr != Su3MagicNumber) throw new ArgumentException("Not SU3 data.");

        // su3 file format version
        FileVersion = reader.ReadByte();

        SignatureType = reader.ReadUInt16BigEndian();
        SignatureLength = reader.ReadUInt16BigEndian();
        _ = reader.ReadByte();
        VersionLength = reader.ReadByte();
        _ = reader.ReadByte();
        SignerIdLength = reader.ReadByte();
        ContentLength = reader.ReadUInt64BigEndian();
        _ = reader.ReadByte();
        FileType = (Su3FileTypes)reader.ReadByte();
        _ = reader.ReadByte();
        ContentType = (Su3ContentTypes)reader.ReadByte();
        reader.Seek(12);
        Version = reader.ReadBlock(VersionLength);
        SignerId = reader.ReadBlock(SignerIdLength)
            .ToEncoding(Encoding.UTF8);
    }
}