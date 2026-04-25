using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PMessagePayload : I2PType
{
    public uint MessageId;
    public byte[] Payload;
    public ushort SessionId;

    public byte[] GetBytes
    {
        get
        {
            using (var ms = new MemoryStream())
            {
                ms.Write(Payload, 0, Payload.Length);
                ms.Position = 0;

                using (var gs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    var result = new List<byte>();
                    var buf = new byte[32768];

                    int len;
                    while ((len = gs.Read(buf, 0, buf.Length)) > 0) result.AddRange(buf.Take(len));

                    return result.ToArray();
                }
            }
        }
    }

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteUInt16BigEndian(SessionId);
        dest.WriteUInt32BigEndian(MessageId);
        if (Payload != null) dest.WriteBytes(Payload);
    }

    public void Compress(byte[] data)
    {
        using (var ms = new MemoryStream())
        {
            using (var gs = new GZipStream(ms, CompressionMode.Compress))
            {
                gs.Write(data, 0, data.Length);
                gs.Flush();
            }

            Payload = ms.ToArray();
        }
    }
}