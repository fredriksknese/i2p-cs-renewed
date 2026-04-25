using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

public class TunnelBuildMessage : I2NpMessage
{
    public List<AesEgBuildRequestRecord> Records = new();

    public TunnelBuildMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);
        for (var i = 0; i < 8; ++i)
        {
            var r = new AesEgBuildRequestRecord(reader);
            Records.Add(r);
        }

        SetBuffer(start, reader);
    }

    // Clones records
    public TunnelBuildMessage(IEnumerable<AesEgBuildRequestRecord> records)
    {
        var hops = (byte)records.Count();
        if (hops > 8) throw new ArgumentException("TunnelBuildMessage can only contain 8 records");

        AllocateBuffer(1 + 8 * AesEgBuildRequestRecord.Length);
        var writer = new I2PBufferCursor(Payload);
        foreach (var rec in records)
        {
            Records.Add(rec);
            writer.WriteBlock(rec.Data);
        }
    }

    private TunnelBuildMessage()
    {
        AllocateBuffer(1 + 8 * AesEgBuildRequestRecord.Length);
        var writer = new I2PBufferCursor(Payload);
        for (var i = 0; i < 8; ++i) Records.Add(new AesEgBuildRequestRecord(writer));
    }

    public override MessageTypes MessageType => MessageTypes.TunnelBuild;

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("TunnelBuild");
        for (var i = 0; i < Records.Count; ++i) result.Append(Records[i]);

        return result.ToString();
    }
}