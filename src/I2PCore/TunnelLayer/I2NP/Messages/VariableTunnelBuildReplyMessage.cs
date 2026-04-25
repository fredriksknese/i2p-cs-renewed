using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

public class VariableTunnelBuildReplyMessage : I2NpMessage
{
    public List<BuildResponseRecord> ResponseRecords;

    public VariableTunnelBuildReplyMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);
        ResponseRecords = new List<BuildResponseRecord>();

        var count = reader.ReadByte();
        for (var i = 0; i < count; ++i) ResponseRecords.Add(new BuildResponseRecord(reader));
        SetBuffer(start, reader);
    }

    public VariableTunnelBuildReplyMessage(IEnumerable<BuildResponseRecord> recs, uint msgid)
    {
        AllocateBuffer(1 + recs.Count() * EgBuildRequestRecord.Length);
        ResponseRecords = new List<BuildResponseRecord>(recs);

        MessageId = msgid;

        // TODO: Remove mem copy
        var writer = new I2PBufferCursor(Payload);
        writer.WriteByte((byte)recs.Count());
        foreach (var rec in ResponseRecords) writer.WriteBlock(rec.Payload);
    }

    public override MessageTypes MessageType => MessageTypes.VariableTunnelBuildReply;

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("VariableTunnelBuildReply");
        if (ResponseRecords != null)
            foreach (var one in ResponseRecords)
                result.AppendLine(one.ToString());

        return result.ToString();
    }
}