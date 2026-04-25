using System.Text;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

public class TunnelBuildReplyMessage : I2NpMessage
{
    public BuildResponseRecord[] ResponseRecords;

    public TunnelBuildReplyMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);
        ResponseRecords = new BuildResponseRecord[8];

        for (var i = 0; i < 8; ++i) ResponseRecords[i] = new BuildResponseRecord(reader);
        SetBuffer(start, reader);
    }

    public override MessageTypes MessageType => MessageTypes.TunnelBuildReply;

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("TunnelBuildReply");

        if (ResponseRecords == null)
            result.AppendLine("Content: (null)");
        else
            for (var i = 0; i < 8; ++i)
            {
                result.AppendLine("ResponseRecords[" + i + "]");
                result.AppendLine(ResponseRecords[i].ToString());
            }

        return result.ToString();
    }
}