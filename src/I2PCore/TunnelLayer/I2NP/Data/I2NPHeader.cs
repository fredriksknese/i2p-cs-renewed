using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public interface Ii2NpHeader
    {
        I2NpMessage.MessageTypes MessageType { get; set; }
        I2PDate Expiration { get; set; }
        BufLen HeaderAndPayload { get; }
        int Length { get; }

        I2NpMessage Message { get; }

        string ToString();
    }
}
