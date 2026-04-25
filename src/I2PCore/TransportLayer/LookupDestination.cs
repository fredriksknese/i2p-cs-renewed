using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TransportLayer;

internal class LookupDestination
{
    public TickCounter Created = TickCounter.Now;
    public I2PIdentHash Destination;
    public List<I2NpMessage> Messages = new();

    public LookupDestination(I2PIdentHash dest)
    {
        Destination = dest;
    }

    public void Add(I2NpMessage msg)
    {
        lock (Messages)
        {
            Messages.Add(msg);
        }
    }
}