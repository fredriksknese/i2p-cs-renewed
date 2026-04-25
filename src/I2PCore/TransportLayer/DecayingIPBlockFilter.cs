using System.Collections.Generic;
using System.Net;
using I2PCore.Utils;

namespace I2PCore.TransportLayer;

internal class DecayingIpBlockFilter
{
    private const int NumberOfFailuresToBlock = 50;
    private static readonly TickSpan BlockTime = TickSpan.Minutes(30);
    private static readonly TickSpan IpFaultHistoryWindow = TickSpan.Minutes(20);
    private readonly Dictionary<IPAddress, TickCounter> BlockedIPs = new();

    private readonly PeriodicAction Decay = new(IpFaultHistoryWindow * 60 / NumberOfFailuresToBlock);

    private readonly Dictionary<IPAddress, LinkedList<TickCounter>> MonitorIpWindow = new();

    internal int Count => BlockedIPs.Count;

    internal void ReportProblem(IPAddress addr)
    {
        LinkedList<TickCounter> list;

        lock (MonitorIpWindow)
        {
            if (MonitorIpWindow.TryGetValue(addr, out list))
            {
                list.AddFirst(TickCounter.Now);
            }
            else
            {
                list = new LinkedList<TickCounter>();
                list.AddFirst(TickCounter.Now);
                MonitorIpWindow[addr] = list;
            }
        }

        if (list.Count == NumberOfFailuresToBlock)
        {
            Logging.LogTransport($"DecayingIPBlockFilter: Blocking {addr}");

            lock (BlockedIPs)
            {
                BlockedIPs[addr] = TickCounter.Now;
            }
        }
    }

    internal bool IsFiltered(IPAddress addr)
    {
        Decay.Do(() =>
        {
            var toremove = new List<IPAddress>();

            lock (MonitorIpWindow)
            {
                foreach (var one in MonitorIpWindow)
                {
                    var startcount = one.Value.Count;

                    while (one.Value.Count > 0
                           && one.Value.Last.Value.DeltaToNow > IpFaultHistoryWindow)
                        one.Value.RemoveLast();

                    if (startcount >= NumberOfFailuresToBlock && one.Value.Count < NumberOfFailuresToBlock)
                    {
                        Logging.LogTransport($"DecayingIPBlockFilter: Window under blocking level {one.Key}");
                        toremove.Add(one.Key);
                    }
                    else if (one.Value.Count == 0)
                    {
                        toremove.Add(one.Key);
                    }
                }

                foreach (var remove in toremove) MonitorIpWindow.Remove(remove);
            }
        });

        lock (BlockedIPs)
        {
            if (BlockedIPs.TryGetValue(addr, out var blocktime))
            {
                if (blocktime.DeltaToNow > BlockTime)
                {
                    Logging.LogTransport($"DecayingIPBlockFilter: Unblocking {addr}");
                    BlockedIPs.Remove(addr);
                    return false;
                }

                return true;
            }

            return false;
        }
    }
}