using System.Buffers;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer;

public class TunnelDataFragmentReassembly
{
    public static readonly TickSpan RememberUnmatchedFragmentsFor = TickSpan.Minutes(10);

    private readonly ConcurrentDictionary<uint, TunnelDataFragmentList> MessageFragments = new();

    private readonly PeriodicAction RemoveUnmatchedFragments = new(RememberUnmatchedFragmentsFor);

    public int BufferedFragmentCount
    {
        get
        {
            lock (MessageFragments)
            {
                return MessageFragments.Sum(mid => mid.Value.Count(fr => fr != null));
            }
        }
    }

    public IEnumerable<TunnelMessage> Process(IEnumerable<TunnelDataMessage> tdmsgs, out bool failure)
    {
        var result = new List<TunnelMessage>();
        failure = false;

        RemoveUnmatchedFragments.Do(() =>
        {
            lock (MessageFragments)
            {
                var remove = MessageFragments.Where(p => p.Value.Created.DeltaToNow > RememberUnmatchedFragmentsFor)
                    .Select(p => p.Key).ToArray();
                foreach (var key in remove)
                {
                    Logging.LogDebug($"TunnelDataFragmentReassembly: Removing old unmatched fragment for {key}");
                    MessageFragments.TryRemove(key, out _);
                }
            }
        });

        foreach (var msg in tdmsgs)
        {
            var hash = I2PHashSha256.GetHash(msg.TunnelDataPayload, msg.Iv);
            var eq = BufUtils.Equal(msg.Checksum.PeekBytes(0, 4), 0, hash, 0, 4);
            if (!eq)
            {
                Logging.LogDebug("TunnelDataFragmentReassembly: SHA256 check failed in TunnelData.");
                failure = true;
                continue;
            }

            var reader = new I2PBufferCursor(msg.TunnelDataPayload);

            while (reader.Remaining > 0)
            {
                var frag = new TunnelDataFragment(reader);

                if (frag.FollowOnFragment)
                {
                    var fragments = MessageFragments.GetOrAdd(frag.MessageId,
                        id => new TunnelDataFragmentList());

                    fragments[frag.FragmentNumber] = frag;

                    CheckForAllFragmentsFound(result, frag.MessageId, fragments);
                }
                else
                {
                    if (frag.Fragmented)
                    {
                        var fragments = MessageFragments.GetOrAdd(frag.MessageId,
                            id => new TunnelDataFragmentList());

                        fragments[0] = frag;

                        CheckForAllFragmentsFound(result, frag.MessageId, fragments);
                    }
                    else
                    {
                        AddTunnelMessage(result, frag, frag.Payload);
                    }
                }
            }
        }

        return result;
    }

    private void CheckForAllFragmentsFound(List<TunnelMessage> result, uint msgid, TunnelDataFragmentList fragments)
    {
        var lastfound = fragments.Count > 1 && fragments[fragments.Count - 1].LastFragment;
        if (lastfound && !fragments.Any(f => f == null))
        {
            var s = new ArrayBufferWriter<byte>();
            for (var i = 0; i < fragments.Count; ++i)
            {
                var pl = fragments[i].Payload;
                s.WriteBytes(pl.ReadBytes(pl.Remaining));
            }

            AddTunnelMessage(result, fragments[0], new I2PBufferCursor(s.WrittenSpan.ToArray()));
            MessageFragments.TryRemove(msgid, out _);
        }
    }

    private static void AddTunnelMessage(List<TunnelMessage> result, TunnelDataFragment initialfragment,
        I2PBufferCursor buf)
    {
        switch (initialfragment.Delivery)
        {
            case TunnelMessage.DeliveryTypes.Local:
                result.Add(
                    new TunnelMessageLocal(
                        I2NpMessage.ReadHeader16(buf).Message));
                break;

            case TunnelMessage.DeliveryTypes.Router:
                result.Add(new TunnelMessageRouter(
                    I2NpMessage.ReadHeader16(buf).Message,
                    new I2PIdentHash(new I2PBufferCursor(initialfragment.ToHash))));
                break;

            case TunnelMessage.DeliveryTypes.Tunnel:
                result.Add(
                    new TunnelMessageTunnel(
                        I2NpMessage.ReadHeader16(buf).Message,
                        new I2PIdentHash(new I2PBufferCursor(initialfragment.ToHash)),
                        initialfragment.Tunnel));
                break;
        }
    }

    private class TunnelDataFragmentList : IEnumerable<TunnelDataFragment>
    {
        public readonly TickCounter Created = new();
        private readonly List<TunnelDataFragment> List;

        public TunnelDataFragmentList()
        {
            List = new List<TunnelDataFragment>();
        }

        public TunnelDataFragmentList(List<TunnelDataFragment> list)
        {
            List = list;
        }

        public int Count => List.Count;

        public TunnelDataFragment this[int ix]
        {
            get => List[ix];
            set
            {
                if (Count <= ix) List.AddRange(new TunnelDataFragment[ix - Count + 1]);

                List[ix] = value;
            }
        }

        public IEnumerator<TunnelDataFragment> GetEnumerator()
        {
            return List.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return List.GetEnumerator();
        }
    }
}