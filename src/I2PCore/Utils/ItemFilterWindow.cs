using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace I2PCore.Utils;

public class ItemFilterWindow<T> : IEnumerable<T>
{
    private readonly TickCounter LastCleanup = TickCounter.Now;
    private readonly int Limit;
    private readonly Dictionary<T, LinkedList<TickCounter>> Memory = new();
    private readonly TickSpan MemorySpan;

    public ItemFilterWindow(TickSpan span, int limit)
    {
        MemorySpan = span;
        Limit = limit;
    }

    public IEnumerator<T> GetEnumerator()
    {
        lock (Memory)
        {
            return Memory
                .Where(k => k.Value.Count(t => t.DeltaToNow < MemorySpan) >= Limit)
                .Select(k => k.Key)
                .ToList()
                .GetEnumerator();
        }
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        lock (Memory)
        {
            return Memory
                .Where(k => k.Value.Count(t => t.DeltaToNow < MemorySpan) >= Limit)
                .Select(k => k.Key)
                .ToList()
                .GetEnumerator();
        }
    }

    /// <summary>
    ///     Returns True if the number of occurances (including a new one now) in the memory span is below the limit.
    /// </summary>
    public bool Update(T ident)
    {
        return Update(ident, Limit);
    }

    /// <summary>
    ///     As <see cref="Update(T)" />, with a limit decided by the caller — for filters whose
    ///     tolerance depends on current load rather than on a constant fixed at construction.
    ///
    ///     Batch 3-14: the count is taken over the memory span, as <see cref="Test" /> and
    ///     <see cref="Count" /> already did. It used to be <c>list.Count</c>, every entry ever
    ///     recorded for the key — and entries are only removed by <see cref="Cleanup" />, which
    ///     runs at most every 240 seconds and only when one of these methods is called. So a key
    ///     under sustained load never fell back below its limit: each rejected occurrence appended
    ///     another entry, and the ones a cleanup did remove were replaced faster than they aged
    ///     out. The window was decorative; the filter was permanent.
    /// </summary>
    public bool Update(T ident, int limit)
    {
        lock (Memory)
        {
            if (LastCleanup.DeltaToNowSeconds > 240) Cleanup();

            if (!Memory.TryGetValue(ident, out var list))
            {
                list = new LinkedList<TickCounter>();
                Memory[ident] = list;
            }

            list.AddLast(TickCounter.Now);
            return list.Count(t => t.DeltaToNow < MemorySpan) < limit;
        }
    }

    /// <summary>
    ///     Returns True if the number of occurances in the memory span is below limit without changing the set.
    /// </summary>
    public bool Test(T ident)
    {
        lock (Memory)
        {
            if (LastCleanup.DeltaToNowSeconds > 240) Cleanup();

            if (Memory.TryGetValue(ident, out var list)) return list.Count(t => t.DeltaToNow < MemorySpan) < Limit;

            return true;
        }
    }

    public int Count(T ident)
    {
        lock (Memory)
        {
            if (LastCleanup.DeltaToNowSeconds > 240) Cleanup();

            if (Memory.TryGetValue(ident, out var list)) return list.Count(t => t.DeltaToNow < MemorySpan);

            return 0;
        }
    }

    public void ProcessEvents(T key, Action<TickCounter> action)
    {
        lock (Memory)
        {
            if (Memory.TryGetValue(key, out var v))
            {
                var active = v
                    .Where(t => t.DeltaToNow < MemorySpan);

                foreach (var one in active) action(one);
            }
        }
    }

    // Lock Memory before calling
    private void Cleanup()
    {
        LastCleanup.SetNow();

        foreach (var identpair in Memory.ToArray())
        {
            while (identpair.Value.Any()
                   && identpair.Value.First.Value.DeltaToNow > MemorySpan)
                identpair.Value.RemoveFirst();

            if (!identpair.Value.Any()) Memory.Remove(identpair.Key);
        }
    }
}