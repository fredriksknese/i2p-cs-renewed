using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore;

public class RoutersStatistics
{
    public delegate void Accessor(RouterStatistics ds);

    private const float Twoweeks = 1000 * 60 * 60 * 24 * 14;

    internal static float BandwidthMax = 1f;

    private readonly ConcurrentDictionary<I2PIdentHash, RouterStatistics> Routers = new();

    public RouterStatistics this[I2PIdentHash ix]
    {
        get
        {
            if (!Routers.TryGetValue(ix, out var stat))
            {
                stat = new RouterStatistics(ix);
                Routers[ix] = stat;
            }
            else
            {
                stat = Routers[ix];
            }

            return stat;
        }
    }

    // Batch 2-7 (docs/PRODUCTION-PLAN.md). This used to read NetDb.Inst.GetFullPath(...).
    // Load() runs on the NetDb worker thread, and NetDb.Stop() sets Inst = null, so a Stop
    // arriving while the worker was still loading dereferenced null on a thread with no
    // exception handler -- taking the whole process down. The store path is now passed in by
    // the NetDb that owns these statistics, so there is no singleton to race with.
    private static Store GetStore(string storePath)
    {
        return BufUtils.GetStore(storePath, -1);
    }

    public void Load(string storePath)
    {
        using (var s = GetStore(storePath))
        {
            var readsw = new Stopwatch();
            var constrsw = new Stopwatch();
            var dicsw = new Stopwatch();
            var sw2 = new Stopwatch();
            sw2.Start();
            var ix = 0;
            while ((ix = s.Next(ix)) > 0)
            {
                readsw.Start();
                var data = s.Read(ix);
                readsw.Stop();

                var reader = new I2PBufferCursor(data);
                switch ((StoreRecordId)reader.ReadUInt32LittleEndian())
                {
                    case StoreRecordId.RouterStatistics:
                        constrsw.Start();
                        var one = new RouterStatistics(reader);
                        constrsw.Stop();

                        dicsw.Start();
                        Routers[one.Id] = one;
                        dicsw.Stop();

                        one.StoreIx = ix;
                        break;

                    default:
                        s.Delete(ix);
                        break;
                }
            }

            sw2.Stop();
            Logging.Log($"Statistics load: [{Routers.Count}] Total: {sw2.Elapsed}, " +
                        $"Read(): {readsw.Elapsed}, Constr: {constrsw.Elapsed}, " +
                        $"Dict: {dicsw.Elapsed} ");

            // var times = Destinations.Select( d => d.Value.TunnelBuildTimeMsPerHop.ToString() );
            // System.IO.File.WriteAllLines( "/tmp/ct.txt", times );
        }
    }

    public void Save(string storePath)
    {
        var sw2 = new Stopwatch();
        sw2.Start();
        var deleted = 0;
        var updated = 0;
        var created = 0;
        using (var s = GetStore(storePath))
        {
            if (!Routers.Any()) return;

            foreach (var one in Routers.ToArray())
            {
                if (one.Value.Deleted && one.Value.StoreIx > 0)
                {
                    s.Delete(one.Value.StoreIx);
                    one.Value.StoreIx = -1;

                    Routers.TryRemove(one.Key, out _);
                    ++deleted;
                    continue;
                }

                var rec = new I2PByteBlock[]
                {
                    new(BitConverter.GetBytes((int)StoreRecordId.RouterStatistics)),
                    new(one.Value.ToByteArray())
                };

                if (one.Value.StoreIx > 0)
                {
                    if (one.Value.Updated)
                    {
                        s.Write(rec, one.Value.StoreIx);
                        ++updated;
                    }
                }
                else
                {
                    one.Value.StoreIx = s.Write(rec);
                    ++created;
                }

                one.Value.Updated = false;
            }
        }

        sw2.Stop();
        Logging.Log($"Statistics save: {sw2.Elapsed}, {created} created, " +
                    $"{updated} updated, {deleted} deleted.");
    }

    public void Update(I2PIdentHash target, Accessor acc, bool success)
    {
        var rec = this[target];
        rec.Updated = true;
        if (success) rec.LastSeen = I2PDate.Now;
        acc(rec);
    }

    public void SuccessfulConnect(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.SuccessfulConnects), true);
    }

    public void FailedToConnect(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.FailedConnects), false);
    }

    public void DestinationInformationFaulty(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.InformationFaulty), false);
    }

    public void SlowHandshakeConnect(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.SlowHandshakeConnect), false);
    }

    public void SuccessfulTunnelMember(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.SuccessfulTunnelMember), true);
    }

    public void MaxBandwidth(I2PIdentHash hash, Bandwidth bw)
    {
        Update(hash, ds => ds.MaxBandwidthSeen = Math.Max(ds.MaxBandwidthSeen, bw.BitrateMax), false);
    }

    public void DeclinedTunnelMember(I2PIdentHash hash)
    {
        Update(hash, ds =>
        {
            Interlocked.Increment(ref ds.DeclinedTunnelMember);
            ds.LastTunnelBuildFailure = TickCounter.Now;
        }, false);
    }

    public void SuccessfulTunnelTest(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.SuccessfulTunnelTest), true);
    }

    public void FailedTunnelTest(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.FailedTunnelTest), false);
    }

    public void TunnelBuildTimeout(I2PIdentHash hash)
    {
        Update(hash, ds =>
        {
            Interlocked.Increment(ref ds.TunnelBuildTimeout);
            ds.LastTunnelBuildFailure = TickCounter.Now;
        }, false);
    }

    public void TunnelBuildTimeMsPerHop(I2PIdentHash hash, long ms)
    {
        Update(hash,
            ds => ds.TunnelBuildTimeMsPerHop = ds.TunnelBuildTimeMsPerHop == 0
                ? ms
                : (long)((9.0 * ds.TunnelBuildTimeMsPerHop + ms) / 10.0), true);
    }

    public void FloodfillUpdateTimeout(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.FloodfillUpdateTimeout), false);
    }

    public void FloodfillUpdateSuccess(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.FloodfillUpdateSuccess), true);
    }

    public void IdentResolveRiTimeout(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.IdentResolveRiTimeout), false);
    }

    public void IdentResolveLsTimeout(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.IdentResolveLsTimeout), false);
    }

    public void IdentResolveSuccess(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.IdentResolveSuccess), true);
    }

    public void IdentResolveReply(I2PIdentHash hash)
    {
        Update(hash, ds => Interlocked.Increment(ref ds.IdentResolveReply), true);
    }

    public void IsFirewalledUpdate(I2PIdentHash hash, bool isfw)
    {
        Update(hash, ds => ds.IsFirewalled = isfw, true);
    }

    public void UpdateScore()
    {
        var rar = Routers.ToArray();

        if (!rar.Any()) return;

        BandwidthMax = rar.Max(r => r.Value.MaxBandwidthSeen);
        if (float.IsNaN(BandwidthMax) || BandwidthMax < 1f) BandwidthMax = 1f;

        foreach (var one in rar) one.Value.UpdateScore();
    }

    private bool OffsetCompare(double fail, double offset, double success, double multip)
    {
        return fail - offset > multip * success;
    }

    private bool TestInactive(Func<bool> test, string desc, bool record)
    {
        var result = test();
        if (record && result) AddInactiveReason(desc);
        return result;
    }

    public bool NodeInactive(RouterStatistics d)
    {
        // Batch 3-10. Three things this one line settles:
        //  - A local, not the shared field it replaced. NodeInactive runs on the NetDb worker and
        //    on whatever thread is asking GetClosestFloodfill; the old flag was only ever set
        //    inside #if DEBUG, so making the recording unconditional would have promoted a
        //    debug-only race into a production one.
        //  - Recorded at any log level. It is one dictionary increment, on the inactive path,
        //    once per statistic -- and gating it on Debug would leave the report below with
        //    nothing to say at the default level, which is the trap this batch exists to fix.
        //  - ContainsKey now, TryAdd once the verdict is in. A router is normally *active* the
        //    first time it is evaluated, so marking it here would mean its reason is never
        //    recorded when it later goes inactive -- the only case the report is for.
        var record = !InactiveReasonAlreadyReported.ContainsKey(d);

        // Checked first, and permanent: one faulty RouterInfo marks a peer inactive for the
        // lifetime of the statistic, so it deserves to appear in the reason breakdown like the
        // rest rather than short-circuiting past it.
        if (TestInactive(() => d.InformationFaulty > 0, "InformationFaulty", record))
        {
            if (record) InactiveReasonAlreadyReported.TryAdd(d, 0);
            return true;
        }

        var result = false;

        result |= TestInactive(
            () => OffsetCompare(d.FloodfillUpdateTimeout, 5, d.FloodfillUpdateSuccess, 2),
            "FloodfillUpdateTimeout", record);

        result |= TestInactive(
            () => OffsetCompare(d.FailedTunnelTest, 20, d.SuccessfulTunnelTest, 3),
            "FailedTunnelTest", record);

        result |= TestInactive(
            () => OffsetCompare(d.TunnelBuildTimeout, 200, d.SuccessfulTunnelMember, 5),
            "TunnelBuildTimeout", record);

        result |= TestInactive(
            () => OffsetCompare(d.IdentResolveRiTimeout, 200, d.IdentResolveSuccess + d.IdentResolveReply * 0.7, 5),
            "IdentResolveTimeout", record);

        result |= TestInactive(
            () => OffsetCompare(d.FailedConnects, 50, d.SuccessfulConnects, 1.5),
            "FailedConnects", record);

        result |= TestInactive(
            () => (DateTime.UtcNow - (DateTime)d.LastSeen).TotalDays > 2,
            "TooOld", record);

        if (result && record) InactiveReasonAlreadyReported.TryAdd(d, 0);

        return result;
    }

    internal HashSet<I2PIdentHash> GetInactive()
    {
        if (!Routers.Any()) return new HashSet<I2PIdentHash>();

        var result = new HashSet<I2PIdentHash>(
            Routers.Where(d => NodeInactive(d.Value))
                .Select(d => d.Key));

        // Batch 3-10 (docs/PRODUCTION-PLAN.md): was #if DEBUG, so a Release run could not say why
        // it had swept a peer. That is the defect batch 0-1 exists to prevent, in a second form:
        // the level is the filter, never the build configuration. The count goes out at Warning
        // because a sweep that empties the floodfill set takes every client offline with it.
        ReportInactiveReason.Do(() =>
        {
            var items = NodeInactiveReason
                .OrderByDescending(p => p.Value)
                .ToArray();

            if (!items.Any()) return;

            var sum = items.Sum(p => p.Value) / 100.0;

            var sta = items.Select(p => $" {p.Key}: {p.Value} ({p.Value / sum:F1}%)");
            // result and Routers, not a recomputation: calling NodeInactive here would record
            // reasons for the routers it walked, so the diagnostic would alter what it measures.
            Logging.LogWarning(
                $"RoutersStatistics: {result.Count} of {Routers.Count} routers inactive. " +
                $"Reasons:{string.Join(',', sta)}");
        });

        return result;
    }

    internal void RemoveOldStatistics(ICollection<I2PIdentHash> keep, string storePath)
    {
        var now = DateTime.UtcNow;

        var toremove = Routers
            .Where(one => (now - (DateTime)one.Value.LastSeen).TotalDays > 2
                          && !keep.Contains(one.Key))
            .ToArray();

        foreach (var one in toremove) one.Value.Deleted = true;

        Save(storePath);
    }

    public void Remove(I2PIdentHash hash)
    {
        if (Routers.TryGetValue(hash, out var router)) router.Deleted = true;
    }

    private enum StoreRecordId
    {
        RouterStatistics = 1
    }

    private readonly ConcurrentDictionary<string, int> NodeInactiveReason = new();
    private readonly PeriodicAction ReportInactiveReason = new(TickSpan.Minutes(7));
    // Concurrent: NodeInactive runs on the NetDb worker and on query threads at once, and a
    // HashSet mutated from two threads can corrupt rather than merely miscount. TryAdd is also
    // the "first time we have seen this statistic go inactive" test, so the flag it replaced is
    // gone rather than shared.
    private readonly ConcurrentDictionary<RouterStatistics, byte> InactiveReasonAlreadyReported = new();

    private void AddInactiveReason(string reason)
    {
        var nirc = NodeInactiveReason.GetOrAdd(reason, 0);
        NodeInactiveReason[reason] = nirc + 1;
    }
}