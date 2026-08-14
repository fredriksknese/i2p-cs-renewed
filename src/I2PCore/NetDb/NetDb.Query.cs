using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.Utils;

namespace I2PCore;

public partial class NetDb
{
    public int RouterCount => RouterInfos.Count;
    public int FloodfillCount => FloodfillInfos.Count;

    /// <summary>
    ///     Pick a router at random, weighted by the supplied roulette.
    /// </summary>
    /// <param name="floodfillOnly">
    ///     Batch 3-9 (docs/PRODUCTION-PLAN.md). The roulette argument alone did not constrain the
    ///     answer: the <c>exploratory</c> branch ignored it and drew from every known router, and
    ///     both fallbacks did the same when the roulette came up empty. So every call asking for a
    ///     floodfill could return a router that is not one, and the callers had no way to tell —
    ///     <c>FloodfillUpdater</c> logged "Publishing LS to ECIES FF [x]" while publishing our
    ///     LeaseSet to peers that simply discard it, which is indistinguishable, from the outside,
    ///     from a router whose LeaseSets cannot be found. This flag keeps every path inside the
    ///     floodfill population, and an empty population returns null rather than a wrong answer.
    /// </param>
    private I2PIdentHash GetRandomRouter(
        RouletteSelection<I2PRouterInfo, I2PIdentHash> r,
        ICollection<I2PIdentHash> exclude,
        bool exploratory,
        bool floodfillOnly = false)
    {
        I2PIdentHash result;
        var me = RouterContext.Inst.MyRouterIdentity.IdentHash;
        var population = floodfillOnly ? FloodfillInfos : RouterInfos;

        var retries = 0;

        if (exploratory)
        {
            var subset = population.Values
                .Where(rp =>
                {
                    var ok = !rp.Meta.Deleted &&
                             (exclude is null || !exclude.Contains(rp.Router.Identity.IdentHash)) &&
                             rp.Router.Addresses.Any(a =>
                                 (a.Options.Contains("host") || a.Options.Contains("h")) &&
                                 (a.TransportStyle == "SSU2" ||
                                  (a.TransportStyle == "NTCP2" && a.Options.Contains("s"))) &&
                                 (RouterContext.UseIpV6 ||
                                  I2PRouterAddress.IpTestHostName(a.Options.TryGet("host")?.ToString() ??
                                                                  a.Options.TryGet("h")?.ToString()) !=
                                  AddressFamily.InterNetworkV6));
                    return ok;
                })
                // Filter for active/good routers to match Java's selectActiveNotFailingPeers
                // especially for exploratory tunnels when we are bootstrapping.
                // include untested routers for exploratory tunnels.
                .Where(rp =>
                {
                    var hash = rp.Router.Identity.IdentHash;
                    var st = Statistics[hash];

                    // 20-second cooldown: skip peers that recently failed a tunnel build
                    // (matches Java I2P's TunnelPeerSelector exclusion of recently-rejected peers)
                    if (st.LastTunnelBuildFailure != null &&
                        st.LastTunnelBuildFailure.DeltaToNow < TickSpan.Seconds(20))
                        return false;

                    // Skip peers marked as bad by RouterProfile (5+ consecutive failures or <10% success rate)
                    if (RouterProfileManager.Instance.GetProfile(hash).IsBad)
                        return false;

                    // Relax further filters during bootstrapping (connected count < 10)
                    // or if we have no exploratory tunnels yet.
                    var established = Router.ExplorationTunnelMgr?.InboundExploratory.EstablishedCount ?? 0;
                    // Batch 3-9: null before the transport layer starts. A NetDb query is
                    // reachable then -- and throwing here reads as "no routers", not as a crash.
                    if ((TransportProvider.Inst?.ConnectedRoutersCount ?? 0) < 10 || established < 2) return true;

                    // Use NodeInactive for exploratory to allow more routers
                    return !Statistics.NodeInactive(st);
                })
                .OrderByDescending(rp =>
                {
                    var established = Router.ExplorationTunnelMgr?.InboundExploratory.EstablishedCount ?? 0;
                    return established < 2 &&
                           (TransportProvider.Inst?.IsRouterConnected(rp.Router.Identity.IdentHash, out _) ?? false);
                })
                .ThenBy(rp => BufUtils.RandomInt(1000))
                .Take(100)
                .ToArray();

            if (subset.Length == 0)
                // Fallback to anything in the population if we have no good routers
                subset = population.Values
                    .Where(rp =>
                        !rp.Meta.Deleted &&
                        (exclude is null || !exclude.Contains(rp.Router.Identity.IdentHash)) &&
                        rp.Router.Addresses.Any(a =>
                            (a.Options.Contains("host") || a.Options.Contains("h")) &&
                            (a.TransportStyle == "SSU2" || (a.TransportStyle == "NTCP2" && a.Options.Contains("s")))))
                    .ToArray();

            if (subset.Length == 0) return null;

            do
            {
                result = subset
                    .Random()
                    .Router.Identity.IdentHash;
            } while (result == me && ++retries < 20);

            return result;
        }

        bool tryagain;
        do
        {
            // Batch 3-9: GetWeightedRandom dereferences the result of Random() on its wheel, so
            // an empty roulette throws rather than returning nothing. Skip straight to the
            // fallback below, which is now confined to the right population.
            result = r is null || r.Count == 0 ? null : r.GetWeightedRandom(exclude);
            tryagain = result == me;

            // 20-second cooldown + IsBad check for non-exploratory too
            if (!tryagain && result != null)
            {
                var st = Statistics[result];
                var coolingDown = st.LastTunnelBuildFailure != null &&
                                  st.LastTunnelBuildFailure.DeltaToNow < TickSpan.Seconds(20);
                var isBad = RouterProfileManager.Instance.GetProfile(result).IsBad;
                if (coolingDown || isBad)
                {
                    // Temporarily exclude and retry
                    exclude ??= new HashSet<I2PIdentHash>();
                    exclude.Add(result);
                    tryagain = true;
                }
            }
        } while (tryagain && ++retries < 20);

        if (result == null)
        {
            // Fallback for non-exploratory if roulette failed
            // Apply the same address reachability filter as exploratory and roulette construction
            var subset = population.Values
                .Where(rp =>
                    !rp.Meta.Deleted &&
                    (exclude is null || !exclude.Contains(rp.Router.Identity.IdentHash)) &&
                    rp.Router.Identity.IdentHash != me &&
                    rp.Router.Addresses.Any(a =>
                        (a.Options.Contains("host") || a.Options.Contains("h")) &&
                        (a.TransportStyle == "SSU2" ||
                         (a.TransportStyle == "NTCP2" && a.Options.Contains("s"))) &&
                        I2PRouterAddress.IsReachableAddress(a)))
                .ToArray();
            if (subset.Length > 0) result = subset.Random().Router.Identity.IdentHash;
        }

        if (result == null && floodfillOnly)
            // Warning, not Debug: with no floodfill we cannot publish a LeaseSet or look one up,
            // so every client of this router is about to be unreachable. Silence here is what
            // let "no more floodfills to try" read as a lookup problem for two sessions.
            Logging.LogWarning(
                $"GetRandomRouter: no floodfill available. Floodfills known: {FloodfillInfos.Count}, " +
                $"routers known: {RouterInfos.Count}, excluded: {exclude?.Count() ?? 0}");
        else if (result == null && !exploratory)
            Logging.LogDebug(
                $"GetRandomRouter: FAILED to find any non-exploratory router. Total known: {RouterInfos.Count}. Excluded: {exclude?.Count() ?? 0}");

        return result;
    }

    private I2PRouterInfo GetRandomRouterInfo(RouletteSelection<I2PRouterInfo, I2PIdentHash> r, bool exploratory)
    {
        return this[GetRandomRouter(r, null, exploratory)];
    }

    public I2PRouterInfo GetRandomRouterInfo(bool exploratory)
    {
        return GetRandomRouterInfo(Roulette, exploratory);
    }

    // Batch 6-1 (docs/PRODUCTION-PLAN.md) deleted a RouterSelectionHistory dictionary and its
    // PeriodicAction from here. They sat behind #if LOG_ROUTER_SELECTION_HISTORY && DEBUG, and
    // nothing in the repository read either one — whatever logged them was removed at some
    // point and left the fields behind. That is why there is no router-selection category in
    // TraceCategories: it would have been a switch that turns nothing on.

    public I2PIdentHash GetRandomRouterForTunnelBuild(bool exploratory, IEnumerable<I2PIdentHash> exclude = null)
    {
        return GetRandomRouter(Roulette, exclude is null ? null : exclude.ToHashSet(), exploratory);
    }

    public IEnumerable<I2PIdentHash> GetRandomRoutersForTunnelBuild(bool exploratory, int hops,
        IEnumerable<I2PIdentHash> initialExclude = null)
    {
        if (hops <= 0) throw new ArgumentException("Hops must be > 0");

        var exclude = initialExclude is null
            ? new HashSet<I2PIdentHash>()
            : initialExclude.ToHashSet();

        var excludeFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ex in exclude)
        {
            var fam = GetRouterFamily(ex);
            if (fam != null) excludeFamilies.Add(fam);
        }

        for (var i = 0; i < hops; ++i)
        {
            var retry = 0;
            I2PIdentHash ih = null;
            var acceptable = false;

            while (!acceptable && ++retry < 100)
            {
                ih = Inst.GetRandomRouterForTunnelBuild(exploratory, exclude);
                acceptable = ih != null && !exclude.Contains(ih);

                // Family-based exclusion: don't put two routers from the same family
                // in a single tunnel to reduce correlation attacks
                if (acceptable)
                {
                    var family = GetRouterFamily(ih);
                    if (family != null && excludeFamilies.Contains(family)) acceptable = false;
                }
            }

            if (acceptable)
            {
                exclude.Add(ih);

                // Track this router's family for exclusion
                var routerFamily = GetRouterFamily(ih);
                if (routerFamily != null) excludeFamilies.Add(routerFamily);

                yield return ih;
            }
            else
            {
                Logging.LogDebug(
                    $"GetRandomRoutersForTunnelBuild: Failed to find hop {i + 1}/{hops} after 100 retries.");
            }
        }
    }

    /// <summary>
    ///     Get the family name for a router, or null if the router has no family.
    ///     Uses TryGet to safely handle routers without a "family" option.
    /// </summary>
    private static string GetRouterFamily(I2PIdentHash ih)
    {
        var ri = Inst[ih];
        return ri?.Options?.TryGet("family")?.ToString();
    }

    public I2PRouterInfo GetRandomNonFloodfillRouterInfo(bool exploratory)
    {
        return GetRandomRouterInfo(RouletteNonFloodFill, exploratory);
    }

    public I2PRouterInfo GetRandomFloodfillRouterInfo(bool exploratory)
    {
        var hash = GetRandomFloodfillRouter(exploratory);
        return hash is null ? null : this[hash];
    }

    private readonly ItemFilterWindow<I2PIdentHash> RecentlyUsedForFf = new(TickSpan.Minutes(15), 2);

    public I2PIdentHash GetRandomFloodfillRouter(bool exploratory)
    {
        return GetRandomRouter(RouletteFloodFill, RecentlyUsedForFf.ToHashSet(), exploratory, true);
    }

    /// <summary>
    ///     Up to <paramref name="count" /> floodfills. Yields nothing when none are known — the
    ///     callers treat this as a list of floodfills, so a null in it would be published to.
    /// </summary>
    public IEnumerable<I2PIdentHash> GetRandomFloodfillRouter(bool exploratory, int count)
    {
        for (var i = 0; i < count; ++i)
        {
            var hash = GetRandomFloodfillRouter(exploratory);
            if (hash is null) yield break;

            yield return hash;
        }
    }

    public IEnumerable<I2PRouterInfo> GetRandomFloodfillRouterInfo(bool exploratory, int count)
    {
        for (var i = 0; i < count; ++i)
        {
            var ri = GetRandomFloodfillRouterInfo(exploratory);
            if (ri is null) yield break;

            yield return ri;
        }
    }

    public IEnumerable<I2PRouterInfo> GetRandomNonFloodfillRouterInfo(bool exploratory, int count)
    {
        for (var i = 0; i < count; ++i) yield return GetRandomNonFloodfillRouterInfo(exploratory);
    }

    public IEnumerable<I2PIdentHash> GetClosestFloodfill(
        I2PIdentHash dest,
        int count,
        ICollection<I2PIdentHash> exclude,
        bool useIpDiversity = false)
    {
        return GetClosestFloodfill(dest, DateTime.UtcNow, count, exclude, useIpDiversity);
    }

    public IEnumerable<I2PIdentHash> GetClosestFloodfill(
        I2PIdentHash dest,
        DateTime targetDate,
        int count,
        ICollection<I2PIdentHash> exclude,
        bool useIpDiversity = false)
    {
        var subset = FloodfillInfos.Where(inf =>
            (exclude == null || !exclude.Contains(inf.Key)) &&
            !Statistics.NodeInactive(Statistics[inf.Key]));

        if (!subset.Any())
            subset = exclude != null && exclude.Any()
                ? FloodfillInfos.Where(inf => !exclude.Contains(inf.Key))
                : FloodfillInfos;

        var refkey = dest.GetRoutingKey(targetDate);

        var sorted = subset
            .Select(ri => new
            {
                Id = ri.Key,
                Dist = ri.Key ^ refkey
            })
            .OrderBy(p => p.Dist);

        if (!useIpDiversity)
            return sorted
                .Take(count)
                .Select(p => p.Id)
                .ToArray();

        var result = new List<I2PIdentHash>();
        var usedSubnets = new HashSet<uint>();

        foreach (var p in sorted)
        {
            var subnet = GetIpSubnet(p.Id);
            if (subnet == 0 || usedSubnets.Add(subnet))
            {
                result.Add(p.Id);
                if (result.Count >= count) break;
            }
        }

        return result;
    }

    private static uint GetIpSubnet(I2PIdentHash ih)
    {
        var ri = Inst[ih];
        if (ri == null) return 0;
        foreach (var addr in ri.Addresses)
        {
            var ip = addr.Host;
            if (ip != null && ip.AddressFamily == AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                return (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8));
            }
        }

        return 0;
    }

    public IEnumerable<I2PRouterInfo> GetClosestFloodfillInfo(
        I2PIdentHash reference,
        int count,
        ICollection<I2PIdentHash> exclude)
    {
        return Find(GetClosestFloodfill(reference, count, exclude));
    }
}