using System.Linq;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-15 (docs/PRODUCTION-PLAN.md). The per-hop budget must scale with how many next hops
///     exist, because Java's floor of four assumes a router that has many.
///
///     <para>
///         3-14 left the throttle working as a rate limit rather than a latch, and the CI run for
///         it showed what remained: in a fixture where the C# router has exactly one possible next
///         hop, the budget was spent 21 seconds after start and 1702 of 1722 build requests were
///         refused, every one naming the same peer. i2pd ended with 7 outbound and **0 inbound**
///         tunnels — no inbound tunnel means no lease, which is why all seventeen integration
///         failures read `LeaseSet not found`.
///     </para>
///     <para>
///         The two reference implementations bracket the rule. i2pd has no per-hop cap at all and
///         refuses only on congestion; Java caps per hop on a curve and never consults its peer
///         count. The cap's job is diversity — the absolute bound is `MaxTransitTunnels`, which is
///         a separate check with its own refusal reason — so a hop gets its share of that capacity,
///         floored by Java's curve, and the rule becomes each of the two at the ends.
///     </para>
/// </summary>
[TestFixture]
public class NextHopBudgetScaleTest
{
    private const int DefaultCapacity = 10000; // RouterContext.Limits.cs: MaxTransitTunnels

    // Java I2P ParticipatingThrottler with LIFETIME_PORTION = 3 applied.
    private const int JavaFloor = 4;

    /// <summary>
    ///     What one peer can legitimately want from us when we are all it has: i2pd's default pool
    ///     is 5 inbound and 5 outbound tunnels of up to 3 hops, rebuilt every tunnel lifetime, and
    ///     the budget counts one window of that.
    /// </summary>
    private static readonly int OnePeersPoolPerWindow =
        2 * 5 * 3 * TickSpan.Seconds( 11 * 60 / 3 ).ToMilliseconds
        / Tunnel.TunnelLifetime.ToMilliseconds;

    /// <summary>
    ///     The defect, stated as the fixture states it. Reinstating Java's curve alone fails here.
    /// </summary>
    [Test]
    public void WithOneOtherRouterKnownTheBudgetSustainsThatPeersPool()
    {
        var limit = TransitTunnelProvider.NextHopRequestLimit( 0, 2, DefaultCapacity );

        Assert.GreaterOrEqual( limit, OnePeersPoolPerWindow,
            "a router whose only next hop is one peer must be able to carry that peer's whole "
            + "pool; at Java's floor of four it carried 20 tunnels while refusing 1702 requests" );
    }

    /// <summary>
    ///     And the half that must not move: with a live network's worth of routers known, the share
    ///     of capacity falls under Java's floor and the rule is Java's, unchanged. That is the case
    ///     the anti-amplification argument is actually about.
    /// </summary>
    [Test]
    public void OnALiveSizedNetworkTheRuleIsJavasUnchanged()
    {
        foreach ( var carried in new[] { 0, 100, 1000, 100000 } )
            Assert.AreEqual(
                TransitTunnelProvider.JavaNextHopLimit( carried ),
                TransitTunnelProvider.NextHopRequestLimit( carried, 3000, DefaultCapacity ),
                $"with 3000 routers known and {carried} tunnels carried, no peer's share of our "
                + "capacity reaches Java's curve, so the curve is the whole rule" );
    }

    [Test]
    public void TheBudgetNarrowsAsTheNetworkGrows()
    {
        var counts = new[] { 1, 2, 10, 100, 500, 1000, 5000 };

        var limits = counts
            .Select( n => TransitTunnelProvider.NextHopRequestLimit( 0, n, DefaultCapacity ) )
            .ToArray();

        foreach ( var i in Enumerable.Range( 1, limits.Length - 1 ) )
            Assert.LessOrEqual( limits[i], limits[i - 1],
                $"knowing more routers cannot raise one hop's share: {counts[i - 1]} routers gave "
                + $"{limits[i - 1]}, {counts[i]} gave {limits[i]}" );

        Assert.Greater( limits.First(), limits.Last(),
            "the two ends must actually differ, or the rule has not scaled with anything" );
        Assert.AreEqual( JavaFloor, limits.Last(),
            "and the large end is Java's floor" );
    }

    /// <summary>
    ///     The budget is a rate; capacity is a level. Converting one to the other is where a rule
    ///     like this goes wrong, so pin it: a hop spending its whole budget every window forever
    ///     sustains no more live tunnels than its share of capacity.
    /// </summary>
    [Test]
    public void ABudgetSpentEveryWindowSustainsNoMoreThanTheShareItCameFrom()
    {
        var windowsperlife = Tunnel.TunnelLifetime.ToMilliseconds
                             / TickSpan.Seconds( 11 * 60 / 3 ).ToMilliseconds;

        foreach ( var hops in new[] { 1, 2, 7, 50 } )
        {
            var perwindow = TransitTunnelProvider.CapacityShareOfOneNextHop( hops, DefaultCapacity );
            var alive = perwindow * windowsperlife;

            Assert.LessOrEqual( alive, DefaultCapacity / hops + windowsperlife,
                $"{hops} next hops: a budget of {perwindow} per window sustains {alive} live "
                + $"tunnels, above the share of capacity it was derived from" );
        }
    }

    [Test]
    public void NoHopIsEverAuthorisedBeyondTheCapacityWeConfigured()
    {
        foreach ( var capacity in new[] { 0, 1, 10, 500, DefaultCapacity } )
        {
            var alive = TransitTunnelProvider.CapacityShareOfOneNextHop( 1, capacity )
                        * ( Tunnel.TunnelLifetime.ToMilliseconds
                            / TickSpan.Seconds( 11 * 60 / 3 ).ToMilliseconds );

            Assert.LessOrEqual( alive, capacity + 2,
                "one hop's share of a capacity cannot exceed that capacity, whatever it is set to" );
        }
    }

    /// <summary>
    ///     A router that knows nothing yet still has to answer. Division by the peer count is the
    ///     obvious way for this rule to throw on the first request after a cold start.
    /// </summary>
    [Test]
    public void AnEmptyNetDbIsNotADivisionByZero()
    {
        var limit = TransitTunnelProvider.NextHopRequestLimit( 0, 0, DefaultCapacity );

        Assert.GreaterOrEqual( limit, JavaFloor,
            "knowing no routers must read as knowing one, not as an error or a budget of nothing" );
    }

    [Test]
    public void ADisabledCapacityStillLeavesJavasFloor()
    {
        Assert.AreEqual( JavaFloor, TransitTunnelProvider.NextHopRequestLimit( 0, 1, 0 ),
            "a capacity of zero is refused by the capacity check, which is a different reason "
            + "with a different name — it must not come out of this rule as a budget" );
    }

    /// <summary>
    ///     The visibility half, and the reason it is in this batch: the 3-14 evidence could only be
    ///     read because that run happened to carry debug lines. The budget belongs in the report
    ///     the router makes at its default level.
    /// </summary>
    [Test]
    public void TheReportStatesTheBudgetAndWhatItWasComputedFrom()
    {
        var report = TransitTunnelProvider.FormatNextHopBudget( 11, 3 );

        StringAssert.Contains( "11", report, "the budget in force" );
        StringAssert.Contains( "3 routers known", report, "and what it was computed from" );
        StringAssert.Contains( "3m 40s", report, "over the window it applies to" );
    }
}
