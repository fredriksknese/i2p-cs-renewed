using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-14 (docs/PRODUCTION-PLAN.md). A router with one usable next hop must still carry
///     tunnels, and must say what it decided.
///
///     <para>
///         With the build reply readable at last (3-13), the CI run showed i2pd building 2 tunnels
///         out of 529 attempts, and our own log gave the reason: **528 of 531 decisions were
///         `Reject due same next destination`**. Two things caused that. The limit was a constant
///         2 per 5 minutes for every next hop, where Java I2P's `ParticipatingThrottler` scales its
///         limit with the tunnels already carried and floors it at 4 per window — and i2pd has no
///         such throttle at all, refusing only on congestion. And `ItemFilterWindow.Update` counted
///         every entry ever recorded, not the ones inside the window, so a key under sustained load
///         never recovered: each refusal appended another entry, and `Cleanup` runs at most every
///         240 seconds.
///     </para>
///     <para>
///         The throttle is kept, not deleted: a router that relays unlimited tunnels toward one
///         peer is an amplifier pointed at that peer.
///     </para>
/// </summary>
[TestFixture]
public class NextHopThrottleTest
{
    // Java I2P ParticipatingThrottler, with LIFETIME_PORTION = 3 applied:
    // MIN_LIMIT = 12/3, MAX_LIMIT = 66/3.
    private const int JavaFloor = 4;
    private const int JavaCeiling = 22;

    /// <summary>
    ///     The defect that made every refusal permanent. Entries outside the span must not count,
    ///     whether or not a cleanup has happened to have run.
    /// </summary>
    [Test]
    public void OccurrencesOutsideTheWindowStopCounting()
    {
        var span = TickSpan.Milliseconds( 300 );
        var filter = new ItemFilterWindow<string>( span, 2 );

        Assert.IsTrue( filter.Update( "peer" ), "first occurrence is inside any limit above one" );
        Assert.IsFalse( filter.Update( "peer" ), "second occurrence reaches the limit of two" );

        Thread.Sleep( 500 );

        Assert.IsTrue( filter.Update( "peer" ),
            "once the window has passed the earlier occurrences must no longer count — "
            + "Cleanup runs at most every 240 s, so the count itself has to respect the span" );
    }

    /// <summary>
    ///     The count is per key: throttling one peer must not throttle another.
    /// </summary>
    [Test]
    public void EachNextHopIsCountedSeparately()
    {
        var filter = new ItemFilterWindow<string>( TickSpan.Minutes( 5 ), 2 );

        filter.Update( "busy" );
        Assert.IsFalse( filter.Update( "busy" ) );

        Assert.IsTrue( filter.Update( "quiet" ), "a second peer starts from its own empty count" );
    }

    [Test]
    public void AnIdleRouterStillAnswersMoreThanOneRequestPerNextHop()
    {
        var limit = TransitTunnelProvider.JavaNextHopLimit( 0 );

        Assert.AreEqual( JavaFloor, limit,
            "a router carrying nothing uses Java's floor, not a constant of two" );
        Assert.GreaterOrEqual( limit, 3,
            "one accepted tunnel per window cannot sustain a peer's pool — that is the 3-13 run" );
    }

    /// <summary>
    ///     The correction the first CI run for this batch forced. Java spends budget on requests it
    ///     refuses; with one possible next hop and a peer retrying a failed build ~35 times a
    ///     minute, that spent a budget of four on refusals and never recovered — 9 of 1166 answered,
    ///     99.2% refused by this filter. The budget counts tunnels accepted toward the hop.
    /// </summary>
    [Test]
    public void RefusedRequestsDoNotSpendTheBudget()
    {
        var limit = TransitTunnelProvider.JavaNextHopLimit( 0 );
        var filter = new ItemFilterWindow<string>( TickSpan.Seconds( 11 * 60 / 3 ), limit );
        const string theonlynexthopthereis = "the only next hop there is";

        var accepted = 0;

        // A retry storm: far more requests than the budget, arriving before anything expires.
        foreach ( var _ in Enumerable.Range( 0, 200 ) )
            if ( TransitTunnelProvider.NextHopBudgetAllows( filter.Count( theonlynexthopthereis ), limit ) )
            {
                filter.Update( theonlynexthopthereis );
                accepted++;
            }

        Assert.AreEqual( limit, accepted,
            "the whole budget is spent on tunnels we agreed to carry, and none of it on refusals" );
    }

    [Test]
    public void CheckingTheBudgetDoesNotSpendIt()
    {
        var filter = new ItemFilterWindow<string>( TickSpan.Minutes( 5 ), 2 );

        Enumerable.Range( 0, 50 ).ToList().ForEach( _ => filter.Count( "peer" ) );

        Assert.AreEqual( 0, filter.Count( "peer" ),
            "asking how much a peer has used must not itself use any" );
    }

    [Test]
    public void TheLimitRisesWithLoadAndStopsAtJavasCeiling()
    {
        Assert.AreEqual( JavaFloor, TransitTunnelProvider.JavaNextHopLimit( 100 ),
            "1% of a hundred tunnels is below the floor, so the floor applies" );
        Assert.AreEqual( 10, TransitTunnelProvider.JavaNextHopLimit( 1000 ),
            "1% of the tunnels carried, per Java's PERCENT_LIMIT" );
        Assert.AreEqual( JavaCeiling, TransitTunnelProvider.JavaNextHopLimit( 100000 ),
            "no peer gets more than Java's ceiling however busy we are" );
    }

    /// <summary>
    ///     The visibility half. A router that refuses everything it is offered has to say so at the
    ///     default log level; before this batch the reasons existed only as `LogDebug`.
    /// </summary>
    [Test]
    public void TheReportNamesTheReasonThatRefusedTheTunnels()
    {
        var report = TransitTunnelProvider.FormatBuildDecisions( new Dictionary<string, long>
        {
            ["Accept"] = 3,
            ["RejectNextHopThrottle"] = 528
        } );

        Assert.IsNotNull( report );
        StringAssert.Contains( "531 answered", report );
        StringAssert.Contains( "3 accepted", report );
        StringAssert.Contains( "RejectNextHopThrottle: 528", report );
        StringAssert.Contains( "99.4%", report, "the dominant reason has to carry its share" );
    }

    /// <summary>
    ///     The policy tests above cannot see the defect that actually shipped: it was not in the
    ///     rule but in *where* the budget was spent. So this one reads the source, as batches 3-11
    ///     and 3-12 did for the same reason — the mistake is a call in the wrong place, and no
    ///     amount of driving the pure functions will find it.
    /// </summary>
    [Test]
    public void TheBudgetIsSpentOnlyWhereWeAccept()
    {
        var source = File.ReadAllLines( ProviderSourcePath() );

        var spends = source
            .Select( ( line, index ) => ( line, index ) )
            .Where( l => l.line.Contains( "NextHopFilter.Update(" ) )
            .ToArray();

        Assert.AreEqual( 1, spends.Length,
            "the hop's budget must be spent in exactly one place; a second call is how the first "
            + "cut of this batch spent it on requests it went on to refuse" );

        var context = string.Join( " ",
            source.Skip( System.Math.Max( 0, spends[0].index - 2 ) ).Take( 5 ) );

        StringAssert.Contains( "DecisionAccept", context,
            "the one call must be guarded by having decided to accept" );
    }

    private static string ProviderSourcePath()
    {
        var dir = TestContext.CurrentContext.TestDirectory;

        while ( dir != null && !Directory.Exists( Path.Combine( dir, "src", "I2PCore" ) ) )
            dir = Directory.GetParent( dir )?.FullName;

        Assert.IsNotNull( dir, "could not locate the repository root from the test directory" );

        return Path.Combine( dir!, "src", "I2PCore", "TunnelLayer", "TransitTunnelProvider.cs" );
    }

    [Test]
    public void NothingAskedOfUsIsNotAReport()
    {
        Assert.IsNull( TransitTunnelProvider.FormatBuildDecisions( new Dictionary<string, long>() ),
            "a router nobody has asked has nothing to report, and must not print a 0 of 0 line" );
    }
}
