using System;
using System.IO;
using System.Linq;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-0c (docs/PRODUCTION-PLAN.md). Guards the two defects that made 11 integration
///     tests fail with a bare <c>NullReferenceException</c> and left the process pointed at the
///     live network.
///
///     <para>
///         <b>Why these are unit tests over a fixture problem.</b> The bug only shows up in a
///         full integration run — one namespace's <c>OneTimeTearDown</c> disposing the router
///         that another namespace's <c>OneTimeSetUp</c> then reuses — which takes 23 minutes and
///         an i2pd binary to observe. The invariants underneath it ("a disposed harness is not a
///         running router", "nothing restores netid 2") are cheap and belong in the gating suite,
///         so a future edit gets told immediately instead of at the next integration run.
///     </para>
/// </summary>
[TestFixture]
public class IntegrationFixtureLifecycleTest
{
    /// <summary>
    ///     The distinction the whole batch turns on: the harness object exists, the router does
    ///     not.
    /// </summary>
    [Test]
    public void AHarnessThatWasNeverStartedIsNotRunning()
    {
        using var harness = new CSharpRouterHarness();

        ClassicAssert.IsFalse( harness.IsRunning,
            "a constructed-but-unstarted harness has no router behind it; anything that "
            + "branches on it must see false" );
    }

    /// <summary>
    ///     <see cref="AHarnessThatWasNeverStartedIsNotRunning" /> on its own is a weak guard: it
    ///     still passes if <c>IsRunning</c> is reduced to the private <c>_started</c> flag, which
    ///     is exactly the defect — a bool the harness sets for itself cannot know that another
    ///     fixture stopped the router out from under it. The case that would catch that
    ///     (started, then stopped elsewhere) needs a real router and 20 minutes, so assert the
    ///     structural property here instead: the answer must come from the singletons.
    /// </summary>
    [Test]
    public void IsRunningIsAnsweredByTheRouterSingletonsAndNotByALocalFlag()
    {
        var source = ReadInfrastructureSource( "CSharpRouterHarness.cs" );

        var declaration = source
            .Split( "public bool IsRunning" )
            .ElementAtOrDefault( 1 )
            ?.Split( ';' )
            .FirstOrDefault();

        ClassicAssert.IsNotNull( declaration, "could not find the IsRunning declaration" );

        foreach ( var required in new[] { "NetDb.Inst", "TransportProvider.Inst" } )
            StringAssert.Contains( required, declaration,
                $"IsRunning must consult {required}. A harness-local flag stays true after a "
                + "different fixture calls Router.Stop(), which is the bug this batch fixes." );
    }

    /// <summary>
    ///     Rule 5 of the plan, and CLAUDE.md: never netid 2 before Gate 6. <c>Stop()</c> used to
    ///     set it back to <c>0x02</c> and re-enable reseed as "restoring defaults". Confirmed to
    ///     fail with either line reinstated.
    /// </summary>
    [Test]
    public void TheHarnessNeverRestoresTheLiveNetworkIdOrReseed()
    {
        var source = ReadInfrastructureSource( "CSharpRouterHarness.cs" );

        foreach ( var banned in new[]
                 {
                     "I2PNetworkId = 0x02",
                     "I2PNetworkId = 2",
                     "Bootstrap.Disabled = false",
                 } )
            ClassicAssert.IsFalse( CodeContains( source, banned ),
                $"CSharpRouterHarness assigns `{banned}`. Netid 2 is the live I2P network and "
                + "that Bootstrap line switches reseed back on; these are process-wide statics "
                + "that outlive the fixture that set them. See docs/PRODUCTION-PLAN.md rule 5." );
    }

    /// <summary>
    ///     The ordering bug itself. A fixture that decides whether it can reuse a shared router
    ///     by testing the reference for null will reuse a disposed one, because teardown drops
    ///     the router without dropping the reference.
    /// </summary>
    [Test]
    public void NoFixtureDecidesToReuseARouterByTestingItsReferenceForNull()
    {
        var offenders = InfrastructureSources()
            .Where( f => CodeContains( File.ReadAllText( f ), "CSharpRouter != null" ) )
            .Select( Path.GetFileName )
            .ToArray();

        CollectionAssert.IsEmpty( offenders,
            "these files gate on a harness reference being non-null, which stays true after the "
            + "harness is disposed. Use CSharpRouterHarness.IsRunning instead." );
    }

    /// <summary>
    ///     Batch 3-6's lesson: an audit that scans nothing passes. Without this, moving or
    ///     renaming the Infrastructure directory turns both scans above green while checking no
    ///     code at all.
    /// </summary>
    [Test]
    public void TheScanActuallyReadsTheFixtureSources()
    {
        var files = InfrastructureSources();

        ClassicAssert.Greater( files.Length, 5,
            "the fixture-source scan found almost nothing — it is probably looking in the "
            + "wrong place, which would make the other tests in this fixture vacuous" );
        ClassicAssert.IsTrue(
            files.Any( f => Path.GetFileName( f ) == "CSharpRouterHarness.cs" ),
            "CSharpRouterHarness.cs is the file these guards exist for and it was not scanned" );
    }

    /// <summary>
    ///     Strip line comments before matching, so the prose explaining why a pattern is banned
    ///     does not itself trip the ban. Both fixes here leave a comment quoting the old code.
    /// </summary>
    private static bool CodeContains( string source, string needle )
    {
        var code = string.Join( "\n", source
            .Split( '\n' )
            .Select( line =>
            {
                var comment = line.IndexOf( "//", StringComparison.Ordinal );
                return comment >= 0 ? line[..comment] : line;
            } ) );

        return code.Contains( needle, StringComparison.Ordinal );
    }

    private static string ReadInfrastructureSource( string fileName )
    {
        var path = InfrastructureSources()
            .FirstOrDefault( f => Path.GetFileName( f ) == fileName );

        ClassicAssert.IsNotNull( path, $"could not locate {fileName} to scan" );

        return File.ReadAllText( path );
    }

    private static string[] InfrastructureSources()
    {
        var dir = FindTestSourceDir();
        if ( dir == null ) return Array.Empty<string>();

        return Directory.GetFiles( dir, "*.cs", SearchOption.AllDirectories );
    }

    /// <summary>
    ///     Walk up from the test binary to the repository, the same way
    ///     <c>ProtocolCatchAuditTest.FindSourceDir</c> does.
    /// </summary>
    private static string FindTestSourceDir()
    {
        var dir = new DirectoryInfo( AppContext.BaseDirectory );

        while ( dir != null )
        {
            var candidate = Path.Combine(
                dir.FullName, "src", "I2PCore.NTests", "IntegrationTests" );
            if ( Directory.Exists( candidate ) ) return candidate;

            dir = dir.Parent;
        }

        return null;
    }
}
