using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-0e (docs/PRODUCTION-PLAN.md). <c>ClientContext.Start()</c> used to open with
///     <c>if (IsRunning) { LogWarning("Already running."); return; }</c>, and
///     <c>Router.Start()</c> calls it before any host application has configured it.
///
///     <para>
///         So every host in this repository configured SAM, the HTTP proxy and SOCKS
///         <i>after</i> the services had already started on their defaults — 7656, 4444, 4447 —
///         and the configuration was silently discarded. <c>--sam-port</c> and
///         <c>--http-proxy-port</c> did nothing, <c>--sam-port 0</c> did not disable SAM, and
///         both hosts printed the ports they had asked for rather than the ones bound. The
///         integration suite lost 13 tests to it, every one reported as "failed to connect to
///         the SAM bridge" on a port where nothing was listening.
///     </para>
///     <para>
///         <b>Why these are source assertions rather than a running ClientContext.</b> Binding
///         the real thing means starting listeners on 7656/4444/4447 — the live router's ports,
///         on the developer's own machine — which is exactly the collision this batch exists to
///         stop. The behaviour is verified by the integration suite; what belongs in the gating
///         unit suite is that the discarding cannot come back.
///     </para>
/// </summary>
[TestFixture]
public class ClientContextConfigTest
{
    /// <summary>
    ///     The defect itself. An early return on "already running" is what threw the
    ///     configuration away; anything that reaches the service starters is fine, because each
    ///     of those reconciles its own port.
    /// </summary>
    [Test]
    public void StartDoesNotBailOutWhenItIsAlreadyRunning()
    {
        var start = MethodBody( ReadSource( "Client/ClientContext.cs" ), "public void Start()" );

        ClassicAssert.IsFalse(
            Regex.IsMatch( start, @"if\s*\(\s*IsRunning\s*\)[^;{]*\{?[^}]*\breturn\s*;" ),
            "ClientContext.Start() returns early when already running. Router.Start() calls it "
            + "before any host has configured it, so that return silently discards every "
            + "SetConfig the host makes — including --sam-port 0, which is meant to disable SAM." );
    }

    /// <summary>
    ///     The mechanism that makes the above safe: a running listener whose configured port no
    ///     longer matches the bound one has to be restarted, not left alone. Each starter asks
    ///     <c>ShouldRestart</c> before its old <c>if (X != null) return;</c> would have fired.
    /// </summary>
    [Test]
    public void EveryClientServiceReconcilesItsPortBeforeDecidingToDoNothing()
    {
        var source = ReadSource( "Client/ClientContext.cs" );

        foreach ( var starter in new[]
                 {
                     "public void StartSAMBridge()",
                     "public void StartHTTPProxy()",
                     "public void StartSOCKSProxy()",
                 } )
            StringAssert.Contains( "ShouldRestart", MethodBody( source, starter ),
                $"{starter} does not reconcile its configured port against the bound one, so a "
                + "host that changes the port on a running service is ignored." );
    }

    /// <summary>
    ///     The ordering half of the fix. Both hosts must configure the client services before
    ///     <c>Router.Start()</c>, which is what starts them. Confirmed to fail with either host's
    ///     configuration block moved back after the call.
    /// </summary>
    [Test]
    public void HostsConfigureClientServicesBeforeStartingTheRouter()
    {
        foreach ( var (project, file) in new[]
                 {
                     ( "I2PRouterCli", "Program.cs" ),
                     ( "I2PCore.NTests", "IntegrationTests/Infrastructure/CSharpRouterHarness.cs" ),
                 } )
        {
            // Comments must go first: I2PRouterCli/Program.cs carries the comment "Must be set
            // before Router.Start(): NTCP2Host reads it when it publishes its address" well
            // above the call, and matching that instead of the call failed this test against
            // correctly-ordered code.
            var source = StripComments( ReadSource( file, project ) );

            var firstConfig = source.IndexOf( "ClientContext.Inst.SetConfig", StringComparison.Ordinal );
            var routerStart = source.IndexOf( "Router.Start()", StringComparison.Ordinal );

            ClassicAssert.Greater( firstConfig, -1, $"{file} sets no client configuration" );
            ClassicAssert.Greater( routerStart, -1, $"{file} never starts the router" );
            ClassicAssert.Less( firstConfig, routerStart,
                $"{project}/{file} configures ClientContext after Router.Start(), which is what "
                + "starts ClientContext. Settings go before the thing that reads them." );
        }
    }

    /// <summary>
    ///     Batch 3-6's lesson: an audit that scans nothing passes. <see cref="MethodBody" /> in
    ///     particular fails open — it returns empty for a method it cannot find, which would make
    ///     the assertions above vacuous after a rename.
    /// </summary>
    [Test]
    public void TheScanActuallyReadsTheMethodsItClaimsTo()
    {
        var source = ReadSource( "Client/ClientContext.cs" );

        foreach ( var method in new[]
                 {
                     "public void Start()",
                     "public void StartSAMBridge()",
                     "public void StartHTTPProxy()",
                     "public void StartSOCKSProxy()",
                 } )
            ClassicAssert.Greater( MethodBody( source, method ).Length, 40,
                $"could not read the body of {method}; the scans over it prove nothing" );
    }

    /// <summary>
    ///     Everything from the signature to the start of the next member declaration. Crude, but
    ///     enough to tell "returns early inside Start()" from "returns early somewhere in a
    ///     900-line file", and <see cref="TheScanActuallyReadsTheMethodsItClaimsTo" /> covers the
    ///     case where it finds nothing.
    /// </summary>
    private static string MethodBody( string source, string signature )
    {
        var start = source.IndexOf( signature, StringComparison.Ordinal );
        if ( start < 0 ) return string.Empty;

        var rest = source[( start + signature.Length )..];
        var next = Regex.Match( rest, @"\n    (public|private|internal|protected)\s" );

        return next.Success ? rest[..next.Index] : rest;
    }

    private static string StripComments( string source )
    {
        return string.Join( "\n", source
            .Split( '\n' )
            .Select( line =>
            {
                var comment = line.IndexOf( "//", StringComparison.Ordinal );
                return comment >= 0 ? line[..comment] : line;
            } ) );
    }

    private static string ReadSource( string relativePath, string project = "I2PCore" )
    {
        var dir = new DirectoryInfo( AppContext.BaseDirectory );

        while ( dir != null )
        {
            var candidate = Path.Combine( dir.FullName, "src", project, relativePath );
            if ( File.Exists( candidate ) ) return File.ReadAllText( candidate );

            dir = dir.Parent;
        }

        ClassicAssert.Fail( $"could not locate src/{project}/{relativePath}" );
        return null;
    }
}
