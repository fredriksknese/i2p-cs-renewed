using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-0f (docs/PRODUCTION-PLAN.md). The integration suite's port sweep used to run
///     <c>fuser -k {port}/tcp</c>, which SIGKILLs <b>every</b> process holding the port — with no
///     way to spare the caller.
///
///     <para>
///         <c>ScaledNetworkFixture</c> sweeps 29000-29299 as its first action. While the
///         in-process SAM bridge was wrongly bound to its default 7656 the ranges never
///         overlapped; batch 4-0e fixed the bridge to honour its configured port, 29002, and the
///         fixture started killing its own test host one second into setup. It presented as
///         <c>"The active test run was aborted. Reason: Test host process crashed"</c> — no
///         managed exception, no stack, no NUnit result, because SIGKILL leaves none — and cost
///         all 11 ScaledNetwork tests on three consecutive CI runs.
///     </para>
///     <para>
///         These are unit tests, not integration ones, because the invariant is about how the
///         helper behaves and must be checked on every commit rather than only when i2pd is
///         installed.
///     </para>
/// </summary>
[TestFixture]
public class PortSweepSafetyTest
{
    /// <summary>
    ///     The behavioural statement: sweep a port this very process is listening on, and this
    ///     process must survive. If the defect is reinstated the test host dies here and the run
    ///     reports a crash rather than a failure — which is itself the signature the batch fixed.
    /// </summary>
    [Test]
    public void SweepingAPortThisProcessHoldsDoesNotKillThisProcess()
    {
        var listener = new TcpListener( IPAddress.Loopback, 0 );
        listener.Start();

        try
        {
            var port = ( (IPEndPoint)listener.LocalEndpoint ).Port;

            RouterProcessManager.KillStaleProcessesOnPorts( port );

            ClassicAssert.IsTrue( listener.Server.IsBound,
                "the sweep took down the listener this process owns" );
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    ///     `fuser -k` cannot exclude the caller, so its presence in this file is the defect
    ///     regardless of what guards sit around it. Enumerate holders and kill by PID instead.
    /// </summary>
    [Test]
    public void ThePortSweepNeverUsesFuserK()
    {
        var source = ReadSource( "IntegrationTests/Infrastructure/RouterProcessManager.cs" );

        ClassicAssert.IsFalse(
            Regex.IsMatch( StripComments( source ), @"""?fuser""?" ),
            "RouterProcessManager invokes fuser. `fuser -k <port>/tcp` SIGKILLs every holder of "
            + "the port including this test host, and offers no way to spare it. Enumerate PIDs "
            + "and skip Environment.ProcessId." );
    }

    /// <summary>
    ///     The narrower invariant behind both of the above, so a future rewrite that drops the
    ///     self-check is caught even if it never mentions fuser.
    /// </summary>
    [Test]
    public void ThePortSweepExcludesTheCurrentProcess()
    {
        var source = StripComments(
            ReadSource( "IntegrationTests/Infrastructure/RouterProcessManager.cs" ) );

        StringAssert.Contains( "Environment.ProcessId", source,
            "the port sweep must know its own PID in order to avoid killing itself" );
    }

    /// <summary>
    ///     Batch 3-6's lesson: an audit that scans nothing passes.
    /// </summary>
    [Test]
    public void TheScanActuallyReadsTheSweepSource()
    {
        var source = ReadSource( "IntegrationTests/Infrastructure/RouterProcessManager.cs" );

        ClassicAssert.Greater( source.Length, 2000, "RouterProcessManager.cs read as near-empty" );
        StringAssert.Contains( "KillStaleProcessesOnPorts", source,
            "scanned a file that does not contain the sweep; the guards above prove nothing" );
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

    private static string ReadSource( string relativePath )
    {
        var dir = new DirectoryInfo( AppContext.BaseDirectory );

        while ( dir != null )
        {
            var candidate = Path.Combine(
                dir.FullName, "src", "I2PCore.NTests", relativePath );
            if ( File.Exists( candidate ) ) return File.ReadAllText( candidate );

            dir = dir.Parent;
        }

        ClassicAssert.Fail( $"could not locate {relativePath}" );
        return null;
    }
}
