using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 5-2 (docs/PRODUCTION-PLAN.md). The ECIES handshake dumped Elligator2 and
///     ephemeral-key fingerprints at <c>LogInformation</c> — the default level — on <b>every</b>
///     session establishment, in both directions.
///
///     <para>
///         <b>The level was only half of it.</b> Both sites computed what they logged into locals
///         first: an <c>Elligator2.Decode</c> and two <c>BitConverter.ToString</c> calls per
///         handshake. Lowering the level alone would have left that work running at every level,
///         because the interpolated-string handler described in CLAUDE.md can only skip
///         formatting it is given, not arguments already evaluated. Both sites are therefore
///         behind <c>Logging.IsEnabled</c>.
///     </para>
///     <para>
///         <b>Why a scan and not a handshake.</b> These lines are on the hybrid post-quantum path,
///         and nothing in the repository can drive one yet — <c>ECIESPump</c> pairs two classical
///         key managers, so a behavioural test would pass without ever reaching the code it
///         claims to cover. A vacuous test is worse than an honest scan. Driving a hybrid
///         handshake belongs with batch 9-3.
///     </para>
/// </summary>
[TestFixture]
public class EciesHandshakeLoggingTest
{
    private static readonly Regex Informational =
        new( @"Logging\.LogInformation\s*\(", RegexOptions.Compiled );

    /// <summary>
    ///     Session establishment is a per-message event, so it belongs at Debug. Information is
    ///     for things an operator watching a running router wants to see once.
    /// </summary>
    [Test]
    public void TheEciesHandshakeDoesNotLogAtInformation()
    {
        var offenders = EciesSources()
            .Where( f => Informational.IsMatch( StripComments( File.ReadAllText( f ) ) ) )
            .Select( Path.GetFileName )
            .ToArray();

        CollectionAssert.IsEmpty( offenders,
            "these ECIES files log at Information on the handshake path. A session is established "
            + "per message, so its diagnostics belong at Debug, and behind Logging.IsEnabled when "
            + "building the message costs real work." );
    }

    /// <summary>
    ///     Batch 3-6's lesson, which this plan has since had to relearn twice: an audit that
    ///     scans nothing passes.
    /// </summary>
    [Test]
    public void TheScanActuallyReadsTheEciesSources()
    {
        var files = EciesSources();

        ClassicAssert.Greater( files.Length, 3,
            "the ECIES source scan found almost nothing, which would make the check above "
            + "vacuous" );
        CollectionAssert.Contains( files.Select( Path.GetFileName ).ToArray(),
            "ECIESSessionKeyManager.cs",
            "the scan is not looking at the file that carried the defect" );
    }

    private static string[] EciesSources()
    {
        var dir = FindEciesDir();

        return dir == null
            ? Array.Empty<string>()
            : Directory.GetFiles( dir, "*.cs", SearchOption.AllDirectories );
    }

    private static string FindEciesDir()
    {
        var probe = new DirectoryInfo( TestContext.CurrentContext.TestDirectory );

        while ( probe != null )
        {
            var candidate = Path.Combine(
                probe.FullName, "src", "I2PCore", "SessionLayer", "ECIES" );

            if ( Directory.Exists( candidate ) ) return candidate;

            probe = probe.Parent;
        }

        return null;
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
}
