using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 3-6 (docs/PRODUCTION-PLAN.md). Gate: zero bare <c>catch { }</c> or
///     <c>catch (Exception) { }</c> under <c>TransportLayer/SSU2/</c> and
///     <c>SessionLayer/ECIES/</c> — the two directories Phases 4 and 5 are about to debug.
///
///     <para>
///         The plan's own words: 3-6 "is the difference between debugging SSU2 and debugging it
///         blindfolded". A swallowed exception in these directories does not merely lose a log
///         line, it converts a specific protocol failure into a generic absence — batch 3-3
///         found the SSU2 handshake failing with no data phase, batch 3-5 found our header
///         encryption unable to read i2pd's, and both investigations had to start by working out
///         what was being hidden.
///     </para>
///
///     <para>
///         <b>The rule the audit applied</b>, recorded here because it is the thing a later
///         batch needs in order to add a catch without reopening the question. Every catch in
///         those two directories must be one of:
///     </para>
///     <list type="number">
///         <item>
///             <b>Unexpected</b> — log at Warning or above, passing the whole exception
///             (<c>{ex}</c>, never <c>{ex.Message}</c>, which discards the stack and the type).
///         </item>
///         <item>
///             <b>Propagated</b> — returned to a caller that logs it, with the exception type
///             carried in the propagated string and a comment naming that caller. Verified by
///             reading the caller, not assumed: the audit found
///             <c>ECIESRouterProcessor.ProcessMessage</c> returning an <c>Error</c> that
///             <c>Router.HandleGarlic</c> never reads.
///         </item>
///         <item>
///             <b>Expected</b> — a trial loop or a benign fallback. Debug level, still carrying
///             the whole exception, plus a comment saying why it is expected and what recovers.
///         </item>
///     </list>
///
///     <para>
///         Only the bare-catch half of that is machine-checkable, and this fixture checks it.
///         The rest is enforced by review — which is why the rule is written down here rather
///         than left implicit in the diff.
///     </para>
/// </summary>
[TestFixture]
public class ProtocolCatchAuditTest
{
    /// <summary>
    ///     The directories Phase 4 and Phase 5 debug. Deliberately narrow: 102 silent catches
    ///     exist repo-wide, and batch 10 (<c>p10/silent-catch-audit-*</c>) owns the rest. Widening
    ///     this list before those batches land would make the test red for work nobody has
    ///     scheduled.
    /// </summary>
    private static readonly string[] AuditedDirectories =
    {
        Path.Combine( "TransportLayer", "SSU2" ),
        Path.Combine( "SessionLayer", "ECIES" )
    };

    /// <summary>
    ///     <c>catch {</c> and <c>catch (Exception) {</c> — a catch that binds no variable cannot
    ///     log what it caught even if someone later wants to, so it is banned outright rather
    ///     than merely discouraged. A typed catch that binds a variable is allowed here and
    ///     judged by review against the three cases above.
    /// </summary>
    [Test]
    public void NoUnbindableCatchInProtocolDirectories()
    {
        var offenders = ScanAudited( new Regex(
            @"^\s*catch\s*(\{|$|\(\s*[\w\.]+\s*\)\s*(\{|$))",
            RegexOptions.Compiled ) );

        ClassicAssert.IsEmpty( offenders,
            "A catch in TransportLayer/SSU2 or SessionLayer/ECIES must bind its exception so it "
            + "can be logged or propagated — see the rule on ProtocolCatchAuditTest. Offenders: "
            + string.Join( ", ", offenders ) );
    }

    /// <summary>
    ///     A catch that binds <c>ex</c> and then never mentions it in its body is the same defect
    ///     wearing a variable name, and it is what the bare-catch check would otherwise push
    ///     people towards.
    /// </summary>
    [Test]
    public void EveryCaughtExceptionIsUsed()
    {
        var offenders = new List<string>();

        foreach ( var file in AuditedFiles() )
        {
            var lines = File.ReadAllLines( file );

            for ( var i = 0; i < lines.Length; i++ )
            {
                var declared = Regex.Match( lines[i], @"^\s*catch\s*\(\s*[\w\.]+\s+(\w+)\s*\)" );
                if ( !declared.Success ) continue;

                var name = declared.Groups[1].Value;
                var body = BlockAfter( lines, i );

                if ( !Regex.IsMatch( body, $@"\b{Regex.Escape( name )}\b" ) )
                    offenders.Add( $"{Path.GetFileName( file )}:{i + 1}" );
            }
        }

        ClassicAssert.IsEmpty( offenders,
            "These catch blocks bind an exception and never use it, which loses the diagnosis "
            + "just as completely as a bare catch: " + string.Join( ", ", offenders ) );
    }

    /// <summary>
    ///     Guards the guard. If the source tree stops being discoverable, or the directory names
    ///     move, both tests above would pass by scanning nothing at all — the failure mode batch
    ///     2-7 hit at suite level, where a partial run reads exactly like a green one.
    /// </summary>
    [Test]
    public void TheAuditActuallyScansSomething()
    {
        var files = AuditedFiles().ToList();

        ClassicAssert.Greater( files.Count, 15,
            "expected to find the SSU2 and ECIES sources; scanning far fewer files than that "
            + "means the audit is passing vacuously" );

        var catches = ScanAudited( new Regex( @"^\s*catch\b", RegexOptions.Compiled ) );

        ClassicAssert.Greater( catches.Count, 20,
            "expected to find the audited catch sites themselves; finding almost none means the "
            + "scan is not reading what it thinks it is" );
    }

    private static List<string> ScanAudited( Regex pattern )
    {
        return AuditedFiles()
            .SelectMany( f => File.ReadLines( f )
                .Select( ( line, n ) => (f, n: n + 1, line) )
                .Where( t => pattern.IsMatch( t.line ) ) )
            .Select( t => $"{Path.GetFileName( t.f )}:{t.n}" )
            .ToList();
    }

    private static IEnumerable<string> AuditedFiles()
    {
        var root = FindSourceDir( "I2PCore" );

        if ( root == null )
            Assert.Ignore( "I2PCore source tree not found next to the test assembly" );

        return AuditedDirectories
            .Select( d => Path.Combine( root, d ) )
            .Where( Directory.Exists )
            .SelectMany( d => Directory.EnumerateFiles( d, "*.cs", SearchOption.AllDirectories ) )
            .OrderBy( f => f, StringComparer.Ordinal );
    }

    /// <summary>
    ///     The braced block starting at or just after <paramref name="start" />, by brace depth.
    ///     Good enough for this purpose: a brace inside a string literal would over-read, which
    ///     can only ever make the test more lenient, never produce a false failure.
    /// </summary>
    private static string BlockAfter( string[] lines, int start )
    {
        var depth = 0;
        var seenOpen = false;
        var body = new List<string>();

        for ( var i = start; i < lines.Length; i++ )
        {
            var line = lines[i];

            if ( i > start || line.Contains( '{' ) ) body.Add( line );

            depth += line.Count( c => c == '{' ) - line.Count( c => c == '}' );

            if ( line.Contains( '{' ) ) seenOpen = true;
            if ( seenOpen && depth <= 0 ) break;

            // A catch whose block never opens (single-statement form) ends at the first
            // statement; stop rather than swallowing the rest of the method.
            if ( !seenOpen && i > start && line.Trim().Length > 0 ) break;
        }

        return string.Join( "\n", body );
    }

    private static string FindSourceDir( string project )
    {
        var dir = new DirectoryInfo( AppContext.BaseDirectory );

        while ( dir != null )
        {
            var candidate = Path.Combine( dir.FullName, "src", project );
            if ( Directory.Exists( candidate ) ) return candidate;

            dir = dir.Parent;
        }

        return null;
    }
}
