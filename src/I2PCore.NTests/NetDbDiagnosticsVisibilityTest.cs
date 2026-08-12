using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 3-10 (docs/PRODUCTION-PLAN.md). NetDb's diagnostics must not be compiled out of a
///     Release build.
///
///     <para>
///         This is the same rule <see cref="LoggingVisibilityTest" /> enforces for
///         <c>[Conditional("DEBUG")]</c>, in the second form it took. Five <c>#if DEBUG</c> blocks
///         in <c>RoutersStatistics</c> held the reason a peer had been judged inactive — and the
///         inactivity sweep is what empties the floodfill index, which takes every client of the
///         router offline. A Release CI run could not say why it had swept anything, so the
///         question "why does NodeInactive fire on peers we are using?" was unanswerable from the
///         only environment where it reproduces.
///     </para>
///     <para>
///         The level is the filter. <c>Logging.LogLevel</c> and <c>Logging.IsEnabled</c> decide
///         what is emitted; the build configuration decides nothing.
///     </para>
/// </summary>
[TestFixture]
public class NetDbDiagnosticsVisibilityTest
{
    private static string NetDbSourceRoot()
    {
        var dir = TestContext.CurrentContext.TestDirectory;

        for (var probe = new DirectoryInfo(dir); probe != null; probe = probe.Parent)
        {
            var candidate = Path.Combine(probe.FullName, "src", "I2PCore", "NetDb");
            if (Directory.Exists(candidate)) return candidate;
        }

        return null;
    }

    [Test]
    public void NoNetDbDiagnosticIsGatedOnTheBuildConfiguration()
    {
        var root = NetDbSourceRoot();
        ClassicAssert.IsNotNull(root, "could not locate src/I2PCore/NetDb from the test directory");

        var files = Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories).ToArray();

        // The scan's own "did it read anything" check. A guard that silently reads zero files
        // passes forever; this plan has had to add this check three times now.
        ClassicAssert.Greater(files.Length, 3, $"expected several sources under {root}");

        var pattern = new Regex(@"#if\s+DEBUG", RegexOptions.Compiled);
        var offenders = new List<string>();

        foreach (var f in files)
        {
            var lines = File.ReadLines(f).ToArray();
            ClassicAssert.Greater(lines.Length, 0, $"{Path.GetFileName(f)} read as empty");

            offenders.AddRange(lines
                .Select((line, n) => (n: n + 1, line: StripComment(line)))
                .Where(t => pattern.IsMatch(t.line))
                .Select(t => $"{Path.GetFileName(f)}:{t.n}"));
        }

        ClassicAssert.IsEmpty(offenders,
            "NetDb diagnostics must be gated by Logging.LogLevel / Logging.IsEnabled, never by "
            + "#if DEBUG — a Release router has to be able to say why it swept a peer: "
            + string.Join(", ", offenders));
    }

    /// <summary>
    ///     Comments mentioning the banned construct are not offenders — the block comment on the
    ///     fix in <c>RoutersStatistics</c> names it, which makes this file a live check that the
    ///     stripping works.
    /// </summary>
    private static string StripComment(string line)
    {
        var at = line.IndexOf("//", System.StringComparison.Ordinal);
        return at >= 0 ? line[..at] : line;
    }
}
