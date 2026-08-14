using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 6-1 (docs/PRODUCTION-PLAN.md). The verbose tunnel/transport tracing categories are
///     runtime flags, not <c>#if</c> symbols in <c>I2PCore.csproj</c>.
/// </summary>
/// <remarks>
///     Two things are guarded, and they fail for different reasons.
///     <para>
///     <b>That the compile-time scheme stays gone.</b> Selecting a category used to mean editing
///     the project file and rebuilding — the same defect batch 0-1 removed from the rest of the
///     logging, and worse here because these are the categories you want when a tunnel is
///     misbehaving in a fixture that takes half an hour per run. Code behind a <c>#if</c> also
///     rots unseen: two of the lines this batch converted interpolated <c>{this}</c> inside the
///     <b>static</b> <c>Router</c> class, so switching that category on would not have compiled
///     at all.
///     </para>
///     <para>
///     <b>That an off category is free.</b> A trace in a per-message tunnel path is only
///     acceptable if it costs nothing when nobody asked for it, which is what the interpolated
///     string handler is for. A call site that concatenates or pre-formats silently loses that
///     and no other test would notice.
///     </para>
/// </remarks>
[TestFixture]
public class TunnelTracingTest
{
    /// <summary>Walks up from the test binary to the repository root.</summary>
    private static string SourceRoot()
    {
        var dir = new DirectoryInfo( TestContext.CurrentContext.TestDirectory );
        while ( dir != null && !File.Exists( Path.Combine( dir.FullName, "i2p.sln" ) ) ) dir = dir.Parent;
        return dir?.FullName ?? TestContext.CurrentContext.TestDirectory;
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

    /// <summary>
    ///     Runs <paramref name="act" /> with the given level and categories, returning everything
    ///     Logging emitted. Console sink, so the process-wide file store is left alone — same
    ///     approach as LoggingVisibilityTest.
    /// </summary>
    private static string Capture( Logging.LogLevels level, TraceCategories categories, Action act )
    {
        var originalOut = Console.Out;
        var originalLevel = Logging.LogLevel;
        var originalTraces = Logging.EnabledTraces;
        var originalToConsole = Logging.LogToConsole;

        var buffer = new StringWriter();

        try
        {
            Console.SetOut( TextWriter.Synchronized( buffer ) );
            Logging.LogLevel = level;
            Logging.EnabledTraces = categories;
            Logging.LogToConsole = true;

            act();
        }
        finally
        {
            Console.SetOut( originalOut );
            Logging.LogLevel = originalLevel;
            Logging.EnabledTraces = originalTraces;
            Logging.LogToConsole = originalToConsole;
        }

        return buffer.ToString();
    }

    /// <summary>Records whether anything asked it to render itself.</summary>
    private sealed class FormatProbe
    {
        public bool WasFormatted { get; private set; }

        public override string ToString()
        {
            WasFormatted = true;
            return "rendered";
        }
    }

    [Test]
    public void NoCompileTimeTraceGatesRemainUnderI2PCore()
    {
        var root = Path.Combine( SourceRoot(), "src", "I2PCore" );

        var offenders = Directory
            .EnumerateFiles( root, "*.cs", SearchOption.AllDirectories )
            .Where( f => Regex.IsMatch(
                StripComments( File.ReadAllText( f ) ),
                @"^\s*#if\s+[^\n]*\bLOG_", RegexOptions.Multiline ) )
            .Select( f => Path.GetRelativePath( root, f ) )
            .ToArray();

        ClassicAssert.IsEmpty( offenders,
            "tracing categories are runtime flags (TraceCategories / --log-trace). A #if LOG_ guard " +
            "makes its code unreachable in the build you have and lets it rot uncompiled: " +
            string.Join( ", ", offenders ) );
    }

    [Test]
    public void TheProjectFileDefinesNoLoggingConstants()
    {
        var csproj = File.ReadAllText(
            Path.Combine( SourceRoot(), "src", "I2PCore", "I2PCore.csproj" ) );

        // The comment left behind names them, so match the define rather than the word.
        ClassicAssert.IsFalse(
            Regex.IsMatch( csproj, @"<DefineConstants>[^<]*LOG_" ),
            "I2PCore.csproj must not define logging category symbols; selection is runtime" );
    }

    [Test]
    public void AnEnabledCategoryIsEmitted()
    {
        var marker = "TRACE-ON-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Debug, TraceCategories.TunnelTransfer,
            () => Logging.LogTrace( TraceCategories.TunnelTransfer, $"{marker}" ) );

        StringAssert.Contains( marker, captured );
    }

    [Test]
    public void ACategoryThatWasNotAskedForIsNotEmitted()
    {
        var marker = "TRACE-OTHER-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Debug, TraceCategories.LeaseMgmt,
            () => Logging.LogTrace( TraceCategories.TunnelTransfer, $"{marker}" ) );

        StringAssert.DoesNotContain( marker, captured );
    }

    /// <summary>
    ///     Both filters apply. A category is which firehose you asked for; the level still says
    ///     how much the router is emitting at all, and a trace is Debug-level output. This is the
    ///     trap the CLI warns about, and it is pinned here so the warning stays true.
    /// </summary>
    [Test]
    public void ACategoryOnWithTheLevelAboveDebugEmitsNothing()
    {
        var marker = "TRACE-LEVEL-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Information, TraceCategories.TunnelTransfer,
            () => Logging.LogTrace( TraceCategories.TunnelTransfer, $"{marker}" ) );

        StringAssert.DoesNotContain( marker, captured );
        ClassicAssert.IsFalse( Logging.IsTraceEnabled( TraceCategories.TunnelTransfer ),
            "IsTraceEnabled must agree with what LogTrace actually does" );
    }

    [Test]
    public void ASuppressedTraceDoesNotFormatItsMessage()
    {
        var probe = new FormatProbe();

        Capture( Logging.LogLevels.Debug, TraceCategories.None,
            () => Logging.LogTrace( TraceCategories.TunnelTransfer, $"probe says {probe}" ) );

        ClassicAssert.IsFalse( probe.WasFormatted,
            "a trace whose category is off must skip the interpolation entirely — these calls " +
            "sit in per-message tunnel paths" );
    }

    [Test]
    public void ASuppressedTraceDoesNotRunItsGenerator()
    {
        var invoked = false;

        Capture( Logging.LogLevels.Debug, TraceCategories.None, () =>
            Logging.LogTrace( TraceCategories.TunnelTransfer, () =>
            {
                invoked = true;
                return "must not be built";
            } ) );

        ClassicAssert.IsFalse( invoked );
    }

    /// <summary>
    ///     A message may name more than one category — Router's DeliveryStatus line was
    ///     <c>#if LOG_ALL_TUNNEL_TRANSFER || LOG_ALL_LEASE_MGMT</c> and stays an "or".
    /// </summary>
    [Test]
    public void AMessageInTwoCategoriesIsEmittedIfEitherIsOn()
    {
        var marker = "TRACE-EITHER-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Debug, TraceCategories.LeaseMgmt,
            () => Logging.LogTrace( TraceCategories.TunnelTransfer | TraceCategories.LeaseMgmt,
                $"{marker}" ) );

        StringAssert.Contains( marker, captured );
    }

    [Test]
    public void AnUnknownCategoryNameIsRejectedAndNamed()
    {
        var ok = TraceCategoryNames.TryParse( "tunnel-transfer,tunel-selection",
            out var parsed, out var unknown );

        ClassicAssert.IsFalse( ok, "a misspelt category must not parse to 'enable nothing'" );
        ClassicAssert.AreEqual( "tunel-selection", unknown );
        ClassicAssert.AreEqual( TraceCategories.None, parsed );
    }

    [Test]
    public void CategoryNamesRoundTrip()
    {
        ClassicAssert.IsTrue(
            TraceCategoryNames.TryParse( "lease-mgmt,tunnel-transfer", out var parsed, out _ ) );
        ClassicAssert.AreEqual( TraceCategories.TunnelTransfer | TraceCategories.LeaseMgmt, parsed );

        ClassicAssert.IsTrue( TraceCategoryNames.TryParse( "all", out var all, out _ ) );
        ClassicAssert.AreEqual( "all", TraceCategoryNames.Format( all ) );
        ClassicAssert.AreEqual( "none", TraceCategoryNames.Format( TraceCategories.None ) );
        ClassicAssert.AreEqual( "tunnel-transfer", TraceCategoryNames.Format( TraceCategories.TunnelTransfer ) );

        foreach ( var name in TraceCategoryNames.All )
            ClassicAssert.IsTrue( TraceCategoryNames.TryParse( name, out _, out _ ),
                $"'{name}' is offered in --log-trace help and must parse" );
    }

    /// <summary>
    ///     The transit hop must trace <b>both</b> sides of its layer crypto.
    /// </summary>
    /// <remarks>
    ///     This is the diagnostic the batch exists for and the one thing a unit test cannot
    ///     observe from outside: session 6 measured a hop that preserves length and destroys
    ///     content, and localising that needs our outgoing digest to be comparable with the next
    ///     hop's incoming one. A trace on only one side of <c>EncryptTunnelMessages</c> reads as
    ///     working and answers nothing, so the ordering is asserted against the source — the same
    ///     approach batches 3-11, 3-12 and 3-14 used where the defect was in placement.
    /// </remarks>
    [Test]
    public void TheTransitHopTracesBothSidesOfItsLayerCrypto()
    {
        var source = StripComments( File.ReadAllText(
            Path.Combine( SourceRoot(), "src", "I2PCore", "TunnelLayer", "TransitTunnel.cs" ) ) );

        var body = Regex.Match( source,
            @"HandleTunnelData\s*\([^)]*\)\s*\{(?<body>.*?)\n    \}", RegexOptions.Singleline );

        ClassicAssert.IsTrue( body.Success, "TransitTunnel.HandleTunnelData not found" );

        var text = body.Groups["body"].Value;
        var before = text.IndexOf( "TraceTunnelData", StringComparison.Ordinal );
        var crypto = text.IndexOf( "EncryptTunnelMessages", StringComparison.Ordinal );
        var after = text.IndexOf( "TraceTunnelData", crypto, StringComparison.Ordinal );

        ClassicAssert.Greater( crypto, before,
            "the transit hop must trace what it received before re-encrypting it" );
        ClassicAssert.Greater( after, crypto,
            "and what it is about to send after — one side alone localises nothing" );
    }

    /// <summary>
    ///     The digest is what makes a message followable between two routers' logs, so it has to
    ///     be a function of the bytes and nothing else.
    /// </summary>
    [Test]
    public void TheTraceDigestDependsOnlyOnTheBytes()
    {
        var a = new byte[] { 1, 2, 3, 4, 5 };
        var b = new byte[] { 1, 2, 3, 4, 5 };
        var c = new byte[] { 1, 2, 3, 4, 6 };

        ClassicAssert.AreEqual( a.ComputeHash(), b.ComputeHash() );
        ClassicAssert.AreNotEqual( a.ComputeHash(), c.ComputeHash() );

        // The span overload the traces use must agree with the byte[] one, including offset views.
        var framed = new byte[] { 9, 9, 1, 2, 3, 4, 5, 9 };
        ClassicAssert.AreEqual( a.ComputeHash(), ( (ReadOnlySpan<byte>)framed.AsSpan( 2, 5 ) ).ComputeHash() );
    }
}
