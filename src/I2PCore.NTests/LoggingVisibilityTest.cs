using System;
using System.IO;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Guards the Gate 0 invariant: a Release build must be able to emit debug-level
///     logging on demand. Historically Logging.Log/LogDebug/LogTransport/LogDebugData
///     carried [Conditional("DEBUG")], so every one of those call sites was stripped from
///     any non-DEBUG build and a Release router was undiagnosable. These tests fail if
///     that compile-time filtering is ever reintroduced.
/// </summary>
[TestFixture]
public class LoggingVisibilityTest
{
    /// <summary>
    ///     Runs <paramref name="act" /> with the runtime threshold at <paramref name="level" />
    ///     and console logging on, returning everything Logging emitted. Uses the console sink
    ///     rather than LogToStore so the process-wide file store is left untouched.
    /// </summary>
    private static string Capture( Logging.LogLevels level, Action act )
    {
        var originalOut = Console.Out;
        var originalLevel = Logging.LogLevel;
        var originalToConsole = Logging.LogToConsole;

        var buffer = new StringWriter();

        try
        {
            Console.SetOut( TextWriter.Synchronized( buffer ) );
            Logging.LogLevel = level;
            Logging.LogToConsole = true;

            act();
        }
        finally
        {
            Console.SetOut( originalOut );
            Logging.LogLevel = originalLevel;
            Logging.LogToConsole = originalToConsole;
        }

        return buffer.ToString();
    }

    [Test]
    public void LogDebugIsEmittedWhenThresholdIsDebug()
    {
        var marker = "LOGVIS-DEBUG-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Debug, () => Logging.LogDebug( marker ) );

        StringAssert.Contains( marker, captured,
            "LogDebug must reach the sink in every build configuration, not just DEBUG" );
    }

    [Test]
    public void LogTransportIsEmittedWhenThresholdIsTransport()
    {
        var marker = "LOGVIS-TRANSPORT-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Transport, () => Logging.LogTransport( marker ) );

        StringAssert.Contains( marker, captured );
    }

    [Test]
    public void LogDebugDataIsEmittedWhenThresholdIsDebugData()
    {
        var marker = "LOGVIS-DEBUGDATA-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.DebugData, () => Logging.LogDebugData( marker ) );

        StringAssert.Contains( marker, captured );
    }

    [Test]
    public void LogDebugIsSuppressedWhenThresholdIsWarning()
    {
        var marker = "LOGVIS-SUPPRESSED-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Warning, () => Logging.LogDebug( marker ) );

        StringAssert.DoesNotContain( marker, captured,
            "the runtime LogLevel must still filter debug output" );
    }

    /// <summary>
    ///     The Func&lt;string&gt; overloads exist so hot paths pay nothing when logging is off.
    ///     The threshold check must therefore happen before the generator is invoked.
    /// </summary>
    [Test]
    public void LazyOverloadDoesNotInvokeGeneratorBelowThreshold()
    {
        var invoked = false;

        Capture( Logging.LogLevels.Warning, () => Logging.LogDebug( () =>
        {
            invoked = true;
            return "must not be built";
        } ) );

        ClassicAssert.IsFalse( invoked,
            "the message generator must not run when the threshold excludes the level" );
    }

    /// <summary>
    ///     Records whether anything asked it to render itself.
    /// </summary>
    private sealed class FormatProbe
    {
        public bool WasFormatted { get; private set; }

        public override string ToString()
        {
            WasFormatted = true;
            return "rendered";
        }
    }

    /// <summary>
    ///     A suppressed LogDebug($"...") must not build its string. Before batch 0-6 the
    ///     interpolation ran at the call site and the result was thrown away inside Log(),
    ///     so every one of the 338 interpolated debug call sites paid full formatting cost on
    ///     every call at the default Information level.
    /// </summary>
    [Test]
    public void InterpolatedLogDebugDoesNotFormatWhenSuppressed()
    {
        var probe = new FormatProbe();

        Capture( Logging.LogLevels.Warning, () => Logging.LogDebug( $"probe says {probe}" ) );

        ClassicAssert.IsFalse( probe.WasFormatted,
            "interpolation must be skipped entirely when the level is suppressed" );
    }

    [Test]
    public void InterpolatedLogDebugStillFormatsWhenEnabled()
    {
        var probe = new FormatProbe();

        var captured = Capture( Logging.LogLevels.Debug, () => Logging.LogDebug( $"probe says {probe}" ) );

        ClassicAssert.IsTrue( probe.WasFormatted, "interpolation must still run when enabled" );
        StringAssert.Contains( "probe says rendered", captured );
    }

    [Test]
    public void InterpolatedLogTransportDoesNotFormatWhenSuppressed()
    {
        var probe = new FormatProbe();

        Capture( Logging.LogLevels.Information, () => Logging.LogTransport( $"probe says {probe}" ) );

        ClassicAssert.IsFalse( probe.WasFormatted );
    }

    [Test]
    public void LazyOverloadIsEmittedWhenThresholdAllows()
    {
        var marker = "LOGVIS-LAZY-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Debug, () => Logging.LogDebug( () => marker ) );

        StringAssert.Contains( marker, captured );
    }
}
