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

    [Test]
    public void LazyOverloadIsEmittedWhenThresholdAllows()
    {
        var marker = "LOGVIS-LAZY-" + Guid.NewGuid().ToString( "N" );

        var captured = Capture( Logging.LogLevels.Debug, () => Logging.LogDebug( () => marker ) );

        StringAssert.Contains( marker, captured );
    }
}
