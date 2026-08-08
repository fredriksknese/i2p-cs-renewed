using System;
using System.Diagnostics;
using System.Threading;
using CM = System.Configuration.ConfigurationManager;

namespace I2PCore.Utils;

public static class Logging
{
    private static ILogStore _store;

    private static readonly object _lock = new();

    public enum LogLevels
    {
        Everything = 0,
        DebugData = 5,
        Transport = 7,
        Debug = 10,
        Information = 20,
        Warning = 50,
        Error = 100,
        Critical = 500,
        Nothing = int.MaxValue
    }

    /// <summary>
    ///     Reads the app config file '.config' for logging settings.
    /// </summary>
    public static void ReadAppConfig()
    {
        if (!string.IsNullOrWhiteSpace(CM.AppSettings["LogFileLevel"])) SetLogLevel(CM.AppSettings["LogFileLevel"]);

        if (!string.IsNullOrWhiteSpace(CM.AppSettings["LogFileNameTimeStamp"]))
            TimestampFiles = bool.Parse(CM.AppSettings["LogFileNameTimeStamp"]);

        if (!string.IsNullOrWhiteSpace(CM.AppSettings["LogFileMaxBytes"]))
            MaxLogFileSize = long.Parse(CM.AppSettings["LogFileMaxBytes"]);

        if (!string.IsNullOrWhiteSpace(CM.AppSettings["LogFileName"])) LogToFile(CM.AppSettings["LogFileName"]);
    }

    public static void SetLogLevel(LogLevels level)
    {
        LogLevel = level;
    }

    /// <summary>
    ///     Batch 2-6 (docs/PRODUCTION-PLAN.md). Restore the compiled-in defaults and close any
    ///     open log store.
    ///     <para>
    ///         Logging is process-global mutable state that no Stop() path restores, so a fixture
    ///         raising the level to Everything or attaching a file store leaves both in place for
    ///         every fixture that runs after it — a class of order-dependent failure that is
    ///         painful to diagnose because the symptom appears in an unrelated test.
    ///     </para>
    /// </summary>
    internal static void ResetForTests()
    {
        CloseLogFile();

        LogLevel = LogLevels.Information;
        LogToConsole = false;
        LogToDebug = false;
        TimestampFiles = false;
        MaxLogFileSize = 10 * 1024 * 1024;
    }

    public static void SetLogLevel(string name)
    {
        LogLevel = (LogLevels)Enum.Parse(typeof(LogLevels), name);
    }

    /// <summary>
    ///     The one and only logging filter. There is deliberately no compile-time filtering:
    ///     debug output must be reachable in a Release build (see IsEnabled below), because a
    ///     router you cannot observe is a router you cannot debug. Defaults to Information so
    ///     that enabling this had no practical effect on existing deployments; hosts raise or
    ///     lower it at runtime (the CLI exposes --log-level).
    /// </summary>
    public static LogLevels LogLevel = LogLevels.Information;

    /// <summary>
    ///     True when <paramref name="level" /> would currently be emitted. Call sites on hot
    ///     paths can use this to skip building a message, though the Func&lt;string&gt;
    ///     overloads below already do exactly that.
    /// </summary>
    public static bool IsEnabled( LogLevels level )
    {
        return level >= LogLevel;
    }

    /// <summary>
    ///     Output debug text to System.Console.
    /// </summary>
    public static bool LogToConsole = false;

    /// <summary>
    ///     Output debug text to System.Diagnostics.Debug.
    /// </summary>
    public static bool LogToDebug = false;

    public static bool TimestampFiles;
    public static long MaxLogFileSize = 10 * 1024 * 1024;

    public static void LogToStore(ILogStore dest, string name)
    {
        lock (_lock)
        {
            if (_store != null)
            {
                _store.Close();
                _store = null;
            }

            _store = dest;
            _store.Name = name;
        }

        LogDebug($"LogToStore: {dest.Name}");
    }

    public static void LogToFile(string filename)
    {
        LogToStore(new FileLogStore(TimestampFiles, MaxLogFileSize), filename);
    }

    private static void CloseLogFile()
    {
        lock (_lock)
        {
            if (_store != null)
            {
                _store.Close();
                _store = null;
            }
        }
    }

    internal static string Unwrap(Exception ex)
    {
        return ex.ToString();
    }

    public static void Log(string txt)
    {
        Log(LogLevels.Debug, txt);
    }

    /// <summary>Log(...) without a level is Debug, so it gets the Debug handler.</summary>
    public static void Log(ref DebugLogInterpolatedStringHandler handler)
    {
        if (handler.Enabled) Log(LogLevels.Debug, handler.GetTextAndClear());
    }

    public static void Log(Func<string> txtgen)
    {
        if (!IsEnabled(LogLevels.Debug)) return;
        Log(LogLevels.Debug, txtgen());
    }

    public static void LogDebug(string txt)
    {
        Log(LogLevels.Debug, txt);
    }

    // Batch 0-6: the interpolated-string overloads. The compiler binds LogDebug($"...") to
    // these in preference to the string overloads, and the handler's constructor decides
    // whether the interpolation runs at all — so a suppressed debug message costs a threshold
    // comparison instead of a full format. Call sites did not change.
    public static void LogDebug(ref DebugLogInterpolatedStringHandler handler)
    {
        if (handler.Enabled) Log(LogLevels.Debug, handler.GetTextAndClear());
    }

    public static void LogDebug(LogLevels lvl, Func<string> gen)
    {
        if (!IsEnabled(lvl)) return;
        Log(lvl, gen());
    }

    public static void LogTransport(string txt)
    {
        Log(LogLevels.Transport, txt);
    }

    public static void LogTransport(ref TransportLogInterpolatedStringHandler handler)
    {
        if (handler.Enabled) Log(LogLevels.Transport, handler.GetTextAndClear());
    }

    public static void LogTransport(Func<string> txtgen)
    {
        if (!IsEnabled(LogLevels.Transport)) return;
        Log(LogLevels.Transport, txtgen());
    }

    public static void LogDebugData(string txt)
    {
        Log(LogLevels.DebugData, txt);
    }

    public static void LogDebugData(ref DebugDataLogInterpolatedStringHandler handler)
    {
        if (handler.Enabled) Log(LogLevels.DebugData, handler.GetTextAndClear());
    }

    public static void LogDebugData(Func<string> txtgen)
    {
        if (!IsEnabled(LogLevels.DebugData)) return;
        Log(LogLevels.DebugData, txtgen());
    }

    public static void LogDebug(Func<string> txtgen)
    {
        if (!IsEnabled(LogLevels.Debug)) return;
        Log(LogLevels.Debug, txtgen());
    }

    public static void LogInformation(string txt)
    {
        Log(LogLevels.Information, txt);
    }

    public static void LogWarning(string txt)
    {
        Log(LogLevels.Warning, txt);
    }

    public static void LogWarning(Exception ex)
    {
        Log(LogLevels.Warning, $"Exception: {Unwrap(ex)}");
    }

    public static void LogWarning(string module, Exception ex)
    {
        Log(LogLevels.Warning, $"Exception ({module}): {Unwrap(ex)}");
    }

    /// <summary>
    ///     Batch 3-6 (docs/PRODUCTION-PLAN.md). <see cref="LogLevels.Error" /> has always been in
    ///     the enum and has always been selectable as <c>--log-level error</c>, but no helper
    ///     emitted at it — so that setting showed Critical only, and the whole level was
    ///     unreachable from library code. Added because the catch audit found failures that end a
    ///     transport for the life of the process, which Warning understates and Critical (a level
    ///     that passes every threshold, including <c>Nothing</c>) overstates.
    /// </summary>
    public static void LogError(string txt)
    {
        Log(LogLevels.Error, txt);
    }

    public static void LogError(Exception ex)
    {
        Log(LogLevels.Error, $"Exception: {Unwrap(ex)}");
    }

    public static void LogError(string module, Exception ex)
    {
        Log(LogLevels.Error, $"Exception ({module}): {Unwrap(ex)}");
    }

    public static void LogCritical(string txt)
    {
        Log(LogLevels.Critical, txt);
    }

    public static void LogCritical(Exception ex)
    {
        Log(LogLevels.Critical, $"Exception: {Unwrap(ex)}");
    }

    public static void LogCritical(string module, Exception ex)
    {
        Log(LogLevels.Critical, $"Exception ({module}): {Unwrap(ex)}");
    }

    private static readonly PeriodicAction _checkFileRotation = new(TickSpan.Minutes(1));
    private static readonly char[] TrimEndChars = new[] { '\r', '\n', ' ', '\t' };

    public static void Log(LogLevels level, string str)
    {
        if (level < LogLevel) return;

        var st = $"{DateTime.Now} /{Thread.CurrentThread.ManagedThreadId,3}/: {str.TrimEnd(TrimEndChars)}";

        lock (_lock)
        {
            if (LogToConsole) Console.WriteLine(st);
            if (LogToDebug) Debug.WriteLine(st);

            if (_store != null)
            {
                _checkFileRotation.Do(_store.CheckStoreRotation);
                _store.Log(st);
            }
        }
    }

    public static void Log(Exception ex)
    {
        LogWarning($"Exception: {Unwrap(ex)}");
    }

    public static void Log(string module, Exception ex)
    {
        LogWarning($"Exception ({module}): {Unwrap(ex)}");
    }

    public static void LogDebug(Exception ex)
    {
        if (!IsEnabled(LogLevels.Debug)) return;
        LogDebug($"Exception: {Unwrap(ex)}");
    }

    public static void LogDebug(string module, Exception ex)
    {
        if (!IsEnabled(LogLevels.Debug)) return;
        LogDebug($"Exception ({module}): {Unwrap(ex)}");
    }
}