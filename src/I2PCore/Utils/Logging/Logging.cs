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

    public static void Log(Func<string> txtgen)
    {
        if (!IsEnabled(LogLevels.Debug)) return;
        Log(LogLevels.Debug, txtgen());
    }

    public static void LogDebug(string txt)
    {
        Log(LogLevels.Debug, txt);
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

    public static void LogTransport(Func<string> txtgen)
    {
        if (!IsEnabled(LogLevels.Transport)) return;
        Log(LogLevels.Transport, txtgen());
    }

    public static void LogDebugData(string txt)
    {
        Log(LogLevels.DebugData, txt);
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