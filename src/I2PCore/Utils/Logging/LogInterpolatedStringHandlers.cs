using System;
using System.Runtime.CompilerServices;

namespace I2PCore.Utils;

/// <summary>
///     Interpolated string handlers for the suppressed-by-default log levels.
///
///     Batch 0-1 removed the [Conditional("DEBUG")] attributes so debug logging is reachable in
///     a Release build. That left a cost: with a plain string parameter, `LogDebug($"...")`
///     builds the whole string at the call site and Log() throws it away when the level is
///     suppressed. At the default Information level that is 338 interpolated debug call sites
///     formatting on every call, much of it in per-message tunnel and transport paths.
///
///     A handler moves the decision in front of the formatting. The `out bool shouldAppend`
///     constructor parameter is the compiler's cue: when it comes back false, every
///     AppendLiteral/AppendFormatted call the interpolation would have made is skipped, so
///     nothing is rendered, boxed, or allocated. Call sites are unchanged — this is why the
///     approach was preferred over rewriting 338 of them into Func&lt;string&gt; lambdas.
///
///     The threshold is read once in the constructor rather than per-append, so a level change
///     racing with a log call cannot half-render a message.
/// </summary>
[InterpolatedStringHandler]
public ref struct DebugLogInterpolatedStringHandler
{
    private DefaultInterpolatedStringHandler _inner;

    public DebugLogInterpolatedStringHandler(
        int literalLength, int formattedCount, out bool shouldAppend )
    {
        shouldAppend = Logging.IsEnabled( Logging.LogLevels.Debug );
        Enabled = shouldAppend;
        _inner = shouldAppend
            ? new DefaultInterpolatedStringHandler( literalLength, formattedCount )
            : default;
    }

    internal bool Enabled { get; }

    public void AppendLiteral( string value )
    {
        _inner.AppendLiteral( value );
    }

    public void AppendFormatted<T>( T value )
    {
        _inner.AppendFormatted( value );
    }

    public void AppendFormatted<T>( T value, string format )
    {
        _inner.AppendFormatted( value, format );
    }

    public void AppendFormatted<T>( T value, int alignment )
    {
        _inner.AppendFormatted( value, alignment );
    }

    public void AppendFormatted<T>( T value, int alignment, string format )
    {
        _inner.AppendFormatted( value, alignment, format );
    }

    public void AppendFormatted( ReadOnlySpan<char> value )
    {
        _inner.AppendFormatted( value );
    }

    public void AppendFormatted( string value )
    {
        _inner.AppendFormatted( value );
    }

    internal string GetTextAndClear()
    {
        return _inner.ToStringAndClear();
    }
}

/// <summary>Transport-level counterpart of <see cref="DebugLogInterpolatedStringHandler" />.</summary>
[InterpolatedStringHandler]
public ref struct TransportLogInterpolatedStringHandler
{
    private DefaultInterpolatedStringHandler _inner;

    public TransportLogInterpolatedStringHandler(
        int literalLength, int formattedCount, out bool shouldAppend )
    {
        shouldAppend = Logging.IsEnabled( Logging.LogLevels.Transport );
        Enabled = shouldAppend;
        _inner = shouldAppend
            ? new DefaultInterpolatedStringHandler( literalLength, formattedCount )
            : default;
    }

    internal bool Enabled { get; }

    public void AppendLiteral( string value )
    {
        _inner.AppendLiteral( value );
    }

    public void AppendFormatted<T>( T value )
    {
        _inner.AppendFormatted( value );
    }

    public void AppendFormatted<T>( T value, string format )
    {
        _inner.AppendFormatted( value, format );
    }

    public void AppendFormatted<T>( T value, int alignment )
    {
        _inner.AppendFormatted( value, alignment );
    }

    public void AppendFormatted<T>( T value, int alignment, string format )
    {
        _inner.AppendFormatted( value, alignment, format );
    }

    public void AppendFormatted( ReadOnlySpan<char> value )
    {
        _inner.AppendFormatted( value );
    }

    public void AppendFormatted( string value )
    {
        _inner.AppendFormatted( value );
    }

    internal string GetTextAndClear()
    {
        return _inner.ToStringAndClear();
    }
}

/// <summary>DebugData-level counterpart of <see cref="DebugLogInterpolatedStringHandler" />.</summary>
[InterpolatedStringHandler]
public ref struct DebugDataLogInterpolatedStringHandler
{
    private DefaultInterpolatedStringHandler _inner;

    public DebugDataLogInterpolatedStringHandler(
        int literalLength, int formattedCount, out bool shouldAppend )
    {
        shouldAppend = Logging.IsEnabled( Logging.LogLevels.DebugData );
        Enabled = shouldAppend;
        _inner = shouldAppend
            ? new DefaultInterpolatedStringHandler( literalLength, formattedCount )
            : default;
    }

    internal bool Enabled { get; }

    public void AppendLiteral( string value )
    {
        _inner.AppendLiteral( value );
    }

    public void AppendFormatted<T>( T value )
    {
        _inner.AppendFormatted( value );
    }

    public void AppendFormatted<T>( T value, string format )
    {
        _inner.AppendFormatted( value, format );
    }

    public void AppendFormatted<T>( T value, int alignment )
    {
        _inner.AppendFormatted( value, alignment );
    }

    public void AppendFormatted<T>( T value, int alignment, string format )
    {
        _inner.AppendFormatted( value, alignment, format );
    }

    public void AppendFormatted( ReadOnlySpan<char> value )
    {
        _inner.AppendFormatted( value );
    }

    public void AppendFormatted( string value )
    {
        _inner.AppendFormatted( value );
    }

    internal string GetTextAndClear()
    {
        return _inner.ToStringAndClear();
    }
}
