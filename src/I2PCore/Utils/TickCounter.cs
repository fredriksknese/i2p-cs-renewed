using System;
using System.Text;

namespace I2PCore.Utils;

public class TickSpan : IEquatable<TickSpan>, IComparable<TickSpan>, IFormattable
{
    private static readonly TimeDivisionName[] _timeDivisions = new TimeDivisionName[]
    {
        new()
        {
            FormatCode = 'D',
            Label = "d",
            Milliseconds = 1000 * 60 * 60 * 24
        },
        new()
        {
            FormatCode = 'H',
            Label = "h",
            Milliseconds = 1000 * 60 * 60
        },
        new()
        {
            FormatCode = 'M',
            Label = "m",
            Milliseconds = 1000 * 60
        },
        new()
        {
            FormatCode = 'S',
            Label = "s",
            Milliseconds = 1000
        },
        new()
        {
            FormatCode = 'm',
            Label = "ms",
            Milliseconds = 1
        }
    };

    public readonly int Ticks;

    public TickSpan(int ticks)
    {
        Ticks = ticks;
    }

    public TickSpan(double ticks)
    {
        Ticks = (int)ticks;
    }

    public int ToMilliseconds => Ticks;
    public float ToSeconds => Ticks / 1000f;
    public float ToMinutes => Ticks / (60f * 1000f);
    public float ToHours => Ticks / (60f * 60f * 1000f);
    public float ToDays => Ticks / (24f * 60f * 60f * 1000f);

    /// <summary>
    ///     Generate a string with only selected time spans: "D" days, "H" hours, "M" minutes, "S" seconds, "m" milliseconds.
    /// </summary>
    public string ToString(string format, IFormatProvider formatprovider)
    {
        return DebugText(this, format);
    }

    public static TickSpan Milliseconds(int ms)
    {
        return new TickSpan(ms);
    }

    public static TickSpan Seconds(int s)
    {
        return new TickSpan(s * 1000);
    }

    public static TickSpan Seconds(double s)
    {
        return new TickSpan((int)(s * 1000));
    }

    public static TickSpan Minutes(int minutes)
    {
        return new TickSpan(minutes * 60 * 1000);
    }

    public static TickSpan Hours(int hours)
    {
        return new TickSpan(hours * 60 * 60 * 1000);
    }

    public static TickSpan Days(int days)
    {
        return new TickSpan(days * 24 * 60 * 60 * 1000);
    }

    public static string DebugText(TickSpan tickspan, string format = null)
    {
        var result = new StringBuilder();
        var reminder = tickspan.ToMilliseconds;

        foreach (var span in _timeDivisions)
        {
            var remove = reminder / span.Milliseconds;
            if (remove > 0 && (format?.Contains(span.FormatCode) ?? true))
            {
                result.AppendFormat("{0}{1}{2}",
                    result.Length == 0 ? "" : " ",
                    remove,
                    span.Label);
                reminder -= remove * span.Milliseconds;
            }
        }

        return result.ToString();
    }

    public override string ToString()
    {
        return $"TickSpan: {DebugText(this)}";
    }

    private class TimeDivisionName
    {
        public char FormatCode;
        public string Label;
        public int Milliseconds;
    }

    #region IEquatable<TickSpan> Members

    bool IEquatable<TickSpan>.Equals(TickSpan other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Ticks == other.Ticks;
    }

    public override bool Equals(object obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        var other = obj as TickSpan;
        if (other is null) return false;
        return Ticks == other.Ticks;
    }

    public override int GetHashCode()
    {
        return Ticks;
    }

    public static bool operator ==(TickSpan left, TickSpan right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        if (ReferenceEquals(left, right)) return true;
        return left.Ticks == right.Ticks;
    }

    public static bool operator !=(TickSpan left, TickSpan right)
    {
        if (left is null && right is null) return false;
        if (left is null || right is null) return true;
        if (ReferenceEquals(left, right)) return false;
        return left.Ticks != right.Ticks;
    }

    #endregion

    #region IComparable<TickSpan> Members

    int IComparable<TickSpan>.CompareTo(TickSpan other)
    {
        if (other is null) return 1;
        if (ReferenceEquals(this, other)) return 0;
        return Ticks.CompareTo(other.Ticks);
    }

    public static bool operator >(TickSpan left, TickSpan right)
    {
        if (left is null && !(right is null)) return false;
        if (!(left is null) && right is null) return true;
        if (ReferenceEquals(left, right)) return false;
        return left.Ticks > right.Ticks;
    }

    public static bool operator <(TickSpan left, TickSpan right)
    {
        if (left is null && !(right is null)) return true;
        if (!(left is null) && right is null) return false;
        if (ReferenceEquals(left, right)) return false;
        return left.Ticks < right.Ticks;
    }

    public static TickSpan operator +(TickSpan left, TickSpan right)
    {
        if (left is null || right is null) return null;
        return new TickSpan(left.Ticks + right.Ticks);
    }

    public static TickSpan operator -(TickSpan left, TickSpan right)
    {
        if (left is null || right is null) return null;
        return new TickSpan(left.Ticks - right.Ticks);
    }

    public static TickSpan operator *(TickSpan left, int multi)
    {
        if (left is null) return null;
        return new TickSpan(left.Ticks * multi);
    }

    public static TickSpan operator *(TickSpan left, double multi)
    {
        if (left is null) return null;
        return new TickSpan(left.Ticks * multi);
    }

    public static TickSpan operator /(TickSpan left, int divi)
    {
        if (left is null) return null;
        return new TickSpan(left.Ticks / divi);
    }

    public static TickSpan operator /(TickSpan left, double divi)
    {
        if (left is null) return null;
        return new TickSpan(left.Ticks / divi);
    }

    public static explicit operator TimeSpan(TickSpan tickspan)
    {
        if (tickspan is null) return default;
        return TimeSpan.FromMilliseconds((double)tickspan.Ticks);
    }

    #endregion
}

public class TickCounter : IComparable<TickCounter>
{
    public TickCounter()
    {
        SetNow();
    }

    public TickCounter(int value)
    {
        Ticks = value & int.MaxValue;
    }

    public int Ticks { get; private set; }

    public static int NowMilliseconds => Environment.TickCount & int.MaxValue;

    public static TickCounter Now => new(Environment.TickCount);

    public static TickCounter MaxDelta => new((int)(((long)Environment.TickCount + int.MaxValue / 2) & int.MaxValue));

    public int DeltaToNowMilliseconds => TimeDeltaMs(Environment.TickCount & int.MaxValue, Ticks);

    public int DeltaToNowSeconds => TimeDeltaMs(Environment.TickCount & int.MaxValue, Ticks) / 1000;

    public TickSpan DeltaToNow => TimeDelta(Now, this);

    public int CompareTo(TickCounter other)
    {
        if (other is null) return 1;
        if (ReferenceEquals(this, other)) return 0;
        return DeltaToNowMilliseconds.CompareTo(other.DeltaToNowMilliseconds);
    }

    public void SetNow()
    {
        Ticks = NowMilliseconds;
    }

    public void Set(int val)
    {
        Ticks = val & int.MaxValue;
    }

    public static TickSpan TimeDelta(TickCounter end, TickCounter start)
    {
        return new TickSpan(TimeDeltaMs(end.Ticks, start.Ticks));
    }

    // Taking care of counter wraparound and jitter.
    public static int TimeDeltaMs(int end, int start)
    {
        var delta = (end - start) & int.MaxValue;
        if (delta > int.MaxValue - 600000) return 0; // Jitter up to 10 minutes
        return delta;
    }

    public static TickSpan operator -(TickCounter left, TickCounter right)
    {
        if (left is null || right is null) throw new ArgumentException("Tickcounter op - null");
        return TimeDelta(left, right);
    }

    public static TickCounter operator -(TickCounter left, int right)
    {
        if (left is null) throw new ArgumentException("Tickcounter op - null");
        return new TickCounter(left.Ticks - right);
    }

    public static TickCounter operator +(TickCounter left, TickSpan span)
    {
        if (left is null || span is null) throw new ArgumentException("Tickcounter op - null");
        return new TickCounter(left.Ticks + span.Ticks);
    }

    public static TickCounter operator -(TickCounter left, TickSpan span)
    {
        if (left is null || span is null) throw new ArgumentException("Tickcounter op - null");
        return new TickCounter(left.Ticks - span.Ticks);
    }

    public override string ToString()
    {
        return $"delta {TickSpan.DebugText(DeltaToNow)}";
    }
}