using System;
using System.Threading;

namespace I2PCore.Utils;

public class Bandwidth
{
    private static readonly TickSpan AggregationWindow = TickSpan.Seconds(20);

    private static readonly float EmaAlphaMax = 0.6f;

    private readonly SemaphoreSlim UpdateGate = new(1, 1);
    private float AggregatedBitrate;
    private long AggregationWindowDataBytes;
    private TickCounter AggregationWindowStart = new();

    private long DataBytesField;
    private float EmaAlpha;
    private float EmaAlphaRes;

    public Bandwidth()
    {
        UpdateAlpha(0.2f);
    }

    public long DataBytes => DataBytesField;

    /// <summary>
    ///     Bitrate in bit / second
    /// </summary>
    public float Bitrate
    {
        get
        {
            var result = AggregatedBitrate * EmaAlpha + AggregationWindowBitrate() * EmaAlphaRes;
            BitrateMax = Math.Max(BitrateMax, result);
            return result;
        }
    }

    public float BitrateMax { get; private set; }

    private void UpdateAlpha(float v)
    {
        EmaAlpha = v;
        EmaAlphaRes = 1f - v;
    }

    public void Measure(long size)
    {
        Interlocked.Add(ref DataBytesField, size);
        Interlocked.Add(ref AggregationWindowDataBytes, size);

        if (UpdateGate.Wait(0))
            try
            {
                if (AggregationWindowStart.DeltaToNow > AggregationWindow) UpdateAggregatedBitrate();
            }
            finally
            {
                UpdateGate.Release();
            }
    }

    private void UpdateAggregatedBitrate()
    {
        var windowbitrate = AggregationWindowBitrate();
        AggregatedBitrate = AggregatedBitrate * EmaAlpha + windowbitrate * EmaAlphaRes;

        AggregationWindowDataBytes /= 2;
        AggregationWindowStart = TickCounter.Now - AggregationWindow / 2;

        if (EmaAlpha < EmaAlphaMax) UpdateAlpha(EmaAlpha + 0.05f);
    }

    private float AggregationWindowBitrate()
    {
        var delta = AggregationWindowStart.DeltaToNowMilliseconds / 1000f; // float seconds
        var windowbitrate = 8f * (AggregationWindowDataBytes / delta);
        return windowbitrate;
    }

    public override string ToString()
    {
        return $"{Bitrate:###,###,##0.0}Bps ({BitrateMax:#0.0}), a/w " +
               $"{AggregatedBitrate:###,###,##0.0} / {AggregationWindowBitrate():###,###,##0.0}.";
    }
}