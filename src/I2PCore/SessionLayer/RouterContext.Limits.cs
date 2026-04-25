using I2PCore.Utils;

namespace I2PCore.SessionLayer;

public partial class RouterContext
{
    /// <summary>
    ///     Bandwidth class letters per i2pd convention.
    ///     L=32KB, M=64KB, N=128KB, O=256KB, P=2048KB, X=unlimited
    /// </summary>
    public enum BandwidthClass
    {
        L = 32, // 12-48 KBps
        M = 64, // 48-64 KBps
        N = 128, // 64-128 KBps
        O = 256, // 128-256 KBps
        P = 2048, // 256-2048 KBps
        X = 0 // Unlimited (>2048 KBps)
    }

    // --- Bandwidth Limits ---

    private BandwidthClass _bandwidthClass = BandwidthClass.X;

    // Bandwidth limiters for inbound, outbound, and transit
    private Bandwidth _inboundBandwidth;
    private BandwidthLimiter _inboundLimiter;

    // --- Connection Limits ---
    private int _maxNtcp2InboundConnections = 2500;

    private int _maxNtcp2OutboundConnections = 2500;
    private Bandwidth _outboundBandwidth;
    private BandwidthLimiter _outboundLimiter;
    private Bandwidth _transitBandwidth;
    private BandwidthLimiter _transitLimiter;

    /// <summary>
    ///     Configured bandwidth class for this router.
    ///     Determines transit tunnel participation and published capabilities.
    /// </summary>
    public BandwidthClass ConfiguredBandwidth
    {
        get => _bandwidthClass;
        set
        {
            _bandwidthClass = value;
            UpdateBandwidthLimits();
            ClearCache();
        }
    }

    /// <summary>
    ///     Maximum inbound bandwidth in KBps.
    /// </summary>
    public int MaxInboundBandwidthKBps { get; private set; } = 256;

    /// <summary>
    ///     Maximum outbound bandwidth in KBps.
    /// </summary>
    public int MaxOutboundBandwidthKBps { get; private set; } = 256;

    /// <summary>
    ///     Percentage of bandwidth allocated to transit traffic (0-100).
    ///     Default is 80% per i2pd.
    /// </summary>
    public int TransitSharePercent { get; set; } = 80;

    /// <summary>
    ///     Maximum transit bandwidth in KBps, computed from total bandwidth and share.
    /// </summary>
    public int MaxTransitBandwidthKBps =>
        _bandwidthClass == BandwidthClass.X
            ? int.MaxValue
            : (int)_bandwidthClass * TransitSharePercent / 100;

    /// <summary>
    ///     Current number of running transit tunnels.
    /// </summary>
    public int CurrentTransitTunnelCount { get; set; }

    public int MaxNtcp2InboundConnections
    {
        get => _maxNtcp2InboundConnections;
        set
        {
            _maxNtcp2InboundConnections = value;
            ClearCache();
        }
    }

    public int MaxNtcp2OutboundConnections
    {
        get => _maxNtcp2OutboundConnections;
        set
        {
            _maxNtcp2OutboundConnections = value;
            ClearCache();
        }
    }

    public int MaxNtcp2Connections => MaxNtcp2InboundConnections + MaxNtcp2OutboundConnections;

    /// <summary>
    ///     Maximum number of concurrent SSU2 sessions.
    /// </summary>
    public int MaxSsu2Sessions { get; set; } = 2500;

    /// <summary>
    ///     Maximum number of transit tunnels this router will participate in.
    /// </summary>
    public int MaxTransitTunnels { get; set; } = 10000;

    private void UpdateBandwidthLimits()
    {
        var limitKBps = _bandwidthClass == BandwidthClass.X ? 0 : (int)_bandwidthClass;

        MaxInboundBandwidthKBps = limitKBps;
        MaxOutboundBandwidthKBps = limitKBps;

        if (_inboundBandwidth != null)
            _inboundLimiter = new BandwidthLimiter(_inboundBandwidth, limitKBps);
        if (_outboundBandwidth != null)
            _outboundLimiter = new BandwidthLimiter(_outboundBandwidth, limitKBps);

        // Transit limiter uses the transit share percentage
        var transitKBps = _bandwidthClass == BandwidthClass.X ? 0 : MaxTransitBandwidthKBps;
        if (_transitBandwidth == null) _transitBandwidth = new Bandwidth();
        _transitLimiter = new BandwidthLimiter(_transitBandwidth, transitKBps);

        Logging.LogInformation(
            $"RouterContext: Bandwidth class={_bandwidthClass}, " +
            $"limit={limitKBps}KBps, transit={MaxTransitBandwidthKBps}KBps");
    }

    /// <summary>
    ///     Initialize bandwidth tracking. Call once at router startup.
    /// </summary>
    public void InitializeBandwidthTracking()
    {
        _inboundBandwidth = new Bandwidth();
        _outboundBandwidth = new Bandwidth();
        UpdateBandwidthLimits();
    }

    /// <summary>
    ///     Check if an inbound message should be dropped due to bandwidth limit.
    /// </summary>
    public bool ShouldDropInbound()
    {
        return _inboundLimiter?.DropMessage() ?? false;
    }

    /// <summary>
    ///     Check if an outbound message should be dropped due to bandwidth limit.
    /// </summary>
    public bool ShouldDropOutbound()
    {
        return _outboundLimiter?.DropMessage() ?? false;
    }

    /// <summary>
    ///     Record inbound bytes for bandwidth tracking.
    /// </summary>
    public void RecordInboundBytes(int count)
    {
        _inboundBandwidth?.Measure(count);
    }

    /// <summary>
    ///     Record outbound bytes for bandwidth tracking.
    /// </summary>
    public void RecordOutboundBytes(int count)
    {
        _outboundBandwidth?.Measure(count);
    }

    /// <summary>
    ///     Check if a transit tunnel message should be dropped due to transit bandwidth limit.
    /// </summary>
    public bool ShouldDropTransit()
    {
        return _transitLimiter?.DropMessage() ?? false;
    }

    /// <summary>
    ///     Record transit bytes for bandwidth tracking.
    /// </summary>
    public void RecordTransitBytes(int count)
    {
        _transitBandwidth?.Measure(count);
    }

    /// <summary>
    ///     Get the router capability character for published RouterInfo.
    /// </summary>
    public char GetBandwidthCapChar()
    {
        return _bandwidthClass switch
        {
            BandwidthClass.L => 'L',
            BandwidthClass.M => 'M',
            BandwidthClass.N => 'N',
            BandwidthClass.O => 'O',
            BandwidthClass.P => 'P',
            BandwidthClass.X => 'X',
            _ => 'O'
        };
    }

    /// <summary>
    ///     Parse a bandwidth class string (single letter) into the enum.
    /// </summary>
    public static BandwidthClass ParseBandwidthClass(string s)
    {
        if (string.IsNullOrEmpty(s)) return BandwidthClass.O;
        return s.ToUpper()[0] switch
        {
            'L' => BandwidthClass.L,
            'M' => BandwidthClass.M,
            'N' => BandwidthClass.N,
            'O' => BandwidthClass.O,
            'P' => BandwidthClass.P,
            'X' => BandwidthClass.X,
            _ => BandwidthClass.O
        };
    }
}