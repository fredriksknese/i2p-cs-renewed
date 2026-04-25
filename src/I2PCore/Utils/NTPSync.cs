using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace I2PCore.Utils;

/// <summary>
///     NTP time synchronization for the I2P router.
///     Ensures clock accuracy for tunnel and LeaseSet expiration.
/// </summary>
public class NTPSync : IDisposable
{
    private static readonly string[] DefaultServers =
    {
        "pool.ntp.org",
        "time.nist.gov",
        "time.google.com"
    };

    private readonly int _syncIntervalMs;
    private long _offsetMs;
    private bool _running;

    private Timer _syncTimer;

    public NTPSync(int syncIntervalHours = 24)
    {
        _syncIntervalMs = syncIntervalHours * 3600 * 1000;
    }

    public long ClockOffsetMs => Interlocked.Read(ref _offsetMs);
    public DateTime AdjustedUtcNow => DateTime.UtcNow.AddMilliseconds(ClockOffsetMs);

    public void Dispose()
    {
        Stop();
    }

    public void Start()
    {
        if (_running) return;
        _running = true;

        // Sync immediately, then on interval
        _syncTimer = new Timer(_ => DoSync(), null, 0, _syncIntervalMs);
    }

    public void Stop()
    {
        _running = false;
        _syncTimer?.Dispose();
    }

    private void DoSync()
    {
        foreach (var server in DefaultServers)
            try
            {
                var offset = QueryNTP(server);
                if (Math.Abs(offset) < 86400000) // Sanity: less than 1 day
                {
                    Interlocked.Exchange(ref _offsetMs, offset);
                    Logging.LogInformation($"NTP sync: offset={offset}ms from {server}");
                    return;
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"NTP sync failed for {server}: {ex.Message}");
            }
    }

    /// <summary>
    ///     Query NTP server and return clock offset in milliseconds
    /// </summary>
    private static long QueryNTP(string server)
    {
        var ntpData = new byte[48];
        ntpData[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.ReceiveTimeout = 5000;
        socket.SendTimeout = 5000;

        var addresses = Dns.GetHostAddresses(server);
        var endpoint = new IPEndPoint(addresses[0], 123);

        var t1 = DateTime.UtcNow;
        socket.Connect(endpoint);
        socket.Send(ntpData);
        socket.Receive(ntpData);
        var t4 = DateTime.UtcNow;

        // Extract transmit timestamp (bytes 40-47)
        var intPart = ((ulong)ntpData[40] << 24) | ((ulong)ntpData[41] << 16) |
                      ((ulong)ntpData[42] << 8) | ntpData[43];
        var fracPart = ((ulong)ntpData[44] << 24) | ((ulong)ntpData[45] << 16) |
                       ((ulong)ntpData[46] << 8) | ntpData[47];

        var ntpEpoch = new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var serverTime = ntpEpoch.AddSeconds(intPart).AddMilliseconds(fracPart * 1000.0 / 0x100000000L);

        // Simple offset calculation: (serverTime - (t1 + t4)/2)
        var localMidpoint = t1.AddMilliseconds((t4 - t1).TotalMilliseconds / 2);
        var offset = (long)(serverTime - localMidpoint).TotalMilliseconds;

        return offset;
    }
}