using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.Streaming;
using I2PCore.Utils;

namespace I2PCore.Client;

public class AddressBook
{
    private const string DefaultHostsFile = "hosts.txt";
    private const int SubscriptionTimeoutMs = 60_000;
    private const int InitialWaitForTunnelsMs = 120_000; // Wait up to 2 min for tunnels
    private static readonly TickSpan DefaultRefreshInterval = TickSpan.Hours(12);

    private readonly ConcurrentDictionary<string, I2PDestination> Hosts = new(
        StringComparer.OrdinalIgnoreCase);

    private readonly string HostsFilePath;
    private readonly PeriodicAction RefreshAction;
    private readonly object SubscriptionLock = new();

    private readonly List<SubscriptionInfo> Subscriptions = new();

    // Shared destination for making outbound I2P connections
    private ClientDestination _fetchDestination;
    private StreamingDestination _fetchStreaming;
    private Thread RefreshThread;

    private volatile bool Running;

    public AddressBook() : this(DefaultHostsFile)
    {
    }

    public AddressBook(string hostsFilePath) : this(hostsFilePath, DefaultRefreshInterval)
    {
    }

    public AddressBook(string hostsFilePath, TickSpan refreshInterval)
    {
        HostsFilePath = hostsFilePath;
        RefreshAction = new PeriodicAction(refreshInterval, true);
    }

    public int Count => Hosts.Count;

    /// <summary>
    ///     Look up a .i2p hostname and return the corresponding destination,
    ///     or null if not found. For .b32.i2p addresses, attempts a NetDb
    ///     lease set lookup via the ident hash encoded in the address.
    /// </summary>
    public I2PDestination Lookup(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname)) return null;

        hostname = hostname.Trim().ToLowerInvariant();

        // Handle .b32.i2p addresses through NetDb
        if (hostname.EndsWith(".b32.i2p", StringComparison.Ordinal)) return LookupBlinded(hostname);

        // Ensure .i2p suffix for standard lookups
        if (!hostname.EndsWith(".i2p", StringComparison.Ordinal)) hostname += ".i2p";

        Hosts.TryGetValue(hostname, out var dest);
        return dest;
    }

    /// <summary>
    ///     Resolve a .b32.i2p address by computing the ident hash and
    ///     looking up the lease set in the NetDb.
    /// </summary>
    private I2PDestination LookupBlinded(string b32Address)
    {
        try
        {
            var hash = new I2PIdentHash(b32Address);
            var ls = NetDb.Inst?.FindLeaseSet(hash);
            return ls?.Destination;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"AddressBook: Failed to resolve b32 address '{b32Address}': {ex.Message}");
            return null;
        }
    }

    /// <summary>
    ///     Add or update a hostname-to-destination mapping.
    /// </summary>
    public void Add(string hostname, I2PDestination destination)
    {
        if (string.IsNullOrWhiteSpace(hostname) || destination is null) return;

        hostname = hostname.Trim().ToLowerInvariant();
        Hosts[hostname] = destination;
    }

    /// <summary>
    ///     Remove a hostname from the address book.
    /// </summary>
    public bool Remove(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname)) return false;
        return Hosts.TryRemove(hostname.Trim().ToLowerInvariant(), out _);
    }

    /// <summary>
    ///     Register a subscription URL for periodic host list downloads.
    ///     URLs should be http://hostname.i2p/path format.
    /// </summary>
    public void AddSubscription(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return;

        lock (SubscriptionLock)
        {
            if (Subscriptions.All(s => s.Url != url)) Subscriptions.Add(new SubscriptionInfo { Url = url });
        }
    }

    /// <summary>
    ///     Remove a previously registered subscription URL.
    /// </summary>
    public void RemoveSubscription(string url)
    {
        lock (SubscriptionLock)
        {
            Subscriptions.RemoveAll(s => s.Url == url);
        }
    }

    /// <summary>
    ///     Load hosts from the hosts.txt file on disk.
    ///     Format: hostname=base64destination (one per line).
    /// </summary>
    public void Load()
    {
        if (!File.Exists(HostsFilePath))
        {
            Logging.LogInformation($"AddressBook: Hosts file '{HostsFilePath}' not found, starting empty.");
            return;
        }

        var count = 0;

        try
        {
            foreach (var line in File.ReadAllLines(HostsFilePath))
                if (ParseHostLine(line))
                    ++count;

            Logging.LogInformation($"AddressBook: Loaded {count} hosts from '{HostsFilePath}'.");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"AddressBook: Error loading hosts file: {ex.Message}");
        }
    }

    /// <summary>
    ///     Save all current hostname mappings to the hosts.txt file.
    /// </summary>
    public void Save()
    {
        try
        {
            var sb = new StringBuilder();

            foreach (var kvp in Hosts)
            {
                var destBytes = kvp.Value.ToByteArray();
                var b64 = FreenetBase64.Encode(new I2PByteBlock(destBytes));
                sb.AppendLine($"{kvp.Key}={b64}");
            }

            File.WriteAllText(HostsFilePath, sb.ToString());
            Logging.LogInformation($"AddressBook: Saved {Hosts.Count} hosts to '{HostsFilePath}'.");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"AddressBook: Error saving hosts file: {ex.Message}");
        }
    }

    /// <summary>
    ///     Start periodic background refresh of subscriptions.
    /// </summary>
    public void Start()
    {
        if (Running) return;

        Running = true;
        Load();

        RefreshThread = new Thread(RefreshLoop)
        {
            Name = "AddressBook",
            IsBackground = true
        };
        RefreshThread.Start();
    }

    /// <summary>
    ///     Stop background refresh and save hosts to disk.
    /// </summary>
    public void Stop()
    {
        Running = false;
        Save();

        try
        {
            RefreshThread?.Join(5000);
        }
        catch (ThreadInterruptedException)
        {
            // Expected during shutdown
        }

        RefreshThread = null;
        CleanupFetchDestination();
    }

    private void RefreshLoop()
    {
        // Wait for the router to be ready before attempting I2P fetches
        WaitForRouter();

        while (Running)
            try
            {
                RefreshAction.Do(RefreshSubscriptions);
                Thread.Sleep(1000);
            }
            catch (ThreadInterruptedException)
            {
                break;
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"AddressBook: Refresh loop error: {ex.Message}");
            }
    }

    private void WaitForRouter()
    {
        // Wait up to 2 minutes for the router to start and establish tunnels
        var deadline = Environment.TickCount64 + InitialWaitForTunnelsMs;
        while (Running && Environment.TickCount64 < deadline)
        {
            if (Router.Started)
            {
                // Give tunnels a bit more time to establish
                Thread.Sleep(10_000);
                return;
            }

            Thread.Sleep(1000);
        }
    }

    /// <summary>
    ///     Ensure we have a streaming destination for making outbound HTTP connections
    ///     over I2P.
    /// </summary>
    private bool EnsureFetchDestination()
    {
        if (_fetchDestination != null && _fetchStreaming != null)
            return true;

        if (!Router.Started)
            return false;

        try
        {
            var destInfo = new I2PDestinationInfo(
                I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);

            _fetchDestination = Router.CreateDestination(destInfo, false, out _);

            var destBytes = destInfo.Destination.ToByteArray();
            _fetchStreaming = new StreamingDestination(destInfo.Destination,
                destInfo.PrivateSigningKey, destBytes);
            _fetchStreaming.SetSendCallback((dest, data) => { _fetchDestination.Send(dest, data); });

            _fetchDestination.DataReceived += (dest, data, sender) =>
            {
                _fetchStreaming.HandleDataMessagePayload(data.ToByteArray(), sender);
            };

            return true;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"AddressBook: Failed to create fetch destination: {ex.Message}");
            return false;
        }
    }

    private void CleanupFetchDestination()
    {
        _fetchStreaming?.Dispose();
        _fetchStreaming = null;

        if (_fetchDestination != null)
        {
            _fetchDestination.Shutdown();
            _fetchDestination = null;
        }
    }

    private void RefreshSubscriptions()
    {
        List<SubscriptionInfo> subs;

        lock (SubscriptionLock)
        {
            subs = new List<SubscriptionInfo>(Subscriptions);
        }

        foreach (var sub in subs)
            try
            {
                FetchSubscriptionViaI2P(sub);
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"AddressBook: Subscription fetch failed for '{sub.Url}': {ex.Message}");
            }

        Save();
    }

    /// <summary>
    ///     Fetch a subscription host list through I2P streaming.
    ///     Matches i2pd's AddressBookSubscription::MakeRequest() flow.
    /// </summary>
    private void FetchSubscriptionViaI2P(SubscriptionInfo sub)
    {
        if (!Uri.TryCreate(sub.Url, UriKind.Absolute, out var uri))
        {
            Logging.LogWarning($"AddressBook: Invalid subscription URL: {sub.Url}");
            return;
        }

        var hostname = uri.Host.ToLowerInvariant();
        var path = uri.PathAndQuery;
        if (string.IsNullOrEmpty(path)) path = "/";

        // Step 1: Resolve the subscription host to an I2P destination
        var dest = Lookup(hostname);
        if (dest == null)
        {
            Logging.LogDebug($"AddressBook: Cannot resolve subscription host '{hostname}' - not in address book yet");
            return;
        }

        // Step 2: Ensure we have a streaming destination
        if (!EnsureFetchDestination())
        {
            Logging.LogDebug("AddressBook: Router not ready for I2P fetch");
            return;
        }

        Logging.LogInformation($"AddressBook: Downloading hosts from {hostname} via I2P");

        // Step 3: Create I2P stream to the subscription host
        I2PStream stream;
        try
        {
            stream = _fetchStreaming.CreateStream(dest);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"AddressBook: Failed to connect to {hostname}: {ex.Message}");
            return;
        }

        // Step 4: Build and send HTTP GET request
        var request = new StringBuilder();
        request.Append($"GET {path} HTTP/1.1\r\n");
        request.Append($"Host: {hostname}\r\n");
        request.Append("User-Agent: Wget/1.11.4\r\n");
        request.Append("Accept-Encoding: identity\r\n");
        request.Append("Connection: close\r\n");

        if (!string.IsNullOrEmpty(sub.ETag))
            request.Append($"If-None-Match: {sub.ETag}\r\n");

        if (!string.IsNullOrEmpty(sub.LastModified))
            request.Append($"If-Modified-Since: {sub.LastModified}\r\n");

        request.Append("\r\n");

        stream.Send(Encoding.ASCII.GetBytes(request.ToString()));

        // Step 5: Collect response with timeout
        var responseData = new List<byte>();
        var done = new ManualResetEventSlim(false);

        stream.DataReceived += (s, data) =>
        {
            lock (responseData)
            {
                responseData.AddRange(data);
            }
        };

        stream.StreamClosed += s => { done.Set(); };

        if (!done.Wait(SubscriptionTimeoutMs))
        {
            Logging.LogWarning($"AddressBook: Subscription request to {hostname} timed out");
            try
            {
                stream.Close();
            }
            catch
            {
            }

            return;
        }

        byte[] rawResponse;
        lock (responseData)
        {
            rawResponse = responseData.ToArray();
        }

        if (rawResponse.Length == 0)
        {
            Logging.LogDebug($"AddressBook: Empty response from {hostname}");
            return;
        }

        // Step 6: Parse HTTP response
        var responseStr = Encoding.ASCII.GetString(rawResponse);
        var headerEnd = responseStr.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerEnd < 0)
        {
            Logging.LogWarning($"AddressBook: Incomplete HTTP response from {hostname}");
            return;
        }

        var headerSection = responseStr.Substring(0, headerEnd);
        var body = responseStr.Substring(headerEnd + 4);

        // Parse status line
        var statusLine = headerSection.Split(new[] { "\r\n" }, StringSplitOptions.None)[0];
        var statusParts = statusLine.Split(' ', 3);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], out var statusCode))
        {
            Logging.LogWarning($"AddressBook: Invalid HTTP status line from {hostname}: {statusLine}");
            return;
        }

        if (statusCode == 304)
        {
            Logging.LogInformation($"AddressBook: No updates from {hostname} (304 Not Modified)");
            return;
        }

        if (statusCode != 200)
        {
            Logging.LogWarning($"AddressBook: HTTP {statusCode} from {hostname}");
            return;
        }

        // Extract ETag and Last-Modified for future conditional requests
        foreach (var headerLine in headerSection.Split(new[] { "\r\n" }, StringSplitOptions.None))
            if (headerLine.StartsWith("ETag:", StringComparison.OrdinalIgnoreCase))
                sub.ETag = headerLine.Substring(5).Trim();
            else if (headerLine.StartsWith("Last-Modified:", StringComparison.OrdinalIgnoreCase))
                sub.LastModified = headerLine.Substring(14).Trim();

        // Step 7: Parse hosts from body
        var count = 0;
        foreach (var line in body.Split('\n'))
            if (ParseHostLine(line))
                ++count;

        Logging.LogInformation($"AddressBook: Fetched {count} hosts from {hostname} via I2P");
    }

    /// <summary>
    ///     Parse a single "hostname=base64destination" line.
    ///     Returns true if a valid entry was added.
    /// </summary>
    private bool ParseHostLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return false;

        var trimmed = line.Trim();
        if (trimmed.StartsWith("#", StringComparison.Ordinal)) return false;
        if (trimmed.StartsWith(";", StringComparison.Ordinal)) return false;

        var eqIndex = trimmed.IndexOf('=');
        if (eqIndex <= 0 || eqIndex >= trimmed.Length - 1) return false;

        var hostname = trimmed.Substring(0, eqIndex).Trim().ToLowerInvariant();
        var b64Data = trimmed.Substring(eqIndex + 1).Trim();

        try
        {
            var decoded = FreenetBase64.Decode(b64Data);
            var buf = new I2PBufferCursor(decoded);
            var dest = new I2PDestination(buf);
            Hosts[hostname] = dest;
            return true;
        }
        catch (Exception)
        {
            Logging.LogDebug($"AddressBook: Skipping malformed entry for '{hostname}'.");
            return false;
        }
    }

    /// <summary>
    ///     Tracks per-subscription state including ETag/Last-Modified for
    ///     conditional HTTP requests, matching i2pd's AddressBookSubscription.
    /// </summary>
    private class SubscriptionInfo
    {
        public string Url { get; set; }
        public string ETag { get; set; }
        public string LastModified { get; set; }
    }
}