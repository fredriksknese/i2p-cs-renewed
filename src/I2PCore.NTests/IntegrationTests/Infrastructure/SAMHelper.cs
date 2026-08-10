using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PTests.IntegrationTests.Infrastructure;

/// <summary>
///     Utility class for SAM v3.3 protocol operations.
///     Handles session creation, stream connections, and data transfer
///     for integration tests.
/// </summary>
public class SAMHelper : IDisposable
{
    private TcpClient _client;
    private bool _disposed;
    private StreamReader _reader;
    private NetworkStream _stream;

    public SAMHelper(string host, int port)
    {
        Host = host;
        Port = port;
    }

    public string Host { get; }
    public int Port { get; }
    public bool IsConnected => _client?.Connected == true;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            _reader?.Dispose();
        }
        catch
        {
        }

        try
        {
            _stream?.Dispose();
        }
        catch
        {
        }

        try
        {
            _client?.Dispose();
        }
        catch
        {
        }
    }

    /// <summary>
    ///     Connect to the SAM bridge TCP port.
    /// </summary>
    public async Task ConnectAsync(int timeoutMs = 10000)
    {
        _client = new TcpClient();
        using var cts = new CancellationTokenSource(timeoutMs);
        await _client.ConnectAsync(Host, Port, cts.Token);
        _stream = _client.GetStream();
        // Don't set ReadTimeout - use CancellationToken in ReadLineAsync instead.
        // Socket-level SO_RCVTIMEO interferes with async reads even with a token.
        _stream.WriteTimeout = 10000;
        _reader = new StreamReader(_stream, Encoding.ASCII);
    }

    /// <summary>
    ///     Perform SAM HELLO handshake.
    ///     Returns the version string from the reply.
    /// </summary>
    public async Task<string> HelloAsync()
    {
        await SendLineAsync("HELLO VERSION MIN=3.0 MAX=3.3");
        var reply = await ReadLineAsync();

        if (!reply.Contains("RESULT=OK"))
            throw new InvalidOperationException($"SAM HELLO failed: {reply}");

        return reply;
    }

    /// <summary>
    ///     Create a SAM session with a transient destination.
    ///     Returns the destination base64 string.
    ///     Requests zero-hop tunnels (length=0) for private test networks where
    ///     only 1-2 peers exist and multi-hop tunnel construction is not possible.
    /// </summary>
    public async Task<string> CreateSessionAsync(
        string sessionId, string style = "STREAM",
        int inboundLength = 0, int outboundLength = 0,
        int inboundQuantity = 1, int outboundQuantity = 1,
        int timeoutMs = 30000,
        string additionalOptions = "")
    {
        var cmd = $"SESSION CREATE STYLE={style} ID={sessionId} DESTINATION=TRANSIENT" +
                  $" inbound.length={inboundLength} outbound.length={outboundLength}" +
                  $" inbound.quantity={inboundQuantity} outbound.quantity={outboundQuantity}";

        if (!string.IsNullOrEmpty(additionalOptions))
        {
            if (!additionalOptions.StartsWith(" ")) cmd += " ";
            cmd += additionalOptions;
        }

        await SendLineAsync(cmd);
        var reply = await ReadLineAsync(timeoutMs);

        if (!reply.Contains("RESULT=OK"))
            throw new InvalidOperationException($"SAM SESSION CREATE failed: {reply}");

        // Extract DESTINATION=<base64> from reply
        return ExtractValue(reply, "DESTINATION");
    }

    /// <summary>
    ///     Initiate STREAM CONNECT to a destination.
    ///     After success, the underlying TCP socket becomes a raw data pipe.
    /// </summary>
    public async Task StreamConnectAsync(
        string sessionId, string destination)
    {
        // Batch 3-8: callers hand this whatever SESSION CREATE returned, which is a private key
        // blob. CONNECT takes a *destination*; that both peers happen to tolerate the longer
        // form by parsing its prefix is not something to depend on. Normalise here, once.
        var dest = FreenetBase64.Encode(
            new I2PByteBlock(DestinationOf(destination).ToByteArray()));

        await SendLineAsync(
            $"STREAM CONNECT ID={sessionId} DESTINATION={dest}");
        var reply = await ReadLineAsync(120000);

        if (!reply.Contains("RESULT=OK"))
            throw new InvalidOperationException($"SAM STREAM CONNECT failed: {reply}");
    }

    /// <summary>
    ///     Wait for an incoming stream connection (STREAM ACCEPT).
    ///     Blocks until a connection arrives, and returns the peer's base64 destination.
    ///     After that, the underlying TCP socket is a raw data pipe.
    /// </summary>
    /// <remarks>
    ///     Batch 3-7 (docs/PRODUCTION-PLAN.md). Two lines arrive here, not one. STREAM STATUS
    ///     answers the command; then, when a peer connects, a SAM v3 bridge with SILENT=false
    ///     writes the peer's destination and a newline as the first bytes of the *data* stream
    ///     (i2pd: SAM.cpp, SAMSocket::HandleI2PAccept). This helper used to read only the
    ///     status, so every subsequent read started ~520 bytes into the destination line and
    ///     the payload came out shifted. Because the callers read a fixed byte count, that
    ///     surfaced as a byte-exact transfer with a mismatched SHA-256 — which is what
    ///     TestSend5MB_I2pd2_To_I2pd3 has been reporting, in a path with no C# router in it.
    /// </remarks>
    public async Task<string> StreamAcceptAsync(string sessionId)
    {
        await SendLineAsync($"STREAM ACCEPT ID={sessionId}");
        var reply = await ReadLineAsync(120000);

        if (!reply.Contains("RESULT=OK"))
            throw new InvalidOperationException($"SAM STREAM ACCEPT failed: {reply}");

        // Blocks until a peer connects. Same generous timeout the status read carried.
        var peerDest = await ReadLineAsync(120000);

        if (!LooksLikeDestination(peerDest))
            throw new InvalidOperationException(
                "SAM STREAM ACCEPT: expected the peer's destination as the first line of the " +
                $"stream, got {peerDest.Length} bytes: {peerDest[..Math.Min(64, peerDest.Length)]}");

        return peerDest;
    }

    /// <summary>
    ///     A destination is at least 516 base64 characters (387 bytes of identity). Checking the
    ///     shape rather than just "non-empty" is what makes a bridge that omits the line fail
    ///     here instead of downstream: without the line, this read returns whatever payload
    ///     precedes the first 0x0A byte, which is short and not base64.
    /// </summary>
    private static bool LooksLikeDestination(string s)
    {
        if (s.Length < 516) return false;

        foreach (var c in s)
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '~' || c == '='))
                return false;

        return true;
    }

    /// <summary>
    ///     Send raw bytes over the established stream.
    ///     Call only after STREAM CONNECT or STREAM ACCEPT succeeds.
    /// </summary>
    public async Task<string> NamingLookupAsync(string name, int timeoutMs = 30000)
    {
        await SendLineAsync($"NAMING LOOKUP NAME={name}");
        return await ReadLineAsync(timeoutMs);
    }

    public async Task SendDataAsync(byte[] data, CancellationToken ct = default)
    {
        const int chunkSize = 16384; // 16KB chunks
        var offset = 0;

        while (offset < data.Length)
        {
            ct.ThrowIfCancellationRequested();
            var remaining = data.Length - offset;
            var count = Math.Min(chunkSize, remaining);
            await _stream.WriteAsync(data, offset, count, ct);
            await _stream.FlushAsync(ct);
            offset += count;
        }
    }

    /// <summary>
    ///     Receive exactly expectedSize bytes from the stream.
    /// </summary>
    public async Task<byte[]> ReceiveDataAsync(
        int expectedSize, CancellationToken ct = default)
    {
        var buffer = new byte[expectedSize];
        var totalRead = 0;

        while (totalRead < expectedSize)
        {
            ct.ThrowIfCancellationRequested();
            var read = await _stream.ReadAsync(
                buffer, totalRead, expectedSize - totalRead, ct);
            if (read == 0)
                throw new EndOfStreamException(
                    $"Stream closed after {totalRead}/{expectedSize} bytes");
            totalRead += read;
        }

        return buffer;
    }

    /// <summary>
    ///     Get the underlying NetworkStream for direct I/O.
    /// </summary>
    public NetworkStream GetStream()
    {
        return _stream;
    }

    /// <summary>
    ///     Parse the destination out of what <c>SESSION CREATE</c> returned.
    /// </summary>
    /// <remarks>
    ///     Batch 3-8 (docs/PRODUCTION-PLAN.md). `SESSION STATUS ... DESTINATION=` carries the
    ///     session's **private keys**, not its destination — i2pd sends 884 base64 characters
    ///     where a destination is 524. The identity is the front of that blob, so it has to be
    ///     parsed out structurally; `SHA256` over the decoded string is the hash of a private
    ///     key blob, which no router in the network has ever heard of. Two NetDb tests did
    ///     exactly that and then asserted the network could find a LeaseSet for it — the
    ///     floodfills answered "Requested LeaseSet not found", correctly, for 150 seconds.
    /// </remarks>
    public static I2PDestination DestinationOf(string samSessionDestination)
    {
        var bytes = FreenetBase64.Decode(samSessionDestination);
        return new I2PDestination(new I2PBufferCursor(bytes));
    }

    /// <summary>
    ///     The ident hash of what <c>SESSION CREATE</c> returned — the value a LeaseSet lookup
    ///     is keyed by. See <see cref="DestinationOf" /> for why this is not a hash of the string.
    /// </summary>
    public static I2PIdentHash IdentHashOf(string samSessionDestination)
    {
        return DestinationOf(samSessionDestination).IdentHash;
    }

    /// <summary>
    ///     Generate deterministic test data using a seeded PRNG.
    /// </summary>
    public static byte[] GenerateTestData(int size, int seed = 42)
    {
        var rng = new Random(seed);
        var data = new byte[size];
        rng.NextBytes(data);
        return data;
    }

    /// <summary>
    ///     Compute SHA-256 hash of data for verification.
    /// </summary>
    public static byte[] ComputeSha256(byte[] data)
    {
        return SHA256.HashData(data);
    }

    /// <summary>
    ///     Compare two SHA-256 hashes for equality.
    /// </summary>
    public static bool HashesMatch(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (var i = 0; i < a.Length; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }

    /// <summary>
    ///     Create a new SAMHelper, connect, and perform HELLO.
    ///     Convenience method for tests.
    /// </summary>
    public static async Task<SAMHelper> CreateAndHelloAsync(
        // Batch 4-0g: was 120000. Six of these in one test is where TestBidirectional5MB's
        // 946 seconds came from -- each failed connect burned the full two minutes.
        string host, int port, int timeoutMs = 45_000)
    {
        var helper = new SAMHelper(host, port);
        var sw = Stopwatch.StartNew();
        Exception lastEx = null;

        while (sw.ElapsedMilliseconds < timeoutMs)
            try
            {
                await helper.ConnectAsync(5000);
                await helper.HelloAsync();
                return helper;
            }
            catch (Exception ex)
            {
                lastEx = ex;
                helper.Dispose();
                helper = new SAMHelper(host, port);
                await Task.Delay(1000);
            }

        throw new InvalidOperationException(
            $"Failed to connect to SAM bridge at {host}:{port} after {timeoutMs}ms", lastEx);
    }

    #region Private helpers

    private async Task SendLineAsync(string line)
    {
        var bytes = Encoding.ASCII.GetBytes(line + "\n");
        await _stream.WriteAsync(bytes);
        await _stream.FlushAsync();
        Logging.LogDebug($"[SAM → {Host}:{Port}] {line}");
    }

    private async Task<string> ReadLineAsync(int timeoutMs = 30000)
    {
        // Clear any socket-level read timeout — rely only on CancellationToken
        _client.ReceiveTimeout = 0;

        using var cts = new CancellationTokenSource(timeoutMs);
        var buf = new StringBuilder();
        var oneByte = new byte[1];

        Logging.LogInformation($"[SAM {Host}:{Port}] ReadLine waiting (timeout={timeoutMs}ms)");

        while (true)
        {
            cts.Token.ThrowIfCancellationRequested();
            var read = await _stream.ReadAsync(
                oneByte.AsMemory(0, 1), cts.Token);
            if (read == 0)
            {
                var partial = buf.ToString().TrimEnd('\r');
                if (partial.Length > 0)
                {
                    Logging.LogWarning(
                        $"[SAM ← {Host}:{Port}] EOF with partial: {partial}");
                    return partial;
                }

                throw new EndOfStreamException("SAM connection closed");
            }

            if (oneByte[0] == '\n')
                break;
            buf.Append((char)oneByte[0]);
        }

        var line = buf.ToString().TrimEnd('\r');
        Logging.LogInformation($"[SAM ← {Host}:{Port}] {line}");
        return line;
    }

    private static string ExtractValue(string reply, string key)
    {
        var prefix = key + "=";
        var idx = reply.IndexOf(prefix, StringComparison.Ordinal);
        if (idx < 0) return null;

        var start = idx + prefix.Length;
        var end = reply.IndexOf(' ', start);
        if (end < 0) end = reply.Length;

        return reply.Substring(start, end - start);
    }

    #endregion
}