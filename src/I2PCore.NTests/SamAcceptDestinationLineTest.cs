using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using StringAssert = NUnit.Framework.Legacy.StringAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-7 (docs/PRODUCTION-PLAN.md). Guards the SAM v3 STREAM ACCEPT contract from the
///     client side: after STREAM STATUS, a non-silent bridge writes the peer's destination and a
///     newline as the first bytes of the data stream, and only then the payload.
///
///     The bridge here is a plain TcpListener rather than i2pd, deliberately — the defect this
///     guards against is in how the integration harness *reads* an accepted stream, and it needs
///     no I2P network to reproduce. Before the fix, SAMHelper read only the status line, so
///     ReceiveDataAsync started inside the destination and returned the requested byte count with
///     every byte shifted. That is why the failure looked like data corruption in a transfer whose
///     length was exact — see TestSend5MB_I2pd2_To_I2pd3, which has no C# router in its path.
/// </summary>
[TestFixture]
public class SamAcceptDestinationLineTest
{
    // A standard destination is 387 bytes, which is 516 characters in I2P's base64 alphabet.
    private static readonly string FakePeerDestination =
        FreenetBase64.Encode(new I2PByteBlock(RandomNumberGenerator.GetBytes(387)));

    [Test]
    public async Task AnAcceptedStreamStartsWithThePeerDestinationAndThenThePayload()
    {
        var payload = RandomNumberGenerator.GetBytes(4096);

        using var bridge = new FakeSamAcceptBridge(FakePeerDestination, payload);
        bridge.Start();

        using var client = await SAMHelper.CreateAndHelloAsync("127.0.0.1", bridge.Port, 10_000);

        var peer = await client.StreamAcceptAsync("recv");
        Assert.AreEqual(FakePeerDestination, peer,
            "STREAM ACCEPT should report the destination the bridge sent");

        var received = await client.ReceiveDataAsync(payload.Length, CancellationToken.None);
        Assert.AreEqual(payload, received,
            "the payload must start after the destination line, not inside it");
    }

    [Test]
    public async Task ABridgeThatOmitsTheDestinationLineIsRejectedRatherThanSilentlyShifted()
    {
        // The pre-fix behaviour of our own SAM bridge: status, then straight into the payload.
        // The harness must notice, because the alternative is a byte-exact, content-wrong read.
        var payload = RandomNumberGenerator.GetBytes(4096);

        using var bridge = new FakeSamAcceptBridge(null, payload);
        bridge.Start();

        using var client = await SAMHelper.CreateAndHelloAsync("127.0.0.1", bridge.Port, 10_000);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.StreamAcceptAsync("recv"));
        StringAssert.Contains("destination", ex.Message);
    }

    /// <summary>
    ///     Minimal SAM v3 server: answers HELLO and STREAM ACCEPT, then plays the accepted-stream
    ///     head — optionally including the peer destination line — followed by the payload.
    /// </summary>
    private sealed class FakeSamAcceptBridge : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly byte[] _payload;
        private readonly string _peerDestination;

        public FakeSamAcceptBridge(string peerDestination, byte[] payload)
        {
            _peerDestination = peerDestination;
            _payload = payload;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        }

        public int Port { get; }

        /// <summary>Faults here surface as a hung read in the test, so keep it observable.</summary>
        public Task Serving { get; private set; }

        public void Dispose()
        {
            try
            {
                _listener.Stop();
            }
            catch
            {
                // The listener is torn down at the end of the test; a socket already closed by
                // the client is not a failure.
            }
        }

        public void Start()
        {
            Serving = Task.Run(ServeAsync);
        }

        private async Task ServeAsync()
        {
            using var client = await _listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();

            await ReadLineAsync(stream); // HELLO
            await WriteLineAsync(stream, "HELLO REPLY RESULT=OK VERSION=3.3");

            await ReadLineAsync(stream); // STREAM ACCEPT
            await WriteLineAsync(stream, "STREAM STATUS RESULT=OK");

            // A real bridge blocks here until a peer connects.
            await Task.Delay(50);

            if (_peerDestination is not null)
                await WriteLineAsync(stream, _peerDestination);

            await stream.WriteAsync(_payload);
            await stream.FlushAsync();

            // Hold the connection open until the client is done reading.
            await Task.Delay(2000);
        }

        private static async Task<string> ReadLineAsync(NetworkStream stream)
        {
            var sb = new StringBuilder();
            var one = new byte[1];

            while (await stream.ReadAsync(one) == 1 && one[0] != '\n')
                sb.Append((char)one[0]);

            return sb.ToString().TrimEnd('\r');
        }

        private static async Task WriteLineAsync(NetworkStream stream, string line)
        {
            var bytes = Encoding.ASCII.GetBytes(line + "\n");
            await stream.WriteAsync(bytes);
            await stream.FlushAsync();
        }
    }
}
