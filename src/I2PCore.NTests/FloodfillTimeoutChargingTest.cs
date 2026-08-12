using System;
using System.IO;
using System.Linq;
using System.Net;
using I2PCore;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-12 (docs/PRODUCTION-PLAN.md). One unanswered publish must cost a floodfill exactly
///     one timeout, and a publish we could not send must cost it nothing.
///
///     <para>
///         <c>CheckTimeouts</c> charges <c>FloodfillUpdateTimeout</c> for every outstanding request
///         that is not yet marked <c>TimedOut</c> — and the marking was done by the two
///         regeneration methods, after the charge. <c>TimeoutRegenerateRiUpdate</c> dereferenced
///         <c>list.Random()</c>, which batch 3-9 made legitimately null once the floodfill index is
///         empty, so it threw before marking anything but the first request. Everything still
///         unmarked was charged again on the next 5-second pass, for the 80 seconds the request
///         lives: about a dozen charges for one unanswered publish, against the five (versus two
///         successes) that make <c>RoutersStatistics</c> call a router inactive and sweep it out of
///         the index.
///     </para>
///     <para>
///         The exception also aborted the rest of the NetDb tick — the LeaseSet retries, the
///         pending-update retries, <c>ImportNetDbFiles</c> and the ident lookups all run after it —
///         so the one thing that could have put a floodfill back never ran while this was firing.
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class FloodfillTimeoutChargingTest
{
    private bool _originalBootstrapDisabled;
    private int _originalNetworkId;
    private string _skipReason;
    private string _tempDir;

    [OneTimeSetUp]
    public void IsolateStorage()
    {
        _skipReason = NetDb.Inst != null
            ? "another fixture already started NetDb in this process"
            : null;

        if (_skipReason != null) return;

        _tempDir = Path.Combine(Path.GetTempPath(), "i2p-fftmo-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);

        _originalNetworkId = I2PConstants.I2PNetworkId;
        _originalBootstrapDisabled = Bootstrap.Disabled;

        I2PConstants.I2PNetworkId = 3;
        Bootstrap.Disabled = true;

        StreamUtils.AppPathOverride = _tempDir;
        RouterContext.RouterSettingsFile = Path.Combine(_tempDir, "FfTimeoutTest.bin");
        RouterContext.Reset();

        NetDb.Start();
    }

    [OneTimeTearDown]
    public void RestoreProcessState()
    {
        if (_skipReason != null) return;

        try
        {
            NetDb.Stop();
        }
        catch
        {
            // Teardown of a store we created; a failure here must not mask a test result.
        }

        I2PConstants.I2PNetworkId = _originalNetworkId;
        Bootstrap.Disabled = _originalBootstrapDisabled;
        StreamUtils.AppPathOverride = null;
        RouterContext.Reset();

        try
        {
            if (_tempDir != null && Directory.Exists(_tempDir)) Directory.Delete(_tempDir, true);
        }
        catch
        {
        }
    }

    [SetUp]
    public void SkipIfShared()
    {
        if (_skipReason != null) Assert.Ignore(_skipReason);
    }

    /// <summary>
    ///     Registers a RouterInfo publish to <paramref name="ff" /> that was sent long enough ago
    ///     to have timed out. <c>TickCounter.Set</c> is the only backdating this needs — the
    ///     timeout is 20 seconds of monotonic time, not a wall clock a test could move.
    /// </summary>
    private static void OutstandingPublishThatExpired(FloodfillUpdater fu, I2PIdentHash ff, uint token)
    {
        var info = new FloodfillUpdater.FfUpdateRequestInfo(
            ff,
            token,
            RouterContext.Inst.MyRouterIdentity.IdentHash);

        // TimeDeltaMs is modular, so a start "before boot" still reads as exactly a minute ago.
        info.Start.Set(TickCounter.NowMilliseconds - 60000);

        fu.OutstandingRequests[token] = info;
    }

    /// <summary>A signed floodfill RouterInfo, as <c>FloodfillSelectionTest</c> builds them.</summary>
    private static I2PRouterInfo MakeFloodfill(int index)
    {
        var privSigning = new I2PSigningPrivateKey(
            new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519));
        var pubSigning = new I2PSigningPublicKey(privSigning);

        var priv = new I2PPrivateKey(new I2PCertificate(I2PKeyType.KeyTypes.X25519));
        var pub = new I2PPublicKey(priv);

        var addr = new I2PRouterAddress(IPAddress.Loopback, 29000 + index, 5, "NTCP2");
        addr.Options["s"] = FreenetBase64.Encode(new I2PByteBlock(pub.Key.ToByteArray()));
        addr.Options["v"] = "2";

        var options = new I2PMapping();
        options["caps"] = "Xf";
        options["netId"] = I2PConstants.I2PNetworkId.ToString();
        options["router.version"] = "0.9.69";

        return new I2PRouterInfo(
            new I2PRouterIdentity(pub, pubSigning),
            I2PDate.Now,
            new[] { addr },
            options,
            privSigning);
    }

    [Test]
    [Order(1)]
    public void WithNoFloodfillLeftAnUnansweredPublishIsStillChargedOnlyOnce()
    {
        var fu = NetDb.Inst.FloodfillUpdate;

        Assert.AreEqual(0, NetDb.Inst.FloodfillCount,
            "precondition: the index is empty, which is the state a run of unanswered publishes " +
            "produces and the state that made the retry throw");

        var first = new I2PIdentHash(true);
        var second = new I2PIdentHash(true);

        OutstandingPublishThatExpired(fu, first, 0x3C120001);
        OutstandingPublishThatExpired(fu, second, 0x3C120002);

        // Pre-fix this is a NullReferenceException out of list.Random(), and it takes the rest of
        // the NetDb tick with it.
        Assert.DoesNotThrow(() => fu.CheckTimeouts(),
            "a floodfill index with nothing in it is a legitimate answer, not a crash");

        // The 5-second pass, over and over, for as long as the request lives.
        for (var i = 0; i < 4; ++i) fu.CheckTimeouts();

        Assert.AreEqual(1, NetDb.Inst.Statistics[first].FloodfillUpdateTimeout,
            "one unanswered publish, one charge");
        Assert.AreEqual(1, NetDb.Inst.Statistics[second].FloodfillUpdateTimeout,
            "the second request was never marked, so every pass charged it again — five charges " +
            "of the eventual dozen, where five is already enough to be swept");
    }

    [Test]
    [Order(2)]
    public void APublishWeCouldNotSendIsNotWaitingForAReply()
    {
        var fu = NetDb.Inst.FloodfillUpdate;

        Assert.IsTrue(NetDb.Inst.AddRouterInfo(MakeFloodfill(1)), "precondition: a floodfill to retry to");
        Assert.AreEqual(1, NetDb.Inst.FloodfillCount);

        var ff = new I2PIdentHash(true);
        const uint token = 0x3C120003;
        OutstandingPublishThatExpired(fu, ff, token);

        // Neither the tunnel layer nor the transport layer is running here, which is also true of
        // a real router for the first moments after NetDb.Start().
        Assert.DoesNotThrow(() => fu.CheckTimeouts(),
            "a publish that cannot be sent must fail, not throw");

        var awaiting = fu.OutstandingRequests
            .Where(r => !r.Value.TimedOut)
            .ToArray();

        Assert.IsEmpty(awaiting,
            "a replacement that was never sent must not be registered — it would time out in " +
            "20 seconds and charge a floodfill for a message it never received. Registered: " +
            string.Join(", ", awaiting.Select(a => a.Value.ToString())));

        Assert.IsTrue(fu.OutstandingRequests.TryGetValue(token, out var original)
                      && original.TimedOut,
            "the original request stays marked, so no later pass charges it again");
    }

    /// <summary>
    ///     The structural half: charging a timeout and recording that it was charged are one
    ///     decision. Splitting them across methods is what let a request be charged repeatedly, so
    ///     pin them to one site. Confirmed to bite — the pre-fix file assigns <c>TimedOut</c> twice,
    ///     in neither case inside <c>CheckTimeouts</c>.
    /// </summary>
    [Test]
    public void TheTimeoutIsMarkedWhereItIsCharged()
    {
        var source = Path.Combine(SourceRoot(), "src", "I2PCore", "NetDb", "FloodfillUpdater.cs");
        Assert.IsTrue(File.Exists(source), $"source not found at {source}");

        // Strip line comments, so prose naming the assignment does not trip the scan.
        var code = File
            .ReadAllLines(source)
            .Select(l => l.Split("//")[0])
            .ToArray();

        var assignments = code
            .Select((Text, i) => (Line: i + 1, Text))
            .Where(l => l.Text.Contains("TimedOut = true"))
            .ToArray();

        Assert.AreEqual(1, assignments.Length,
            "TimedOut must be set in exactly one place. Found at: " +
            string.Join(", ", assignments.Select(a => a.Line)));

        var charge = Array.FindIndex(code, l => l.Contains("Statistics.FloodfillUpdateTimeout("));
        Assert.GreaterOrEqual(charge, 0, "the timeout charge itself has moved or been renamed");

        Assert.LessOrEqual(Math.Abs(assignments[0].Line - (charge + 1)), 3,
            $"the mark (line {assignments[0].Line}) must sit with the charge (line {charge + 1}); " +
            "anything that can run between them can charge the same request twice");
    }

    /// <summary>Walks up from the test binary to the repository root.</summary>
    private static string SourceRoot()
    {
        var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "i2p.sln"))) dir = dir.Parent;
        return dir?.FullName ?? TestContext.CurrentContext.TestDirectory;
    }
}
