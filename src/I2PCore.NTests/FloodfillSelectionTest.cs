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
using CollectionAssert = NUnit.Framework.Legacy.CollectionAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-9 (docs/PRODUCTION-PLAN.md). A request for a floodfill must never be answered with
///     a router that is not one.
///
///     <para>
///         <c>GetRandomRouter</c> took a roulette argument that did not constrain its answer: the
///         <c>exploratory</c> branch drew from every known router regardless, and both fallbacks
///         did the same whenever the roulette was empty. Since <c>FloodfillUpdater</c> asks with
///         <c>exploratory: true</c>, a router that knew no floodfills published its LeaseSets to
///         arbitrary peers — which discard them — while logging "Publishing LS to ECIES FF [x]".
///         From every other router in the network that is indistinguishable from a destination
///         whose LeaseSet cannot be found, and it is what i2pd reported for ours.
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class FloodfillSelectionTest
{
    private string _skipReason;
    private string _tempDir;
    private int _originalNetworkId;
    private bool _originalBootstrapDisabled;

    [OneTimeSetUp]
    public void IsolateStorage()
    {
        _skipReason = NetDb.Inst != null
            ? "another fixture already started NetDb in this process"
            : null;

        if (_skipReason != null) return;

        _tempDir = Path.Combine(Path.GetTempPath(), "i2p-ffsel-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);

        _originalNetworkId = I2PConstants.I2PNetworkId;
        _originalBootstrapDisabled = Bootstrap.Disabled;

        I2PConstants.I2PNetworkId = 3;
        Bootstrap.Disabled = true;

        StreamUtils.AppPathOverride = _tempDir;
        RouterContext.RouterSettingsFile = Path.Combine(_tempDir, "FfSelTest.bin");
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
    ///     A signed RouterInfo with an NTCP2 address that passes the reachability filters in
    ///     <c>GetRandomRouter</c> — host, and the <c>s</c> option NTCP2 requires.
    /// </summary>
    private static I2PRouterInfo MakeRouter(bool floodfill, int index)
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
        // The only thing that makes a router a floodfill: 'f' in caps. i2pd publishes "Xf".
        options["caps"] = floodfill ? "Xf" : "X";
        options["netId"] = I2PConstants.I2PNetworkId.ToString();
        options["router.version"] = "0.9.57";

        return new I2PRouterInfo(
            new I2PRouterIdentity(pub, pubSigning),
            I2PDate.Now,
            new[] { addr },
            options,
            privSigning);
    }

    private static int AddRouters(int floodfills, int nonFloodfills)
    {
        var added = 0;

        for (var i = 0; i < floodfills; ++i)
            if (NetDb.Inst.AddRouterInfo(MakeRouter(true, i)))
                added++;

        for (var i = 0; i < nonFloodfills; ++i)
            if (NetDb.Inst.AddRouterInfo(MakeRouter(false, 100 + i)))
                added++;

        return added;
    }

    [Test]
    [Order(1)]
    public void WithNoFloodfillsKnownWeReturnNothingRatherThanSomeOtherRouter()
    {
        AddRouters(0, 6);

        Assert.AreEqual(0, NetDb.Inst.FloodfillCount, "precondition: no floodfills known");
        Assert.Greater(NetDb.Inst.RouterCount, 0, "precondition: other routers are known");

        // exploratory: true is what FloodfillUpdater asks with, and was the path that ignored
        // the floodfill roulette entirely.
        Assert.IsNull(NetDb.Inst.GetRandomFloodfillRouter(true),
            "a router that is not a floodfill is a wrong answer, not a fallback");
        Assert.IsNull(NetDb.Inst.GetRandomFloodfillRouter(false));

        CollectionAssert.IsEmpty(NetDb.Inst.GetRandomFloodfillRouter(true, 20).ToArray(),
            "the list form must not pad itself with non-floodfills");
    }

    [Test]
    [Order(2)]
    public void EveryFloodfillWeHandOutIsActuallyAFloodfill()
    {
        AddRouters(3, 6);

        Assert.AreEqual(3, NetDb.Inst.FloodfillCount, "precondition: three floodfills known");

        foreach (var exploratory in new[] { true, false })
            for (var i = 0; i < 40; ++i)
            {
                var hash = NetDb.Inst.GetRandomFloodfillRouter(exploratory);
                if (hash is null) continue;

                var ri = NetDb.Inst[hash];
                Assert.IsNotNull(ri, $"selected {hash.Id32Short} is not in the NetDb");
                Assert.GreaterOrEqual(ri.Options["caps"].IndexOf('f'), 0,
                    $"selected {hash.Id32Short} has caps '{ri.Options["caps"]}', which is not a floodfill " +
                    $"(exploratory={exploratory})");
            }
    }
}
