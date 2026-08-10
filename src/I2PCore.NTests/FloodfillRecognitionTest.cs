using System;
using System.IO;
using I2PCore.Data;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using StringAssert = NUnit.Framework.Legacy.StringAssert;

namespace I2PTests;

/// <summary>
///     A router is a floodfill iff its RouterInfo options carry <c>caps</c> containing <c>f</c>,
///     and everything downstream of that — who we can ask for a LeaseSet, where we publish —
///     depends on reading it out of a real peer's RouterInfo correctly.
///
///     <para>
///         The fixture is a genuine i2pd 2.45.1 floodfill RouterInfo (<c>caps=Xf</c>), not one we
///         generated. A round trip through our own writer would agree with our own reader and
///         prove nothing — the same shape this plan has now hit eight times.
///     </para>
/// </summary>
[TestFixture]
public class FloodfillRecognitionTest
{
    private static I2PRouterInfo LoadFixture()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "TestData", "routerinfo_floodfill_i2pd.dat");
        Assert.IsTrue(File.Exists(path), $"fixture missing: {path}");

        var data = File.ReadAllBytes(path);
        Assert.Greater(data.Length, 0, "fixture is empty");

        return new I2PRouterInfo(new I2PBufferCursor(data), false);
    }

    [Test]
    public void WeReadTheCapsOfARealI2pdFloodfill()
    {
        var ri = LoadFixture();

        StringAssert.Contains("f", ri.Options["caps"],
            "i2pd publishes caps=Xf on a floodfill; if this is empty the option is not being " +
            "read from the router options mapping");
    }

    [Test]
    public void ARealI2pdFloodfillIsClassifiedAsOne()
    {
        var ri = LoadFixture();

        // The same predicate NetDb.RouterEntry.IsFloodfill applies. Asserted here on the value
        // rather than through NetDb, so a failure points at parsing rather than at storage.
        Assert.IsTrue(ri.Options["caps"].IndexOf('f') >= 0,
            $"caps was '{ri.Options["caps"]}'");
    }

    [Test]
    public void TheFixtureIsTheI2pdRouterInfoItClaimsToBe()
    {
        var ri = LoadFixture();

        // Guards against the fixture being silently replaced by something we generated.
        Assert.AreEqual("99", ri.Options["netId"], "fixture should be a netid 99 test router");
        StringAssert.StartsWith("0.9.", ri.Options["router.version"],
            "fixture should carry i2pd's router.version");
    }

    [Test]
    public void WeCanVerifyTheSignatureOfARealI2pdRouterInfo()
    {
        // NetDb.AddRouterInfo drops any RouterInfo it has not seen before whose signature it
        // cannot verify, so this is the gate every i2pd peer has to pass to enter our NetDb at
        // all -- and a floodfill that never enters is a floodfill we can never ask.
        var ri = LoadFixture();

        Assert.IsTrue(ri.VerifySignature(),
            "an i2pd RouterInfo must verify, or NetDb.AddRouterInfo silently discards the peer");
    }
}
