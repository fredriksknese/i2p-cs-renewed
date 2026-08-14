using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 3-18 (docs/PRODUCTION-PLAN.md). A client that asks for zero hops must get a
///     zero-hop tunnel, and one client's failure must not deny tunnels to every other client.
/// </summary>
/// <remarks>
///     <c>inbound.length=0</c> is a legitimate I2CP/SAM option, and the integration fixture asks
///     for it deliberately — <c>SAMHelper.CreateSessionAsync</c> defaults both lengths to 0
///     because a private network of two routers cannot build a multi-hop tunnel at all.
///     <c>ClientTunnelProvider</c> passed the hop count straight to
///     <c>Tunnel.CreateInboundTunnelChain</c>, which asks NetDb for zero routers and gets
///     <c>ArgumentException: Hops must be &gt; 0</c>.
///     <para>
///     It threw <b>234 times in the 3-17 CI run</b>, and because the throw escaped the
///     <c>foreach</c> over clients, every client after it in the same pass got nothing either —
///     on every pass, for the whole run. Both halves are guarded here, because fixing only the
///     zero-hop case would leave the amplifier in place for the next client that cannot be
///     served.
///     </para>
///     <para>
///     These are source scans. What is wrong in both cases is <i>where</i> code sits — a guard
///     ahead of a call, and a try inside a loop rather than around it — which is a property of
///     shape, not of behaviour at any one input. Standing a ClientTunnelProvider up would also
///     need a live RouterContext, TransportProvider and NetDb; batches 3-11, 3-12, 3-14 and 6-1
///     guard placement the same way.
///     </para>
/// </remarks>
[TestFixture]
public class ZeroHopClientTunnelTest
{
    private static string SourceRoot()
    {
        var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "i2p.sln"))) dir = dir.Parent;
        return dir?.FullName ?? TestContext.CurrentContext.TestDirectory;
    }

    private static string StripComments(string source)
    {
        var noBlock = Regex.Replace(source, @"/\*.*?\*/", "", RegexOptions.Singleline);

        return string.Join("\n", noBlock.Split('\n').Select(line =>
        {
            var cut = line.IndexOf("//", StringComparison.Ordinal);
            return cut >= 0 ? line[..cut] : line;
        }));
    }

    private static string Provider()
    {
        return StripComments(File.ReadAllText(Path.Combine(
            SourceRoot(), "src", "I2PCore", "TunnelLayer", "ClientTunnelProvider.cs")));
    }

    private static string Method(string source, string signature)
    {
        var m = Regex.Match(source,
            signature + @"\s*\([^)]*\)\s*\{(?<body>.*?)\n    \}", RegexOptions.Singleline);

        ClassicAssert.IsTrue(m.Success, $"{signature} not found in ClientTunnelProvider");
        return m.Groups["body"].Value;
    }

    [Test]
    public void AZeroHopInboundClientNeverReachesTheChainBuilder()
    {
        var body = Method(Provider(), @"InboundTunnel CreateInboundTunnel");

        var guard = body.IndexOf("InboundTunnelHopCount <= 0", StringComparison.Ordinal);
        var chain = body.IndexOf("CreateInboundTunnelChain", StringComparison.Ordinal);

        ClassicAssert.Greater(guard, -1,
            "a client asking for zero hops must be routed to a zero-hop tunnel");
        ClassicAssert.Greater(chain, guard,
            "the zero-hop check must come before the chain builder, which throws on 0 hops");
    }

    [Test]
    public void AZeroHopOutboundClientNeverReachesTheChainBuilder()
    {
        var body = Method(Provider(), @"OutboundTunnel CreateOutboundTunnel");

        var guard = body.IndexOf("OutboundTunnelHopCount <= 0", StringComparison.Ordinal);
        var chain = body.IndexOf("CreateOutboundTunnelChain", StringComparison.Ordinal);

        ClassicAssert.Greater(guard, -1);
        ClassicAssert.Greater(chain, guard);
    }

    /// <summary>
    ///     The zero-hop tunnels are built the way TunnelPool.CreateFallbackTunnel builds one —
    ///     an empty hop list and the ZeroHop types — and not through TunnelMgr.CreateTunnel,
    ///     which returns null for a config with no hops and would silently produce no tunnel.
    /// </summary>
    [Test]
    public void ZeroHopTunnelsAreConstructedDirectlyAndEstablished()
    {
        var source = Provider();

        foreach (var (method, type) in new[]
                 {
                     (@"InboundTunnel CreateZeroHopInboundTunnel", "ZeroHopTunnel"),
                     (@"OutboundTunnel CreateZeroHopOutboundTunnel", "ZeroHopOutboundTunnel")
                 })
        {
            var body = Method(source, method);

            StringAssert.Contains($"new {type}(", body, $"{method} must construct a {type}");
            StringAssert.Contains("new TunnelInfo(new List<HopInfo>())", body,
                "a zero-hop tunnel carries an empty hop list");
            StringAssert.DoesNotContain("TunnelMgr.CreateTunnel", body,
                "TunnelMgr.CreateTunnel returns null for a hopless config — it would yield no tunnel");
            StringAssert.Contains("TunnelEstablished(", body,
                "there is nothing to build, so it must reach established rather than sit pending");
        }
    }

    /// <summary>
    ///     The amplifier. Execute() already wraps the whole pass; that is what made one client's
    ///     exception deny tunnels to all of them.
    /// </summary>
    [Test]
    public void OneClientsFailureDoesNotAbortTheWholePass()
    {
        var body = Method(Provider(), "void BuildNewTunnels");

        var loops = Regex.Matches(body, @"foreach\s*\(\s*var create in tocreate(in|out)bound\s*\)").Count;
        ClassicAssert.AreEqual(2, loops, "expected an inbound and an outbound build loop");

        // Each loop body must contain its own try/catch, so the throw cannot escape the foreach.
        foreach (Match loop in Regex.Matches(body,
                     @"foreach\s*\(\s*var create in tocreate(?:in|out)bound\s*\)(?<block>.*?)\n        \}",
                     RegexOptions.Singleline))
        {
            StringAssert.Contains("try", loop.Groups["block"].Value,
                "each client is built for inside its own try — otherwise one client that cannot " +
                "be served denies tunnels to every client after it, on every pass");
            StringAssert.Contains("catch", loop.Groups["block"].Value);
        }
    }

    /// <summary>
    ///     The fixture's requirement, pinned so that changing it is a deliberate act rather than
    ///     something that quietly makes this batch look unnecessary.
    /// </summary>
    [Test]
    public void TheIntegrationFixtureStillAsksForZeroHops()
    {
        var helper = File.ReadAllText(Path.Combine(SourceRoot(),
            "src", "I2PCore.NTests", "IntegrationTests", "Infrastructure", "SAMHelper.cs"));

        ClassicAssert.IsTrue(
            Regex.IsMatch(helper, @"int inboundLength = 0,\s*int outboundLength = 0"),
            "SAMHelper requests zero-hop tunnels because a two-router network cannot build " +
            "multi-hop ones; that is why the client path has to support them");
    }

    /// <summary>
    ///     SAM passes the requested length through unchanged. A router that quietly substituted
    ///     3 for 0 would be lying to the client about its own anonymity, in the safe direction
    ///     but without saying so.
    /// </summary>
    [Test]
    public void SamPassesTheRequestedLengthThroughUnchanged()
    {
        var bridge = StripComments(File.ReadAllText(Path.Combine(
            SourceRoot(), "src", "I2PCore", "Client", "SAMBridge.cs")));

        ClassicAssert.IsTrue(
            Regex.IsMatch(bridge, @"InboundTunnelHopCount = inLength"),
            "SAM must honour INBOUND.LENGTH as given");
        ClassicAssert.IsTrue(
            Regex.IsMatch(bridge, @"OutboundTunnelHopCount = outLength"),
            "SAM must honour OUTBOUND.LENGTH as given");
    }
}
