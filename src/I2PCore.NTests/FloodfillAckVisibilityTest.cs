using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 3-17 (docs/PRODUCTION-PLAN.md). Every outcome of the floodfill's acknowledgement
///     path must leave a line in the log.
/// </summary>
/// <remarks>
///     The 3-16 CI run left i2pd logging <c>Publish confirmation was not received</c> 1490 times.
///     That is the largest number in the run and we are the other half of it — i2pd publishes to
///     us, so the acknowledgement is ours to send. It could not be investigated, because
///     <c>SendDeliveryStatus</c> logged nothing on either success path and dropped a store with
///     no reply gateway in an <c>else</c> that was not written. <b>"We sent 24 acknowledgements"
///     and "we sent none" produced byte-identical output.</b>
///     <para>
///     This is a source scan rather than a behavioural test on purpose. What is being guarded is
///     that no <i>path</i> through the method is silent, which is a property of the code's shape;
///     a test that drove one path would pass while the other three stayed mute, which is exactly
///     the state this batch found.
///     </para>
/// </remarks>
[TestFixture]
public class FloodfillAckVisibilityTest
{
    private static string SourceRoot()
    {
        var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "i2p.sln"))) dir = dir.Parent;
        return dir?.FullName ?? TestContext.CurrentContext.TestDirectory;
    }

    private static string Source()
    {
        return File.ReadAllText(
            Path.Combine(SourceRoot(), "src", "I2PCore", "NetDb", "FloodfillServer.cs"));
    }

    private static string SendDeliveryStatusBody()
    {
        var body = Regex.Match(Source(),
            @"void SendDeliveryStatus\s*\([^)]*\)\s*\{(?<body>.*?)\n    \}", RegexOptions.Singleline);

        ClassicAssert.IsTrue(body.Success, "FloodfillServer.SendDeliveryStatus not found");
        return body.Groups["body"].Value;
    }

    /// <summary>
    ///     Strip comments so the remarks above — which describe the silent paths — cannot be what
    ///     satisfies a scan looking for logging.
    /// </summary>
    private static string StripComments(string source)
    {
        var noBlock = Regex.Replace(source, @"/\*.*?\*/", "", RegexOptions.Singleline);

        return string.Join("\n", noBlock.Split('\n').Select(line =>
        {
            var comment = line.IndexOf("//", StringComparison.Ordinal);
            var doc = line.IndexOf("///", StringComparison.Ordinal);
            var cut = doc >= 0 ? doc : comment;
            return cut >= 0 ? line[..cut] : line;
        }));
    }

    /// <summary>
    ///     Each of the three ways the acknowledgement can leave, and the one way it cannot, is
    ///     reported once.
    /// </summary>
    [Test]
    public void EverySendPathReportsWhereTheAcknowledgementWent()
    {
        var body = StripComments(SendDeliveryStatusBody());

        var sends = Regex.Matches(body, @"(outtunnel\.Send\(|TransportProvider\.Send\()").Count;
        var logs = Regex.Matches(body, @"Logging\.Log(Information|Warning)\(").Count;

        ClassicAssert.AreEqual(3, sends,
            "three ways out: our outbound tunnel, direct to the gateway with a reply tunnel, " +
            "and direct with none");

        ClassicAssert.GreaterOrEqual(logs, sends + 1,
            "every send is reported, and so is the store that names no reply gateway — that " +
            "last one sends nothing at all and used to do so silently");
    }

    /// <summary>
    ///     A store carrying a reply token that we cannot answer is a warning, not a silent return.
    /// </summary>
    [Test]
    public void AStoreWithNoReplyGatewayIsWarnedAbout()
    {
        var body = StripComments(SendDeliveryStatusBody());

        var guard = Regex.Match(body,
            @"if\s*\(\s*store\.ReplyGateway\s+is\s+null\s*\)(?<block>.*?)return;", RegexOptions.Singleline);

        ClassicAssert.IsTrue(guard.Success,
            "the no-reply-gateway case must be handled explicitly, not fallen out of");

        StringAssert.Contains("Logging.LogWarning(", guard.Groups["block"].Value,
            "an acknowledgement that was asked for and cannot be sent is a warning");
    }

    /// <summary>
    ///     The caller must distinguish "no acknowledgement requested" from "acknowledgement
    ///     requested and sent". A publisher that never sees its confirmation is in one of those
    ///     two states and the log has to say which.
    /// </summary>
    [Test]
    public void AStoreThatAsksForNoAcknowledgementSaysSo()
    {
        var source = StripComments(Source());

        var branch = Regex.Match(source,
            @"if\s*\(\s*store\.ReplyToken\s*!=\s*0\s*\)(?<block>.*?)(?=\n\s*//|\n\s*Flood)",
            RegexOptions.Singleline);

        ClassicAssert.IsTrue(branch.Success, "the ReplyToken branch was not found");
        StringAssert.Contains("else", branch.Groups["block"].Value,
            "the no-token case must be stated, not implied by the absence of a line");
    }

    /// <summary>
    ///     The reply gateway being this router is worth saying out loud.
    /// </summary>
    /// <remarks>
    ///     In a two-router fixture i2pd's inbound tunnel runs through us, so the gateway hash it
    ///     names in its DatabaseStore is our own. <c>TransportProvider.Send</c> treats that as a
    ///     loopback, which is correct — but a reader of the log cannot guess it, and it changes
    ///     what the next question is. This is the fact that took a source read to establish while
    ///     investigating the 1490.
    /// </remarks>
    [Test]
    public void ALoopbackReplyGatewayIsNamedInTheLog()
    {
        var body = StripComments(SendDeliveryStatusBody());

        ClassicAssert.IsTrue(
            Regex.IsMatch(body, @"MyRouterIdentity\.IdentHash"),
            "the log must distinguish a reply gateway that is this router from one that is not");
    }
}
