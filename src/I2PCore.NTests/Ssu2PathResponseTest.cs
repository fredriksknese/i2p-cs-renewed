using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using I2PCore.TransportLayer.SSU2;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-3a (docs/PRODUCTION-PLAN.md). A PathChallenge must be answered on the wire.
/// </summary>
/// <remarks>
///     <c>SSU2Session.SendPathResponse</c> built the block into a local array, logged, and
///     returned. That would be a dormant stub except that <c>SSU2Host.PathValidationSupported</c>
///     is <c>true</c>, so this router publishes <c>p</c> in its SSU2 <c>caps</c> — which is an
///     invitation to send the challenge we answered with silence. Batch 0-4 found the same shape
///     in the <c>m</c> capability and switched it off; <c>p</c> was left on.
///     <para>
///     The framing half matters as much as the sending half: the stub hand-rolled a type byte and
///     a big-endian length in front of the data, which <c>SSU2DataPacket.BuildWithBlock</c> also
///     writes. Had the stub ever been wired up as it stood, every response would have carried its
///     header twice and the peer would have read a malformed block — so the round trip below goes
///     through the real builder and parser rather than asserting on the bytes we happen to write.
///     </para>
/// </remarks>
[TestFixture]
public class Ssu2PathResponseTest
{
    private static readonly byte[] DataKey = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();
    private static readonly byte[] HeaderKey1 = Enumerable.Range(0, 32).Select(i => (byte)(i * 3 + 1)).ToArray();
    private static readonly byte[] HeaderKey2 = Enumerable.Range(0, 32).Select(i => (byte)(i * 5 + 2)).ToArray();

    private static string SourceRoot()
    {
        var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "i2p.sln"))) dir = dir.Parent;
        return dir?.FullName ?? TestContext.CurrentContext.TestDirectory;
    }

    private static string ReadSsu2Source(string file)
    {
        var text = File.ReadAllText(
            Path.Combine(SourceRoot(), "src", "I2PCore", "TransportLayer", "SSU2", file));

        // Strip line comments so prose describing the old stub cannot satisfy or trip a scan.
        return string.Join("\n", text.Split('\n').Select(line =>
        {
            var comment = line.IndexOf("//", StringComparison.Ordinal);
            return comment >= 0 ? line[..comment] : line;
        }));
    }

    /// <summary>
    ///     The response a peer reads back is the challenge it sent, byte for byte, through the
    ///     real builder and parser.
    /// </summary>
    [Test]
    public void APathResponseCarriesTheChallengeUnchanged()
    {
        var challenge = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x7F, 0x80 };

        var packet = SSU2DataPacket.BuildWithBlock(
            SSU2BlockType.PathResponse, challenge,
            0x0123456789ABCDEFUL, 42,
            DataKey, HeaderKey1, HeaderKey2);

        var parsed = SSU2DataPacket.Parse(packet, DataKey, HeaderKey1, HeaderKey2);

        var block = parsed.Blocks.FirstOrDefault(b => b.BlockType == SSU2BlockType.PathResponse);

        ClassicAssert.IsNotNull(block, "the packet must carry a PathResponse block");
        CollectionAssert.AreEqual(challenge, block.Data,
            "the echo must be exact — a peer matches the response against the challenge it sent");
    }

    /// <summary>
    ///     Length is not fixed by the protocol, so the echo must survive whatever the peer chose.
    /// </summary>
    [Test]
    public void APathResponseSurvivesUnusualChallengeLengths()
    {
        foreach (var length in new[] { 1, 7, 16, 255, 256, 1024 })
        {
            var challenge = new byte[length];
            BufUtils.Randomize(challenge);

            var packet = SSU2DataPacket.BuildWithBlock(
                SSU2BlockType.PathResponse, challenge,
                0xFEDCBA9876543210UL, (uint)length,
                DataKey, HeaderKey1, HeaderKey2);

            var block = SSU2DataPacket
                .Parse(packet, DataKey, HeaderKey1, HeaderKey2)
                .Blocks.FirstOrDefault(b => b.BlockType == SSU2BlockType.PathResponse);

            ClassicAssert.IsNotNull(block, $"no PathResponse block for a {length} byte challenge");
            CollectionAssert.AreEqual(challenge, block.Data,
                $"a {length} byte challenge must echo unchanged");
        }
    }

    /// <summary>
    ///     The defect itself: the handler must hand the block to the send path, not build and
    ///     drop it. Read from source, because a unit test cannot stand up an Established session
    ///     with a live host and keys — and because "builds the right bytes" is exactly what the
    ///     stub already did.
    /// </summary>
    [Test]
    public void SendPathResponseReachesTheSendPath()
    {
        var source = ReadSsu2Source("SSU2Session.cs");

        var body = Regex.Match(source,
            @"void SendPathResponse\s*\([^)]*\)\s*\{(?<body>.*?)\n    \}", RegexOptions.Singleline);

        ClassicAssert.IsTrue(body.Success, "SSU2Session.SendPathResponse not found");

        StringAssert.Contains("SendBlock(SSU2BlockType.PathResponse", body.Groups["body"].Value,
            "SendPathResponse must transmit the block; building it into a local array and " +
            "logging is the batch 4-3a defect");
    }

    /// <summary>
    ///     And it must not reintroduce the hand-rolled framing, which BuildWithBlock already does.
    /// </summary>
    [Test]
    public void SendPathResponseDoesNotFrameTheBlockItself()
    {
        var source = ReadSsu2Source("SSU2Session.cs");

        var body = Regex.Match(source,
            @"void SendPathResponse\s*\([^)]*\)\s*\{(?<body>.*?)\n    \}", RegexOptions.Singleline)
            .Groups["body"].Value;

        ClassicAssert.IsFalse(
            Regex.IsMatch(body, @"\(byte\)SSU2BlockType\.PathResponse"),
            "the type byte and length are BuildWithBlock's to write; writing them here too " +
            "would send every response with its header twice");
    }

    /// <summary>
    ///     A capability is a promise. <c>p</c> may only be published while the responder exists;
    ///     <c>m</c> may not be, because a moved peer's packets are dropped by DispatchPacket
    ///     before any block is read — Sessions is keyed by IPEndPoint. That is batch 4-3b.
    /// </summary>
    [Test]
    public void TheAdvertisedCapabilitiesMatchWhatIsImplemented()
    {
        ClassicAssert.IsTrue(SSU2Host.PathValidationSupported,
            "'p' is published and SendPathResponse now answers, so this stays on");

        ClassicAssert.IsFalse(SSU2Host.ConnectionMigrationSupported,
            "'m' promises migration. Answering a challenge is not migrating: until sessions are " +
            "keyed by connection id (batch 4-3b), a packet from a moved peer never reaches a " +
            "session at all");

        // The session table keying is the reason above, so pin it — if it changes, this test
        // should be revisited deliberately rather than left asserting a stale rationale.
        var host = ReadSsu2Source("SSU2Host.cs");
        ClassicAssert.IsTrue(
            Regex.IsMatch(host, @"Sessions\.TryGetValue\(\s*remoteEP"),
            "DispatchPacket still finds sessions by endpoint; if that changed, 4-3b may be done " +
            "and ConnectionMigrationSupported should be reconsidered");
    }
}
