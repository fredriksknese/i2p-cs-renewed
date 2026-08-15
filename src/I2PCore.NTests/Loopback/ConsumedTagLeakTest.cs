using System;
using System.Text;
using I2PCore.SessionLayer.ECIES;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests.Loopback;

/// <summary>
///     Batch 5-6 (docs/PRODUCTION-PLAN.md). A session tag that has been used up must leave the
///     manager's routing index, and a message arriving under an already-used tag must be named
///     as a repeat rather than as a tag we never held.
/// </summary>
/// <remarks>
///     Found while reading the 3-18 CI run for the ECIES failures that batch exposed. Twenty
///     messages failed with <c>Unknown or expired tag</c> and twenty with <c>mac check in
///     ChaCha20Poly1305 failed</c>, and neither could be attributed, because the two opposite
///     faults — a duplicate arriving, and the two sides disagreeing about the tag set — reported
///     identically.
///     <para>
///     The leak behind it: <c>_tagToDestination</c> is maintained by two events,
///     <c>InboundTagAdded</c> and <c>InboundTagExpired</c>. Expiry is raised only by the sliding
///     window sweep, and the sweep walks <c>_inboundTags</c> — which a <i>consumed</i> tag has
///     already left. So every tag ever received stayed in the index for the life of the process,
///     one entry per message, and a repeat of one routed into a session that no longer had it.
///     </para>
///     <para>
///     Driven through the batch 3-4 pump rather than asserted against source, because both
///     halves are observable: the index size, and the error a second delivery produces.
///     </para>
/// </remarks>
[TestFixture]
public class ConsumedTagLeakTest
{
    private static ECIESPump Handshaken()
    {
        var pump = ECIESPump.Create();
        pump.Handshake(Encoding.ASCII.GetBytes("req"), Encoding.ASCII.GetBytes("rep"));
        return pump;
    }

    /// <summary>
    ///     The index tracks the live tag window. Before this batch it grew by one per message
    ///     and never shrank.
    /// </summary>
    [Test]
    public void TheTagIndexDoesNotGrowWithEveryMessageReceived()
    {
        var pump = Handshaken();

        var afterHandshake = pump.Bob.Keys.TrackedTagCount;

        var (delivered, stoppedBecause) = pump.SendMany(pump.Alice, pump.Bob, 200);
        Assert.That(delivered, Is.EqualTo(200), $"pump stopped early: {stoppedBecause}");

        var afterTraffic = pump.Bob.Keys.TrackedTagCount;

        // The window slides — one generated per one consumed — so the count should be flat.
        // Anything proportional to the message count is the leak this batch removes.
        Assert.That(afterTraffic, Is.LessThan(afterHandshake + 200),
            "the routing index kept one entry per message received; a consumed tag must leave it");
    }

    /// <summary>
    ///     A tag is single-use. The second message under it must be refused — and say why.
    /// </summary>
    [Test]
    public void ARepeatedTagIsRefusedAndNamedAsARepeat()
    {
        var pump = Handshaken();

        var message = pump.Alice.Keys
            .CreateExistingSession(pump.Bob.Destination.IdentHash, Encoding.ASCII.GetBytes("once"))
            .ToByteArray();

        var first = pump.Bob.Keys.ProcessMessage(message);
        ClassicAssert.IsTrue(first.Success, $"first delivery should decrypt: {first.Error}");

        var second = pump.Bob.Keys.ProcessMessage((byte[])message.Clone());

        ClassicAssert.IsFalse(second.Success,
            "a session tag is single-use; decrypting twice under it would be a replay");
        StringAssert.Contains("RepeatedTag", second.Error ?? "",
            "a repeat and a tag we never held are opposite faults and must not report identically");
    }

    /// <summary>
    ///     And a tag that genuinely was never ours still reports as unknown, so the two stay
    ///     distinguishable in both directions.
    /// </summary>
    [Test]
    public void ATagThatWasNeverOursIsStillReportedAsUnknown()
    {
        var pump = Handshaken();

        var stranger = new byte[64];
        new Random(1234).NextBytes(stranger);

        var result = pump.Bob.Keys.ProcessMessage(stranger);

        ClassicAssert.IsFalse(result.Success);
        StringAssert.DoesNotContain("RepeatedTag", result.Error ?? "",
            "nothing consumed this tag — it must not be reported as a repeat");
    }

    /// <summary>
    ///     The index size is a function of the live tag window, not of how much has been sent.
    /// </summary>
    /// <remarks>
    ///     Stated as stability rather than as an absolute bound: the window is
    ///     <c>TagsPerDirection</c> tags wide, so the count sits at that figure and the question
    ///     is whether it <i>moves</i> with traffic. An earlier version of this test asserted a
    ///     small absolute number and failed against correct code, which is worth recording — the
    ///     leak is growth, and growth is what has to be measured.
    /// </remarks>
    [Test]
    public void TheIndexSizeIsIndependentOfHowMuchHasBeenSent()
    {
        var pump = Handshaken();

        var (first, why1) = pump.SendMany(pump.Alice, pump.Bob, 200);
        Assert.That(first, Is.EqualTo(200), $"pump stopped early: {why1}");
        var afterFirst = pump.Bob.Keys.TrackedTagCount;

        var (second, why2) = pump.SendMany(pump.Alice, pump.Bob, 500);
        Assert.That(second, Is.EqualTo(500), $"pump stopped early: {why2}");
        var afterSecond = pump.Bob.Keys.TrackedTagCount;

        Assert.That(afterSecond - afterFirst, Is.LessThan(100),
            $"500 further messages moved the index by {afterSecond - afterFirst}; it must track " +
            "the live window, not the number of messages received");
    }
}
