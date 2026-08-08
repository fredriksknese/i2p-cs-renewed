using System.Text;
using NUnit.Framework;

namespace I2PTests.Loopback;

/// <summary>
///     The ECIES ratchet exercised end to end between two key managers, with no garlic, no
///     tunnels and no router. Batch 3-4 (docs/PRODUCTION-PLAN.md).
///
///     <para>
///         Companion to <see cref="SSU2LoopbackTest" />, and a much happier one: the ECIES
///         handshake works. New Session and New Session Reply both complete and both carry their
///         payloads. The defect is further along — the session runs out of tags and stops dead.
///     </para>
/// </summary>
[TestFixture]
public class ECIESPumpTest
{
    /// <summary>
    ///     The number of Existing Session messages a session survives before
    ///     <c>ECIESSession.CreateExistingSessionMessage</c> throws. It is
    ///     <c>ECIESSessions.TagsPerDirection</c>, pre-generated once at handshake time and never
    ///     replenished. Asserted rather than merely described, so that if batch 5-3 changes the
    ///     strategy this test says so instead of silently passing.
    /// </summary>
    private const int TagWindow = 5000;

    [Test]
    public void HandshakeCarriesPayloadsInBothDirections()
    {
        var pump = ECIESPump.Create();

        var request = Encoding.ASCII.GetBytes("new session");
        var reply = Encoding.ASCII.GetBytes("reply");

        var (atBob, atAlice) = pump.Handshake(request, reply);

        Assert.Multiple(() =>
        {
            Assert.That(atBob, Is.EqualTo(request), "New Session payload did not reach the responder");
            Assert.That(atAlice, Is.EqualTo(reply), "New Session Reply payload did not reach the initiator");
            Assert.That(pump.Alice.Keys.HasOutboundSession(pump.Bob.Destination.IdentHash), Is.True);
            Assert.That(pump.Alice.Keys.HasAvailableOutboundTags(pump.Bob.Destination.IdentHash), Is.True,
                "no outbound tags after a completed handshake");
        });
    }

    [Test]
    public void EstablishedSessionCarriesTrafficBothWays()
    {
        var pump = ECIESPump.Create();
        pump.Handshake(new byte[] { 1 }, new byte[] { 2 });

        var toBob = pump.Send(pump.Alice, pump.Bob, Encoding.ASCII.GetBytes("alice to bob"));
        Assert.That(toBob, Is.EqualTo(Encoding.ASCII.GetBytes("alice to bob")));

        var toAlice = pump.Send(pump.Bob, pump.Alice, Encoding.ASCII.GetBytes("bob to alice"));
        Assert.That(toAlice, Is.EqualTo(Encoding.ASCII.GetBytes("bob to alice")));
    }

    /// <summary>
    ///     Traffic well inside the tag window works, which keeps
    ///     <see cref="SustainedTrafficExceedingTheTagWindow" /> honest: when that one fails, it
    ///     fails at the window and not because the pump cannot move a message at all.
    /// </summary>
    [Test]
    public void TrafficInsideTheTagWindowIsDeliveredIntact()
    {
        var pump = ECIESPump.Create();
        pump.Handshake(new byte[] { 1 }, new byte[] { 2 });

        var (delivered, stoppedBecause) = pump.SendMany(pump.Alice, pump.Bob, 1000);

        Assert.That(delivered, Is.EqualTo(1000), $"stopped early: {stoppedBecause}");
    }

    /// <summary>
    ///     Pins the boundary itself. Green today, and it is what turns "5-3 changed something"
    ///     into a visible event rather than a silent one: whichever way batch 5-3 goes, this
    ///     assertion has to be revisited deliberately.
    /// </summary>
    [Test]
    public void TheTagWindowIsExactlyTheGeneratedTagCount()
    {
        var pump = ECIESPump.Create();
        pump.Handshake(new byte[] { 1 }, new byte[] { 2 });

        var (delivered, stoppedBecause) = pump.SendMany(pump.Alice, pump.Bob, TagWindow + 1);

        Assert.Multiple(() =>
        {
            Assert.That(delivered, Is.EqualTo(TagWindow),
                "the session did not stop at the pre-generated tag count");
            Assert.That(stoppedBecause, Does.Contain("No available outbound tags"),
                "the session stopped for a different reason than tag exhaustion");
        });
    }

    /// <summary>
    ///     The 5-3 defect. <c>ECIESSession.InitializeBiDirectionalTags</c> pre-generates exactly
    ///     <c>TagsPerDirection</c> = 5000 tags per direction at handshake time and never
    ///     generates another, so <c>CreateExistingSessionMessage</c> throws
    ///     <c>"No available outbound tags"</c> on message 5001 and the session is finished.
    ///
    ///     <para>
    ///         At 1 KB per message that is roughly 5 MB before a destination stops being able to
    ///         speak — under half of Gate 5's ">10 MB sustained without a session reset". There
    ///         is no window, no generate-ahead and no expire-behind; batch 5-3 replaces the fixed
    ///         block with an i2pd-style sliding window, and 5-4 adds the DH ratchet that lets a
    ///         session outlive any window at all.
    ///     </para>
    ///     <para>
    ///         Quarantined, owner batch 5-3, which un-quarantines it. The plan's stated 3-4
    ///         verification is N=5001; this runs to 100000 so that a fix producing a *bigger*
    ///         fixed block rather than a genuine window still fails here.
    ///     </para>
    /// </summary>
    [Test]
    [Category(TestCategories.Experimental)]
    public void SustainedTrafficExceedingTheTagWindow()
    {
        const int count = 100000;

        var pump = ECIESPump.Create();
        pump.Handshake(new byte[] { 1 }, new byte[] { 2 });

        var (delivered, stoppedBecause) = pump.SendMany(pump.Alice, pump.Bob, count);

        Assert.That(delivered, Is.EqualTo(count),
            $"delivered {delivered} of {count} before stopping: {stoppedBecause}");
    }
}
