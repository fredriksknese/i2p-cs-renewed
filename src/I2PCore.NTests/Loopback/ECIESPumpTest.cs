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
    ///     <c>ECIESSessions.TagsPerDirection</c>: how many unused tags each direction keeps
    ///     available. Batch 5-3 changed what this number means. It used to be the number of
    ///     Existing Session messages a session survived *in total* — generated once at handshake
    ///     time, never replenished, and <c>CreateExistingSessionMessage</c> threw on the next one.
    ///     It is now the width of a sliding window, so crossing it is unremarkable and the tests
    ///     below say so.
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
    ///     <b>Revisited by batch 5-3, deliberately, which is what this test existed to force.</b>
    ///     It used to assert the opposite — that delivery stopped at exactly
    ///     <c>TagWindow</c> with "No available outbound tags" — and pinning that boundary is what
    ///     turned 5-3 into a visible change rather than a silent one.
    ///
    ///     <para>
    ///         The window is now a window rather than a quota: crossing it is the interesting
    ///         moment, so it keeps its own small test next to the 100000-message one. A session
    ///         that survives 100000 but stumbles at 5001 would otherwise report a single number
    ///         and leave you to guess where it broke.
    ///     </para>
    /// </summary>
    [Test]
    public void TrafficCrossingTheInitialTagWindowKeepsFlowing()
    {
        var pump = ECIESPump.Create();
        pump.Handshake(new byte[] { 1 }, new byte[] { 2 });

        var (delivered, stoppedBecause) = pump.SendMany(pump.Alice, pump.Bob, TagWindow + 1);

        Assert.That(delivered, Is.EqualTo(TagWindow + 1),
            $"the session stopped at the initial tag block instead of generating past it: "
            + $"{stoppedBecause}");
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
    ///         <b>Un-quarantined by batch 5-3.</b> The plan's stated 3-4 verification is N=5001;
    ///         this runs to 100000 so that a fix producing a *bigger fixed block* rather than a
    ///         genuine window still fails here — which is the mistake the number is chosen to
    ///         catch, since 5-3 would look fixed at any N below the new block size.
    ///     </para>
    /// </summary>
    [Test]
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
