using I2PCore.Data;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-8 (docs/PRODUCTION-PLAN.md). What SAM's <c>SESSION STATUS RESULT=OK
///     DESTINATION=</c> carries is the session's **private keys**, destination-first — not the
///     destination. A client that wants the ident hash has to parse the identity out of the
///     front; hashing the decoded string produces the hash of a key blob, which is not a
///     routable identity and never appears in any router's NetDb.
///
///     Two integration tests did exactly that and then asserted the network could find a
///     LeaseSet for the result. Every floodfill answered "Requested LeaseSet not found" —
///     correctly — and the failure read as broken LeaseSet publication for two sessions of work.
/// </summary>
[TestFixture]
public class SamSessionDestinationTest
{
    private static I2PDestinationInfo NewDestination()
    {
        return new I2PDestinationInfo(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
    }

    [Test]
    public void TheIdentHashComesFromParsingTheBlobNotFromHashingIt()
    {
        var info = NewDestination();
        var samReply = info.ToBase64();

        Assert.AreEqual(info.Destination.IdentHash, SAMHelper.IdentHashOf(samReply),
            "the identity is the front of the key blob and must be parsed out");
    }

    [Test]
    public void HashingTheWholeBlobYieldsSomethingThatIsNotTheDestination()
    {
        // The bug, stated as a test: this is what the two NetDb tests computed, and it is why
        // the lookups could not have succeeded whatever the network did.
        var info = NewDestination();
        var samReply = info.ToBase64();

        var decoded = FreenetBase64.Decode(samReply);
        var hashOfEverything = new I2PIdentHash(
            new I2PBufferCursor(I2PHashSha256.GetHash(decoded, 0, decoded.Length)));

        Assert.AreNotEqual(info.Destination.IdentHash, hashOfEverything,
            "hashing the key blob must not be mistaken for the destination hash");
    }

    [Test]
    public void TheReplyIsWhatASessionWouldHaveToSendBackToKeepItsDestination()
    {
        // The point of the field: SESSION CREATE DESTINATION=<what we returned> must rebuild the
        // same destination, keys and all. SAMBridge.CreateDestinationInfo parses it exactly this
        // way, so returning the bare destination made a TRANSIENT destination unrecoverable —
        // the reply could not be fed back into the command that asks for it.
        var info = NewDestination();

        var restored = new I2PDestinationInfo(info.ToBase64());

        Assert.AreEqual(info.Destination.IdentHash, restored.Destination.IdentHash,
            "the SESSION CREATE reply must round-trip through SESSION CREATE DESTINATION=");
    }

    [Test]
    public void ThePrivateKeyBlobIsLongerThanTheDestinationItStartsWith()
    {
        // The measured discriminator from CI: i2pd's SESSION CREATE reply is 884 base64
        // characters where our old one was 524 — the length is what gave the two contracts away.
        var info = NewDestination();

        var destOnly = FreenetBase64.Encode(new I2PByteBlock(info.Destination.ToByteArray()));
        var withKeys = info.ToBase64();

        Assert.Greater(withKeys.Length, destOnly.Length,
            "SESSION STATUS must carry more than the destination");
        Assert.AreEqual(info.Destination.IdentHash, SAMHelper.IdentHashOf(destOnly),
            "a bare destination must still parse, so a peer that sends one is understood");
    }
}
