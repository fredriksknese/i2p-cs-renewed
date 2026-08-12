using System.IO;
using System.Linq;
using System.Net;
using I2PCore;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-11 (docs/PRODUCTION-PLAN.md). What we publish to a floodfill must be encrypted to
///     the key that floodfill actually holds.
///
///     <para>
///         Three of the four garlic sends in <c>FloodfillUpdater</c> called
///         <c>Garlic.EgEncryptGarlic</c> unconditionally — the RouterInfo publish, its retry, and
///         the LeaseSet retry. Every i2pd since 2.36 has an X25519 identity, so an ElGamal block
///         arriving at one is read as a 32-byte Noise ephemeral key that is not a curve point.
///         Both floodfills in the scaled fixture logged
///         <c>Garlic: Incorrect N ephemeral public key</c> at the exact second of each of our
///         RouterInfo publishes, and answered none of them: 20 sends, 0 delivery statuses.
///     </para>
///     <para>
///         The unanswered publishes are then charged to the floodfill as
///         <c>FloodfillUpdateTimeout</c>, which is the sole reason <c>RoutersStatistics</c> gave
///         for sweeping every floodfill out of the index in the 3-10 CI run — after which nothing,
///         including LeaseSets, can be published at all.
///     </para>
/// </summary>
[TestFixture]
public class FloodfillPublishEncryptionTest
{
    /// <summary>
    ///     A signed RouterInfo whose identity holds <paramref name="keyType" />, returned with the
    ///     private key so a test can decrypt what was addressed to it.
    /// </summary>
    private static (I2PRouterInfo Ri, I2PPrivateKey Priv) MakeRouter(I2PKeyType.KeyTypes keyType)
    {
        var privSigning = new I2PSigningPrivateKey(
            new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519));
        var pubSigning = new I2PSigningPublicKey(privSigning);

        var priv = new I2PPrivateKey(new I2PCertificate(keyType));
        var pub = new I2PPublicKey(priv);

        var addr = new I2PRouterAddress(IPAddress.Loopback, 29000, 5, "NTCP2");
        addr.Options["s"] = FreenetBase64.Encode(new I2PByteBlock(pub.Key.ToByteArray()));
        addr.Options["v"] = "2";

        var options = new I2PMapping();
        options["caps"] = "Xf";
        options["netId"] = I2PConstants.I2PNetworkId.ToString();
        options["router.version"] = "0.9.69";

        return (new I2PRouterInfo(
            new I2PRouterIdentity(pub, pubSigning),
            I2PDate.Now,
            new[] { addr },
            options,
            privSigning), priv);
    }

    /// <summary>The RouterInfo store a router publishes about itself, reply token and all.</summary>
    private static DatabaseStoreMessage OurRouterInfoStore(I2PRouterInfo us, uint token)
    {
        return new DatabaseStoreMessage(us, token, us.Identity.IdentHash, 0);
    }

    /// <summary>
    ///     Read the one garlic clove out of a Noise N message, as a floodfill would: process the
    ///     handshake with the recipient's static key, parse the ECIES blocks, and strip the
    ///     10-byte clove header (delivery instructions, type, message id, expiry).
    /// </summary>
    private static DatabaseStoreMessage OpenAsFloodfill(
        GarlicMessage garlic,
        I2PPrivateKey ffPriv,
        I2PPublicKey ffPub)
    {
        var noiseN = NoiseN.CreateResponder(ffPriv.ToByteArray(), ffPub.ToByteArray());
        byte[] plaintext;
        try
        {
            plaintext = noiseN.ProcessMessage(garlic.Data.ToByteArray());
        }
        finally
        {
            noiseN.Dispose();
        }

        var clove = ECIESBlockFormat
            .ParseBlocks(plaintext)
            .OfType<GarlicCloveBlock>()
            .Single();

        Assert.AreEqual(0, clove.Data[0], "delivery instructions must say local");
        Assert.AreEqual((byte)I2NpMessage.MessageTypes.DatabaseStore, clove.Data[1],
            "the clove must carry a DatabaseStore");

        return new DatabaseStoreMessage(new I2PBufferCursor(clove.Data, 10));
    }

    [Test]
    public void ARouterInfoPublishedToAnX25519FloodfillIsEncryptedWithNoiseN()
    {
        var (ff, ffPriv) = MakeRouter(I2PKeyType.KeyTypes.X25519);
        var (us, _) = MakeRouter(I2PKeyType.KeyTypes.X25519);

        const uint token = 0x5EED0001;
        var wrapped = FloodfillUpdater.WrapForFloodfill(OurRouterInfoStore(us, token), ff);

        // The decryption is the assertion: Noise N authenticates, so nothing an ElGamal block
        // could produce opens here.
        var store = OpenAsFloodfill((GarlicMessage)wrapped, ffPriv, ff.Identity.PublicKey);

        Assert.AreEqual(DatabaseStoreMessage.MessageContent.RouterInfo, store.Content);
        Assert.AreEqual(us.Identity.IdentHash, store.Key, "the floodfill must be asked to store us");
        Assert.AreEqual(token, store.ReplyToken,
            "without the reply token the floodfill sends no delivery status, and the publish " +
            "is counted as a timeout however well it worked");
    }

    /// <summary>
    ///     The defect was not that ElGamal is wrong — it is that it was chosen without asking. The
    ///     publisher had four garlic sends and one of them asked, so this pins the encryption
    ///     decision to a single site: two encrypt calls in the file, both inside
    ///     <c>WrapForFloodfill</c>. Confirmed to bite — the pre-fix file has three.
    /// </summary>
    [Test]
    public void ThePublisherDecidesItsEncryptionInExactlyOnePlace()
    {
        var source = Path.Combine(SourceRoot(), "src", "I2PCore", "NetDb", "FloodfillUpdater.cs");
        Assert.IsTrue(File.Exists(source), $"source not found at {source}");

        // Strip line comments, so prose naming a call does not trip the scan.
        var code = File
            .ReadAllLines(source)
            .Select(l => l.Split("//")[0])
            .ToArray();

        Lines("EgEncryptGarlic", 1);
        Lines("EciesEncryptGarlic", 1);
        Lines("NoiseN", 0);

        void Lines(string call, int expected)
        {
            var hits = code
                .Select((l, i) => (Line: i + 1, Text: l))
                .Where(l => l.Text.Contains(call))
                .ToArray();

            Assert.AreEqual(expected, hits.Length,
                $"{call} must appear {expected} time(s) in FloodfillUpdater — every send picks its " +
                $"encryption through WrapForFloodfill, from the recipient's key type. Found at: " +
                $"{string.Join(", ", hits.Select(h => h.Line))}");
        }
    }

    /// <summary>Walks up from the test binary to the repository root.</summary>
    private static string SourceRoot()
    {
        var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "i2p.sln"))) dir = dir.Parent;
        return dir?.FullName ?? TestContext.CurrentContext.TestDirectory;
    }

    [Test]
    public void AHybridIdentityIsHandedTheX25519HalfOfItsKey()
    {
        var (ff, ffPriv) = MakeRouter(I2PKeyType.KeyTypes.MLKEM768_X25519);

        Assert.AreEqual(32, ff.GetECIESPublicKey()?.Length,
            "Noise N takes 32 bytes; the LeaseSet path used to hand it the whole key");

        var (us, _) = MakeRouter(I2PKeyType.KeyTypes.X25519);

        Assert.DoesNotThrow(
            () => OpenAsFloodfill(
                (GarlicMessage)FloodfillUpdater.WrapForFloodfill(OurRouterInfoStore(us, 0x5EED0003), ff),
                ffPriv,
                ff.Identity.PublicKey));
    }

    [Test]
    public void AnElGamalFloodfillStillGetsElGamal()
    {
        var (ff, ffPriv) = MakeRouter(I2PKeyType.KeyTypes.ElGamal2048);
        var (us, _) = MakeRouter(I2PKeyType.KeyTypes.X25519);

        const uint token = 0x5EED0004;
        var garlic = (GarlicMessage)FloodfillUpdater.WrapForFloodfill(OurRouterInfoStore(us, token), ff);

        // The fix is a choice, not a replacement: a router that really does hold an ElGamal key
        // must still be able to read us.
        var (aes, _) = Garlic.EgDecryptGarlic(garlic, ffPriv);
        var cloves = new Garlic(new I2PBufferCursor(aes.Payload)).Cloves;

        var store = (DatabaseStoreMessage)cloves.Single().Message;
        Assert.AreEqual(us.Identity.IdentHash, store.Key);
        Assert.AreEqual(token, store.ReplyToken);
    }
}
