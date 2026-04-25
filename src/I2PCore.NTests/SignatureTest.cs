using I2PCore.Data;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

[TestFixture]
public class SignatureTest
{
    public void TestCert(I2PCertificate certificate)
    {
        var privskey = new I2PSigningPrivateKey(certificate);
        var pubskey = new I2PSigningPublicKey(privskey);

        var data = new I2PByteBlock(BufUtils.RandomBytes(500));
        var sign = new I2PSignature(new I2PBufferCursor(I2PSignature.DoSign(privskey, data)), certificate);

        Assert.IsTrue(I2PSignature.DoVerify(pubskey, sign, data));
    }

    [Test]
    public void TestEdDsasha512Ed25519()
    {
        TestCert(new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519));
    }

    [Test]
    public void TestDsasha1()
    {
        TestCert(new I2PCertificate(I2PSigningKey.SigningKeyTypes.DsaSha1));
    }

    [Test]
    public void TestEcdsasha256P256()
    {
        TestCert(new I2PCertificate(I2PSigningKey.SigningKeyTypes.EcdsaSha256P256));
    }

    [Test]
    public void TestEcdsasha384P384()
    {
        TestCert(new I2PCertificate(I2PSigningKey.SigningKeyTypes.EcdsaSha384P384));
    }

    [Test]
    public void TestEcdsasha512P521()
    {
        TestCert(new I2PCertificate(I2PSigningKey.SigningKeyTypes.EcdsaSha512P521));
    }
}