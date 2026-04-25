using I2PCore.Utils;
using Org.BouncyCastle.Math;

namespace I2PCore.Data;

public class I2PSigningPrivateKey : I2PSigningKey
{
    public I2PSigningPrivateKey(I2PCertificate cert)
        : base(new I2PByteBlock(BufUtils.RandomBytes(cert.SigningPrivateKeyLength)), cert)
    {
        if (cert.SignatureType == SigningKeyTypes.EcdsaSha512P521) Key[0] &= 0x01;
    }

    public I2PSigningPrivateKey(I2PBufferCursor reader, I2PCertificate cert) : base(reader, cert)
    {
    }

    public I2PSigningPrivateKey(BigInteger key, I2PCertificate cert) : base(key, cert)
    {
    }

    public override int KeySizeBytes => Certificate.SigningPrivateKeyLength;
}