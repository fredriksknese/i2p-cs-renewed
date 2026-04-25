using I2PCore.Utils;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace I2PCore.Data;

public class I2PSigningPublicKey : I2PSigningKey
{
    public I2PSigningPublicKey(BigInteger key, I2PCertificate cert) : base(key, cert)
    {
    }

    public I2PSigningPublicKey(I2PSigningPrivateKey privkey)
        : base(privkey.Certificate)
    {
        switch (Certificate.SignatureType)
        {
            case SigningKeyTypes.DsaSha1:
                Key = new I2PByteBlock(I2PConstants.DsaG.ModPow(privkey.ToBigInteger(), I2PConstants.DsaP)
                    .ToByteArrayUnsigned());
                break;

            case SigningKeyTypes.EcdsaSha256P256:
            {
                var param = NistNamedCurves.GetByName("P-256");
                var domain = new ECDomainParameters(param.Curve, param.G, param.N, param.H);

                var q = domain.G.Multiply(privkey.ToBigInteger());
                var publicparam = new ECPublicKeyParameters(q, domain);
                Key = new I2PByteBlock(publicparam.Q.GetEncoded());
            }
                break;

            case SigningKeyTypes.EcdsaSha384P384:
            {
                var param = NistNamedCurves.GetByName("P-384");
                var domain = new ECDomainParameters(param.Curve, param.G, param.N, param.H);

                var q = domain.G.Multiply(privkey.ToBigInteger());
                var publicparam = new ECPublicKeyParameters(q, domain);
                Key = new I2PByteBlock(publicparam.Q.GetEncoded());
            }
                break;

            case SigningKeyTypes.EcdsaSha512P521:
            {
                var param = NistNamedCurves.GetByName("P-521");
                var domain = new ECDomainParameters(param.Curve, param.G, param.N, param.H);

                var q = domain.G.Multiply(privkey.ToBigInteger());
                var publicparam = new ECPublicKeyParameters(q, domain);
                Key = new I2PByteBlock(publicparam.Q.GetEncoded());
            }
                break;

            case SigningKeyTypes.EdDsaSha512Ed25519:
                Key = new I2PByteBlock(
                    new Ed25519PrivateKeyParameters(privkey.Key.BaseArray, privkey.Key.BaseArrayOffset)
                        .GeneratePublicKey().GetEncoded());
                break;

            default:
                Logging.LogWarning(
                    $"I2PSigningPublicKey: Public key derivation not implemented for {Certificate.SignatureType}");
                Key = new I2PByteBlock(new byte[KeySizeBytes]);
                break;
        }
    }

    public I2PSigningPublicKey(I2PBufferCursor buf, I2PCertificate cert) : base(cert)
    {
        Key = buf.ReadBlock(KeySizeBytes);
    }

    public override int KeySizeBytes => Certificate.SigningPublicKeyLength;
}