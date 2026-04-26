using System;
using System.Linq;
using I2PCore.Crypto;
using I2PCore.Crypto.MLKEM;
using I2PCore.Utils;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace I2PCore.Data;

public class I2PPublicKey : I2PKeyType
{
    public I2PPublicKey(I2PPrivateKey priv) : base(priv.Certificate)
    {
        switch (Certificate.PublicKeyType)
        {
            case KeyTypes.ElGamal2048:
                Key = new I2PByteBlock(I2PConstants
                    .ElGamalG.ModPow(
                        priv.ToBigInteger(),
                        I2PConstants.ElGamalP)
                    .ToByteArrayUnsigned());
                break;

            case KeyTypes.X25519:
            case KeyTypes.MLKEM512_X25519:
            case KeyTypes.MLKEM768_X25519:
            case KeyTypes.MLKEM1024_X25519:
                Key = new I2PByteBlock(X25519.GetPublicKey(priv.ToByteArray()));
                break;

            case KeyTypes.P256:
            {
                var curve = ECNamedCurveTable.GetByName("secp256r1");
                var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                var privKeyParams = new ECPrivateKeyParameters(new BigInteger(1, priv.ToByteArray()), domainParams);
                var q = domainParams.G.Multiply(privKeyParams.D).Normalize();
                var xBytes = q.AffineXCoord.GetEncoded();
                var yBytes = q.AffineYCoord.GetEncoded();
                var pubBytes = new byte[64];
                Array.Copy(xBytes, 0, pubBytes, 32 - xBytes.Length, xBytes.Length);
                Array.Copy(yBytes, 0, pubBytes, 64 - yBytes.Length, yBytes.Length);
                Key = new I2PByteBlock(pubBytes);
            }
                break;

            case KeyTypes.P384:
            {
                var curve = ECNamedCurveTable.GetByName("secp384r1");
                var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                var privKeyParams = new ECPrivateKeyParameters(new BigInteger(1, priv.ToByteArray()), domainParams);
                var q = domainParams.G.Multiply(privKeyParams.D).Normalize();
                var xBytes = q.AffineXCoord.GetEncoded();
                var yBytes = q.AffineYCoord.GetEncoded();
                var pubBytes = new byte[96];
                Array.Copy(xBytes, 0, pubBytes, 48 - xBytes.Length, xBytes.Length);
                Array.Copy(yBytes, 0, pubBytes, 96 - yBytes.Length, yBytes.Length);
                Key = new I2PByteBlock(pubBytes);
            }
                break;

            case KeyTypes.P521:
            {
                var curve = ECNamedCurveTable.GetByName("secp521r1");
                var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                var privKeyParams = new ECPrivateKeyParameters(new BigInteger(1, priv.ToByteArray()), domainParams);
                var q = domainParams.G.Multiply(privKeyParams.D).Normalize();
                var xBytes = q.AffineXCoord.GetEncoded();
                var yBytes = q.AffineYCoord.GetEncoded();
                var pubBytes = new byte[132];
                Array.Copy(xBytes, 0, pubBytes, 66 - xBytes.Length, xBytes.Length);
                Array.Copy(yBytes, 0, pubBytes, 132 - yBytes.Length, yBytes.Length);
                Key = new I2PByteBlock(pubBytes);
            }
                break;

            default:
                Logging.LogWarning(
                    $"I2PPublicKey: Public key derivation not implemented for key type {Certificate.PublicKeyType}");
                Key = new I2PByteBlock(new byte[KeySizeBytes]);
                break;
        }
    }

    public I2PPublicKey(I2PBufferCursor buf, I2PCertificate cert) : base(buf, cert)
    {
    }

    public I2PPublicKey(BigInteger pubkey, I2PCertificate cert) : base(cert)
    {
        Key = new I2PByteBlock(pubkey.ToByteArrayUnsigned());
    }

    public override int KeySizeBytes => Certificate.PublicKeyLength;
}