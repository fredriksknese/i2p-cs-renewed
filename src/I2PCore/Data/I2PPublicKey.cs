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
                // ToByteArray(length), not ToByteArrayUnsigned(): the latter drops leading zero
                // bytes, so roughly one ElGamal key in 256 came out 255 bytes long (and one in
                // 65536 shorter still). I2P public keys are fixed width, so a short key
                // serialised into a Destination shifts every field after it and the peer reads
                // a corrupt group element -- "y value does not appear to be in correct group".
                // Rare enough to look like a flaky test rather than a key that was born broken.
                Key = new I2PByteBlock(I2PConstants
                    .ElGamalG.ModPow(
                        priv.ToBigInteger(),
                        I2PConstants.ElGamalP)
                    .ToByteArray(Certificate.PublicKeyLength));
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
        // Left-padded for the same reason as the ElGamal derivation above. The signing-key
        // counterpart, I2PSigningKey(BigInteger, I2PCertificate), has always padded here; this
        // one did not, which is the asymmetry that hid the bug.
        Key = new I2PByteBlock(pubkey.ToByteArray(cert.PublicKeyLength));
    }

    public override int KeySizeBytes => Certificate.PublicKeyLength;
}