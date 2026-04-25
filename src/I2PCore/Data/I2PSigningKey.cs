using I2PCore.Utils;
using Org.BouncyCastle.Math;

namespace I2PCore.Data;

public abstract class I2PSigningKey : I2PKeyType
{
    public enum SigningKeyTypes : ushort
    {
        Invalid = ushort.MaxValue,
        DsaSha1 = 0,
        EcdsaSha256P256 = 1,
        EcdsaSha384P384 = 2,
        EcdsaSha512P521 = 3,
        RsaSha2562048 = 4,
        RsaSha3843072 = 5,
        RsaSha5124096 = 6,
        EdDsaSha512Ed25519 = 7,
        EdDsaSha512Ed25519ph = 8,
        GostR34102012_256 = 9,
        GostR34102012_512 = 10,
        RedDsaSha512Ed25519 = 11,
        MlDsa44 = 12
    }

    protected I2PSigningKey(I2PCertificate cert) : base(cert)
    {
    }

    public I2PSigningKey(I2PBufferCursor reader, I2PCertificate cert) : base(reader, cert)
    {
    }

    public I2PSigningKey(BigInteger key, I2PCertificate cert) : base(cert)
    {
        var buf = key.ToByteArrayUnsigned();
        if (buf.Length == KeySizeBytes)
        {
            Key = new I2PByteBlock(buf);
        }
        else
        {
            Key = new I2PByteBlock(new byte[KeySizeBytes]);
            Key.CopyFrom(buf, KeySizeBytes - buf.Length);
        }
    }

    public I2PSigningKey(I2PByteBlock key, I2PCertificate cert)
        : base(cert)
    {
        if (key.Length == KeySizeBytes)
        {
            Key = key;
        }
        else if (key.Length < KeySizeBytes)
        {
            Key = new I2PByteBlock(new byte[KeySizeBytes]);
            Key.CopyFrom(key, KeySizeBytes - key.Length);
        }
        else
        {
            Key = new I2PByteBlock(key.BaseArray, key.BaseArrayOffset, KeySizeBytes);
        }
    }

    public static int SigningPublicKeyLength(SigningKeyTypes skt)
    {
        switch (skt)
        {
            case SigningKeyTypes.DsaSha1:
                return 128;

            case SigningKeyTypes.EcdsaSha256P256:
                return 65;

            case SigningKeyTypes.EcdsaSha384P384:
                return 97;

            case SigningKeyTypes.EdDsaSha512Ed25519:
            case SigningKeyTypes.EdDsaSha512Ed25519ph:
            case SigningKeyTypes.RedDsaSha512Ed25519:
                return 32;

            case SigningKeyTypes.GostR34102012_256:
                return 64;

            case SigningKeyTypes.GostR34102012_512:
                return 128;

            case SigningKeyTypes.EcdsaSha512P521:
                return 133;

            case SigningKeyTypes.RsaSha2562048:
                return 256;

            case SigningKeyTypes.RsaSha3843072:
                return 384;

            case SigningKeyTypes.RsaSha5124096:
                return 512;

            case SigningKeyTypes.MlDsa44:
                return 1312; // MLDSA44_PUBLIC_KEY_LENGTH

            default:
                Logging.LogWarning($"I2PSigningKey: Unknown signing key type {skt} for SigningPublicKeyLength");
                return 128; // Default fallback
        }
    }

    public static int SigningPrivateKeyLength(SigningKeyTypes skt)
    {
        switch (skt)
        {
            case SigningKeyTypes.DsaSha1:
                return 20;

            case SigningKeyTypes.EcdsaSha256P256:
                return 32;

            case SigningKeyTypes.EcdsaSha384P384:
                return 48;

            case SigningKeyTypes.EdDsaSha512Ed25519:
            case SigningKeyTypes.EdDsaSha512Ed25519ph:
            case SigningKeyTypes.RedDsaSha512Ed25519:
                return 32;

            case SigningKeyTypes.GostR34102012_256:
                return 32;

            case SigningKeyTypes.GostR34102012_512:
                return 64;

            case SigningKeyTypes.EcdsaSha512P521:
                return 66;

            case SigningKeyTypes.RsaSha2562048:
                return 512;

            case SigningKeyTypes.RsaSha3843072:
                return 768;

            case SigningKeyTypes.RsaSha5124096:
                return 1024;

            case SigningKeyTypes.MlDsa44:
                return 2560; // MLDSA44_PRIVATE_KEY_LENGTH

            default:
                Logging.LogWarning($"I2PSigningKey: Unknown signing key type {skt} for SigningPrivateKeyLength");
                return 20; // Default fallback
        }
    }

    public static int SignatureLength(SigningKeyTypes skt)
    {
        switch (skt)
        {
            case SigningKeyTypes.DsaSha1:
                return 40;

            case SigningKeyTypes.EcdsaSha256P256:
                return 64;

            case SigningKeyTypes.EcdsaSha384P384:
                return 96;

            case SigningKeyTypes.EdDsaSha512Ed25519:
            case SigningKeyTypes.EdDsaSha512Ed25519ph:
            case SigningKeyTypes.RedDsaSha512Ed25519:
                return 64;

            case SigningKeyTypes.GostR34102012_256:
                return 64;

            case SigningKeyTypes.GostR34102012_512:
                return 128;

            case SigningKeyTypes.EcdsaSha512P521:
                return 132;

            case SigningKeyTypes.RsaSha2562048:
                return 256;

            case SigningKeyTypes.RsaSha3843072:
                return 384;

            case SigningKeyTypes.RsaSha5124096:
                return 512;

            case SigningKeyTypes.MlDsa44:
                return 2420; // MLDSA44_SIGNATURE_LENGTH

            default:
                Logging.LogWarning($"I2PSigningKey: Unknown signing key type {skt} for SignatureLength");
                return 40; // Default fallback
        }
    }
}