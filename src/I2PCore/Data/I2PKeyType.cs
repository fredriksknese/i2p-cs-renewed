using System.Buffers;
using I2PCore.Utils;
using Org.BouncyCastle.Math;

namespace I2PCore.Data;

public abstract class I2PKeyType : I2PType
{
    public enum KeyTypes : ushort
    {
        Invalid = ushort.MaxValue,
        NotImplemented = ushort.MaxValue - 1,
        ElGamal2048 = 0,
        P256 = 1,
        P384 = 2,
        P521 = 3,
        X25519 = 4,
        MLKEM512_X25519 = 5,
        MLKEM768_X25519 = 6,
        MLKEM1024_X25519 = 7,

        // Handshake-only types (not used in KeysAndCert)
        MLKEM512 = 100,
        MLKEM768 = 101,
        MLKEM1024 = 102,
        MLKEM512_CT = 103,
        MLKEM768_CT = 104,
        MLKEM1024_CT = 105
    }

    // Replace when ElGamal is optional
    public static readonly I2PCertificate DefaultAsymetricKeyCert = new();

    public static readonly I2PCertificate DefaultSigningKeyCert = new();

    public readonly I2PCertificate Certificate;
    public I2PByteBlock Key;

    protected I2PKeyType(I2PCertificate cert)
    {
        Certificate = cert;
    }

    protected I2PKeyType(I2PBufferCursor buf, I2PCertificate cert)
    {
        Certificate = cert;
        Key = buf.ReadBlock(KeySizeBytes);
    }

    public int KeySizeBits => KeySizeBytes * 8;
    public abstract int KeySizeBytes { get; }

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteBytes(ToByteArray());
    }

    public byte[] ToByteArray()
    {
        return Key.ToByteArray();
    }

    public BigInteger ToBigInteger()
    {
        return Key.ToBigInteger();
    }

    public override string ToString()
    {
        return $"I2PKeyType {GetType().Name}" +
               $"Key : {KeySizeBits} bits, {KeySizeBytes} bytes." +
               $"Key : {Key}";
    }

    public static KeyTypes Parse(string name)
    {
        if (ushort.TryParse(name, out var id))
        {
            return (KeyTypes)id;
        }

        var normalized = name.Replace("_", "").Replace("-", "").ToUpperInvariant();
        return normalized switch
        {
            "ELGAMAL2048" or "ELGAMAL" or "0" => KeyTypes.ElGamal2048,
            "P256" or "1" => KeyTypes.P256,
            "P384" or "2" => KeyTypes.P384,
            "P521" or "3" => KeyTypes.P521,
            "X25519" or "ECIESX25519" or "4" => KeyTypes.X25519,
            "MLKEM512X25519" or "5" => KeyTypes.MLKEM512_X25519,
            "MLKEM768X25519" or "6" => KeyTypes.MLKEM768_X25519,
            "MLKEM1024X25519" or "7" => KeyTypes.MLKEM1024_X25519,
            _ => KeyTypes.Invalid
        };
    }

    public static int PublicKeyLength(KeyTypes kt)
    {
        switch (kt)
        {
            case KeyTypes.ElGamal2048:
                return 256;

            case KeyTypes.P256:
                return 64;

            case KeyTypes.P384:
                return 96;

            case KeyTypes.P521:
                return 132;

            case KeyTypes.X25519:
            case KeyTypes.MLKEM512_X25519:
            case KeyTypes.MLKEM768_X25519:
            case KeyTypes.MLKEM1024_X25519:
                return 32;

            case KeyTypes.MLKEM512:
                return 800;

            case KeyTypes.MLKEM768:
                return 1184;

            case KeyTypes.MLKEM1024:
                return 1568;

            case KeyTypes.MLKEM512_CT:
                return 768;

            case KeyTypes.MLKEM768_CT:
                return 1088;

            case KeyTypes.MLKEM1024_CT:
                return 1568;

            default:
                Logging.LogWarning($"I2PKeyType: Unknown key type {kt} for PublicKeyLength");
                return 256; // Default ElGamal length
        }
    }

    public static int PrivateKeyLength(KeyTypes kt)
    {
        switch (kt)
        {
            case KeyTypes.ElGamal2048:
                return 256;

            case KeyTypes.P256:
                return 32;

            case KeyTypes.P384:
                return 48;

            case KeyTypes.P521:
                return 66;

            case KeyTypes.X25519:
            case KeyTypes.MLKEM512_X25519:
            case KeyTypes.MLKEM768_X25519:
            case KeyTypes.MLKEM1024_X25519:
                return 32;

            case KeyTypes.MLKEM512:
                return 1632;

            case KeyTypes.MLKEM768:
                return 2400;

            case KeyTypes.MLKEM1024:
                return 3168;

            default:
                Logging.LogWarning($"I2PKeyType: Unknown key type {kt} for PrivateKeyLength");
                return 256; // Default ElGamal length
        }
    }
}