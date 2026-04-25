using System;
using I2PCore.Data;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace I2PCore.Utils;

public static class ElGamalCrypto
{
    public const int ClearTextLength = 222;
    public const int EncryptedPaddedLength = 514;
    public const int EncryptedShortLength = 512;
    public const int EgBlockLength = 255;

    private static readonly SecureRandom Rnd = new();

    public static byte[] Encrypt(I2PByteBlock data, I2PPublicKey key, bool zeropad)
    {
        var result = new byte[zeropad ? EncryptedPaddedLength : EncryptedShortLength];
        Encrypt(new I2PBufferCursor(result), data, key, zeropad);
        return result;
    }

    public static void Encrypt(I2PBufferCursor dest, I2PByteBlock data, I2PPublicKey key, bool zeropad)
    {
        if (data.IsEmpty || data.Length > ClearTextLength)
            throw new InvalidParameterException($"ElGamal data must be {ClearTextLength} bytes or less!");

        var k = new BigInteger(I2PConstants.ElGamalFullExponentBits, Rnd);
        var a = I2PConstants.ElGamalG.ModPow(k, I2PConstants.ElGamalP);
        var b1 = key.ToBigInteger().ModPow(k, I2PConstants.ElGamalP);

        var startbuf = new byte[EgBlockLength];
        var start = new I2PByteBlock(startbuf);
        var writer = new I2PBufferCursor(startbuf, 1);

        start[0] = 0xFF;

        writer.WriteBytes(I2PHashSha256.GetHash(data));
        writer.WriteBlock(data);
        var egblock = new I2PByteBlock(startbuf, 0, writer.Position);
        var egint = egblock.ToBigInteger();

        var b = b1.Multiply(egint).Mod(I2PConstants.ElGamalP);

        var targetlen = zeropad
            ? EncryptedPaddedLength / 2
            : EncryptedShortLength / 2;

        WriteToDest(dest, a, targetlen);
        WriteToDest(dest, b, targetlen);
    }

    private static void WriteToDest(I2PBufferCursor dest, BigInteger v, int targetlen)
    {
        var vba = v.ToByteArray();
        if (vba.Length < targetlen) dest.WriteBytes(new byte[targetlen - vba.Length]);

        if (vba.Length > targetlen)
        {
            var trimmed = new byte[targetlen];
            Array.Copy(vba, vba.Length - targetlen, trimmed, 0, targetlen);
            dest.WriteBytes(trimmed);
        }
        else
        {
            dest.WriteBytes(vba);
        }
    }

    public static I2PByteBlock Decrypt(I2PByteBlock data, I2PPrivateKey pkey, bool zeropad)
    {
        if (data.IsEmpty || (zeropad && data.Length != EncryptedPaddedLength))
            throw new ArgumentException(
                $"ElGamal padded data ({data.Length}) to decrypt must be exactly {EncryptedPaddedLength} bytes!");

        if (!zeropad && data.Length != EncryptedShortLength)
            throw new ArgumentException(
                $"ElGamal data ({data.Length}) to decrypt must be exactly {EncryptedShortLength} bytes!");

        var x = I2PConstants.ElGamalPMinusOne.Subtract(pkey.ToBigInteger());

        var reader = new I2PBufferCursor(data);

        var readlen = zeropad
            ? EncryptedPaddedLength / 2
            : EncryptedShortLength / 2;

        var a = reader.ReadBigInteger(readlen);
        var b = reader.ReadBigInteger(readlen);

        var m2 = b.Multiply(a.ModPow(x, I2PConstants.ElGamalP));
        var m1 = m2.Mod(I2PConstants.ElGamalP);
        var m = m1.ToByteArrayUnsigned();
        var payload = new I2PByteBlock(m, 33, ClearTextLength);
        var hash = I2PHashSha256.GetHash(payload);
        if (!BufUtils.Equal(m, 1, hash, 0, 32)) throw new ChecksumFailureException();

        return payload;
    }
}