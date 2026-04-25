using System;
using System.Security.Cryptography;
using I2PCore.Utils;
using Org.BouncyCastle.Math;

namespace I2PCore.Crypto;

/// <summary>
///     Elligator2 encoding/decoding for X25519 ephemeral keys.
///     Ported from Java I2P (net.i2p.router.crypto.ratchet.Elligator2).
/// </summary>
public static class Elligator2
{
    private static readonly BigInteger P = BigInteger.Two.Pow(255).Subtract(BigInteger.ValueOf(19));
    private static readonly BigInteger A = BigInteger.ValueOf(486662);
    private static readonly BigInteger NegativeA = P.Subtract(A);
    private static readonly BigInteger U = BigInteger.Two;
    private static readonly BigInteger InvertedU = U.ModInverse(P);

    private static readonly BigInteger DivideMinusP12 = P.Subtract(BigInteger.One).Divide(BigInteger.Two);
    private static readonly BigInteger DivideMinusP14 = DivideMinusP12.Divide(BigInteger.Two);
    private static readonly BigInteger DividePlusP38 = P.Add(BigInteger.ValueOf(3)).Divide(BigInteger.ValueOf(8));
    private static readonly BigInteger SqrtM1 = BigInteger.Two.ModPow(DivideMinusP14, P);

    /// <summary>
    ///     Generate a new X25519 private key that maps to an Elligator2-encodable public key.
    /// </summary>
    public static byte[] GenerateEncodablePrivateKey()
    {
        var privateKey = new byte[32];
        var maxAttempts = 1000;

        for (var i = 0; i < maxAttempts; i++)
        {
            RandomNumberGenerator.Fill(privateKey);
            X25519.ClampPrivateKey(privateKey);

            var publicKey = X25519.GetPublicKey(privateKey);
            if (CanEncode(publicKey)) return privateKey;
        }

        throw new InvalidOperationException($"Failed to generate encodable private key after {maxAttempts} attempts");
    }

    public static bool CanEncode(byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length != 32) return false;
        return InternalEncode(publicKey, false, 0) != null;
    }

    /// <summary>
    ///     Encode an X25519 public key using Elligator2.
    ///     Returns 32-byte representative or null on failure.
    /// </summary>
    public static byte[] Encode(byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length != 32)
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKey));

        // For on-the-wire, use randomized version like Java I2P
        var rand = (byte)BufUtils.RandomUint();
        var result = InternalEncode(publicKey, (rand & 0x01) == 0, rand);

        if (result == null)
            // If the first choice of 'alternative' failed, try the other one
            result = InternalEncode(publicKey, (rand & 0x01) != 0, rand);

        if (result == null)
            throw new InvalidOperationException(
                "Public key cannot be Elligator2 encoded. Use GenerateEncodablePrivateKey()");

        return result;
    }

    private static byte[] InternalEncode(byte[] publicKey, bool alternative, byte highBits)
    {
        // x coordinate (Montgomery)
        var x = new BigInteger(1, ReverseBytes(publicKey));

        if (x.SignValue == 0) alternative = false;

        // negative_plus_x_A = -(x + A) (mod p)
        var negativePlusXA = x.Add(A).Negate().Mod(P);

        // val = -ux(x + A) (mod p)
        var val = U.Multiply(x).Mod(P);
        val = val.Multiply(negativePlusXA).Mod(P);

        // If -ux(x + A) is not a square modulo p
        if (Legendre(val) == -1) return null;

        BigInteger r;
        if (alternative)
            // r := -(x + A) / x (mod p)
            r = x.ModInverse(P).Multiply(negativePlusXA).Mod(P);
        else
            // r := -x / (x + A) (mod p)
            r = negativePlusXA.ModInverse(P).Multiply(x).Mod(P);

        // r := square_root(r / u) (mod p)
        r = r.Multiply(InvertedU).Mod(P);
        r = ModSqrt(r);

        // little-endian
        var rv = ToLittleEndian(r, 32);
        // randomize two high bits
        rv[31] |= (byte)(highBits & 0xC0);
        return rv;
    }

    /// <summary>
    ///     Decode an Elligator2 representative back to an X25519 public key.
    /// </summary>
    public static byte[] Decode(byte[] representative)
    {
        if (representative == null || representative.Length != 32)
            return null;

        var rBytes = (byte[])representative.Clone();
        rBytes[31] &= 0x3F; // Mask out high two bits

        var r = new BigInteger(1, ReverseBytes(rBytes));

        // If r >= (p - 1) / 2
        if (r.CompareTo(DivideMinusP12) >= 0)
            return null;

        // v = -A / (1 + ur^2) (mod p)
        var v = r.Multiply(r).Mod(P);
        v = v.Multiply(U).Mod(P);
        v = v.Add(BigInteger.One).Mod(P);
        v = v.ModInverse(P).Multiply(NegativeA).Mod(P);

        // t = v^3 + Av^2 + v (Montgomery equation with B=1)
        var plusVA = v.Add(A).Mod(P);
        var t = v.Multiply(v).Mod(P);
        t = t.Multiply(plusVA).Mod(P);
        t = t.Add(v).Mod(P);

        var e = Legendre(t);
        BigInteger x;
        if (e == 1)
            x = v;
        else
            x = P.Subtract(v).Subtract(A).Mod(P);

        return ToLittleEndian(x, 32);
    }

    private static int Legendre(BigInteger a)
    {
        if (a.SignValue == 0) return 0;
        var mp = a.ModPow(DivideMinusP12, P);
        return mp.Equals(BigInteger.One) ? 1 : -1;
    }

    private static BigInteger ModSqrt(BigInteger x)
    {
        var t = x.ModPow(DivideMinusP14, P);
        var result = x.ModPow(DividePlusP38, P);

        // If t = -1 (mod p)
        if (t.Add(BigInteger.One).Mod(P).Equals(BigInteger.Zero)) result = result.Multiply(SqrtM1).Mod(P);

        // If result > (p - 1) / 2, use -result
        if (result.CompareTo(DivideMinusP12) > 0) result = P.Subtract(result);
        return result;
    }

    private static byte[] ReverseBytes(byte[] bytes)
    {
        var rev = new byte[bytes.Length];
        for (var i = 0; i < bytes.Length; i++) rev[i] = bytes[bytes.Length - 1 - i];
        return rev;
    }

    private static byte[] ToLittleEndian(BigInteger n, int length)
    {
        var bytes = n.ToByteArrayUnsigned();
        var res = new byte[length];
        var copyLen = Math.Min(bytes.Length, length);
        for (var i = 0; i < copyLen; i++) res[i] = bytes[bytes.Length - 1 - i];
        return res;
    }

    public static byte[] GenerateRandomRepresentative()
    {
        var representative = new byte[32];
        RandomNumberGenerator.Fill(representative);
        representative[31] &= 0x7F; // Clear top bit
        return representative;
    }
}