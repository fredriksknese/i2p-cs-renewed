using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using I2PCore.Data;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace I2PCore.Utils;

public static class BufUtils
{
    // An IP should be considered as internal when:
    //
    // ::1          -   IPv6  loopback
    // 10.0.0.0     -   10.255.255.255  (10/8 prefix)
    // 127.0.0.0    -   127.255.255.255 (127/8 prefix)
    // 172.16.0.0   -   172.31.255.255  (172.16/12 prefix)
    // 192.168.0.0  -   192.168.255.255 (192.168/16 prefix)

    public static bool IsInternal(this IPAddress ipaddr)
    {
        var ip = ipaddr.GetAddressBytes();

        if (ip.Length == 6) return ip[5] == 1;

        switch (ip[0])
        {
            case 10:
            case 127:
                return true;
            case 172:
                return ip[1] >= 16 && ip[1] < 32;
            case 192:
                return ip[1] == 168;
            default:
                return false;
        }
    }

    public static string BytesToReadable(long i)
    {
        var absoluteI = i < 0 ? -i : i;
        string suffix;
        double readable;

        if (absoluteI >= 0x1000000000000000) // Exabyte
        {
            suffix = "EB";
            readable = i >> 50;
        }
        else if (absoluteI >= 0x4000000000000) // Petabyte
        {
            suffix = "PB";
            readable = i >> 40;
        }
        else if (absoluteI >= 0x10000000000) // Terabyte
        {
            suffix = "TB";
            readable = i >> 30;
        }
        else if (absoluteI >= 0x40000000) // Gigabyte
        {
            suffix = "GB";
            readable = i >> 20;
        }
        else if (absoluteI >= 0x100000) // Megabyte
        {
            suffix = "MB";
            readable = i >> 10;
        }
        else if (absoluteI >= 0x400) // Kilobyte
        {
            suffix = "KB";
            readable = i;
        }
        else
        {
            return i.ToString("0 B"); // Byte
        }

        readable = readable / 1024.0;
        return $"{readable:0.###} {suffix}";
    }

    public static Store GetStore(string filename, int sectorsize)
    {
        filename = Path.GetFullPath(filename);

        for (var i = 0; i < 5; ++i)
            try
            {
                return new Store(filename, sectorsize);
            }
            catch (IOException ex)
            {
                Logging.LogWarning($"GetStore file version mismatch. Deleting file '{filename}'.", ex);
                File.Delete(filename);
            }
            catch (Exception ex)
            {
                Logging.LogDebug("GetStore", ex);
                Thread.Sleep(500);
            }

        return null;
    }

    #region Endian conversion

    public static ulong Flip64(ulong src)
    {
        return BinaryPrimitives.ReverseEndianness(src);
    }

    public static uint Flip32(uint src)
    {
        return BinaryPrimitives.ReverseEndianness(src);
    }

    public static uint Flip32(byte[] buf, int offset)
    {
        return BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt32(buf, offset));
    }

    public static ushort Flip16(ushort src)
    {
        return BinaryPrimitives.ReverseEndianness(src);
    }

    public static ushort Flip16(byte[] buf, int offset)
    {
        return BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(buf, offset));
    }

    public static byte[] Flip64B(ulong src)
    {
        var buf = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(buf, src);
        return buf;
    }

    public static byte[] Flip32B(uint src)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, src);
        return buf;
    }

    public static I2PByteBlock Flip32Bl(uint src)
    {
        return new I2PByteBlock(Flip32B(src));
    }

    public static byte[] Flip16B(ushort src)
    {
        var buf = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buf, src);
        return buf;
    }

    public static I2PByteBlock Flip16Bl(ushort src)
    {
        return new I2PByteBlock(Flip16B(src));
    }

    public static byte[] To64B(ulong src)
    {
        return BitConverter.GetBytes(src);
    }

    public static I2PByteBlock To64Bl(ulong src)
    {
        return new I2PByteBlock(To64B(src));
    }

    public static byte[] To32B(uint src)
    {
        return BitConverter.GetBytes(src);
    }

    public static I2PByteBlock To32Bl(uint src)
    {
        return new I2PByteBlock(To32B(src));
    }

    public static byte[] To16B(ushort src)
    {
        return BitConverter.GetBytes(src);
    }

    public static I2PByteBlock To16Bl(ushort src)
    {
        return new I2PByteBlock(To16B(src));
    }

    public static byte[] To8B(byte src)
    {
        return new[] { src };
    }

    public static I2PByteBlock To8Bl(byte src)
    {
        return new I2PByteBlock(To8B(src));
    }

    #endregion

    #region Data structures to byte array

    public static byte[] Dhi2PToByteArray(BigInteger bi)
    {
        var result = new List<byte>();

        if (bi == BigInteger.Zero) throw new FormatException("BigInteger == 0 for DH key!");

        result.AddRange(bi.ToByteArray());

        if ((result[0] & 0x80) != 0) result.Insert(0, 0);

        while (result.Count < 32) result.Add(0);

        return result.Take(32).ToArray();
    }

    public static void Dhi2PToSessionAndMac(out I2PByteBlock sessionkey, out I2PByteBlock mackey, BigInteger bi)
    {
        var result = new List<byte>();

        if (bi == BigInteger.Zero) throw new FormatException("BigInteger == 0 for DH key!");

        result.AddRange(bi.ToByteArray());

        if ((result[0] & 0x80) != 0) result.Insert(0, 0);

        while (result.Count < 32) result.Add(0);

        sessionkey = new I2PByteBlock(result.Take(32).ToArray());

        if (result.Count >= 64)
            mackey = new I2PByteBlock(result.Skip(32).Take(32).ToArray());
        else
            mackey = new I2PByteBlock(I2PHashSha256.GetHash(result.ToArray()));
    }

    public static byte[] ToByteArray(this BigInteger bi, int length)
    {
        var ar = bi.ToByteArrayUnsigned();
        if (ar.Length == length) return ar;

        var result = new byte[length];
        if (ar.Length == 0) return result;

        if (ar.Length > length) throw new OverflowException("BigInteger does not fit in buffer!");
        Array.Copy(ar, 0, result, length - ar.Length, ar.Length);

        return result;
    }

    public static byte[] ToByteArray(this I2PType data)
    {
        var buf = new ArrayBufferWriter<byte>();
        data.Write(buf);
        return buf.WrittenSpan.ToArray();
    }

    public static byte[] ToByteArray(params I2PType[] fields)
    {
        var buf = new ArrayBufferWriter<byte>();
        foreach (var one in fields) one.Write(buf);
        return buf.WrittenSpan.ToArray();
    }

    #endregion

    #region Byte array operations

    public static bool Equal(byte[] b1, byte[] b2)
    {
        return b1.AsSpan().SequenceEqual(b2);
    }

    public static bool Equal(byte[] b1, int b1Offset, byte[] b2, int b2Offset, int length)
    {
        return b1.AsSpan(b1Offset, length).SequenceEqual(b2.AsSpan(b2Offset, length));
    }

    public static byte[] Copy(this byte[] b1, int offset, int length)
    {
        var buf = new byte[length];
        Array.Copy(b1, offset, buf, 0, length);
        return buf;
    }

    public static byte[] Copy(this byte[] b1, ref int offset, int length)
    {
        var result = b1.Copy(offset, length);
        offset += length;
        return result;
    }

    #endregion

    #region Crypto

    public static void AesEcbEncrypt(this I2PByteBlock buf, byte[] key)
    {
        var cipher = new AesEngine();
        cipher.Init(true, new KeyParameter(key));
        cipher.ProcessBlock(buf.BaseArray, buf.BaseArrayOffset, buf.BaseArray, buf.BaseArrayOffset);
    }

    public static void AesEcbEncrypt(this I2PByteBlock buf, I2PByteBlock key)
    {
        var cipher = new AesEngine();
        cipher.Init(true, new KeyParameter(key.BaseArray, key.BaseArrayOffset, key.Length));
        cipher.ProcessBlock(buf.BaseArray, buf.BaseArrayOffset, buf.BaseArray, buf.BaseArrayOffset);
    }

    public static void AesEcbDecrypt(this I2PByteBlock buf, byte[] key)
    {
        var cipher = new AesEngine();
        cipher.Init(false, new KeyParameter(key));
        cipher.ProcessBlock(buf.BaseArray, buf.BaseArrayOffset, buf.BaseArray, buf.BaseArrayOffset);
    }

    public static void AesEcbDecrypt(this I2PByteBlock buf, I2PByteBlock key)
    {
        var cipher = new AesEngine();
        cipher.Init(false, new KeyParameter(key.BaseArray, key.BaseArrayOffset, key.Length));
        cipher.ProcessBlock(buf.BaseArray, buf.BaseArrayOffset, buf.BaseArray, buf.BaseArrayOffset);
    }

    public static void Encrypt(this BufferedBlockCipher cipher, byte[] key, I2PByteBlock iv, I2PByteBlock data)
    {
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv.BaseArray, iv.BaseArrayOffset, iv.Length));
        cipher.ProcessBytes(data);
    }

    public static void Decrypt(this BufferedBlockCipher cipher, byte[] key, I2PByteBlock iv, I2PByteBlock data)
    {
        cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv.BaseArray, iv.BaseArrayOffset, iv.Length));
        cipher.ProcessBytes(data);
    }

    public static void Encrypt(this BufferedBlockCipher cipher, I2PByteBlock key, I2PByteBlock iv, I2PByteBlock data)
    {
        cipher.Init(true,
            new ParametersWithIV(new KeyParameter(key.BaseArray, key.BaseArrayOffset, key.Length), iv.BaseArray,
                iv.BaseArrayOffset, iv.Length));
        cipher.ProcessBytes(data);
    }

    public static void Decrypt(this BufferedBlockCipher cipher, I2PByteBlock key, I2PByteBlock iv, I2PByteBlock data)
    {
        cipher.Init(false,
            new ParametersWithIV(new KeyParameter(key.BaseArray, key.BaseArrayOffset, key.Length), iv.BaseArray,
                iv.BaseArrayOffset, iv.Length));
        cipher.ProcessBytes(data);
    }

    public static void Encrypt(this CbcBlockCipher cipher, I2PByteBlock key, I2PByteBlock iv, I2PByteBlock data)
    {
        cipher.Init(true, key.ToParametersWithIv(iv));
        cipher.ProcessBytes(data);
    }

    public static void Decrypt(this CbcBlockCipher cipher, I2PByteBlock key, I2PByteBlock iv, I2PByteBlock data)
    {
        cipher.Init(false, key.ToParametersWithIv(iv));
        cipher.ProcessBytes(data);
    }

    public static void ProcessBytes(this BufferedBlockCipher cipher, I2PByteBlock data)
    {
        cipher.ProcessBytes(data.BaseArray, data.BaseArrayOffset, data.Length, data.BaseArray, data.BaseArrayOffset);
    }

    public static void ProcessBytes(this CbcBlockCipher cipher, I2PByteBlock data)
    {
        if (Get16BytePadding(data.Length) != 0) throw new ArgumentException("Cbc needs blocks of 16 bytes!");

        var end = data.Length / 16;
        for (var i = 0; i < end; ++i)
            cipher.ProcessBlock(
                data.BaseArray, data.BaseArrayOffset + i * 16,
                data.BaseArray, data.BaseArrayOffset + i * 16);
    }

    public static KeyParameter ToKeyParameter(this I2PByteBlock key)
    {
        return new KeyParameter(key.BaseArray, key.BaseArrayOffset, key.Length);
    }

    public static ParametersWithIV ToParametersWithIv(this I2PByteBlock key, I2PByteBlock iv)
    {
        return new ParametersWithIV(key.ToKeyParameter(), iv.BaseArray, iv.BaseArrayOffset, iv.Length);
    }

    #endregion

    #region Misc often needed utils

    // Batch 1-4 (docs/PRODUCTION-PLAN.md): the single seam through which randomness enters
    // I2PCore. Before this, four independent doors existed -- BufUtils, System.Random (removed in
    // 1-3), static RandomNumberGenerator.Fill calls, and per-call `new SecureRandom()` -- so no
    // test could make a handshake reproducible. Everything now draws from RandomSource.
    //
    // The setter is internal on purpose: a host application must never be able to substitute the
    // generator that produces this router's ephemeral keys. It exists so tests can inject a
    // deterministic stream and diff protocol bytes; the deterministic implementation lives in the
    // test assembly, not here.
    private static RandomNumberGenerator _rnd = RandomNumberGenerator.Create();

    internal static RandomNumberGenerator RandomSource
    {
        get => _rnd;
        set => _rnd = value ?? RandomNumberGenerator.Create();
    }

    /// <summary>
    ///     BouncyCastle-facing view of <see cref="RandomSource" />. A single instance whose
    ///     generator reads the seam on every draw, so swapping RandomSource takes effect
    ///     immediately and callers need not re-create it.
    /// </summary>
    internal static readonly SecureRandom BcRandom = new(new RandomSourceGenerator());

    public static void Randomize(this byte[] buf, int offset, int length)
    {
        _rnd.GetBytes(buf, offset, length);
    }

    public static void Randomize(this byte[] buf)
    {
        _rnd.GetBytes(buf);
    }

    public static void Randomize(this I2PBufferCursor buf)
    {
        _rnd.GetBytes(buf.BaseArray, buf.BaseArrayOffset, buf.Remaining);
    }

    public static void Randomize(this I2PByteBlock buf)
    {
        _rnd.GetBytes(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
    }

    public static TV RandomValue<TK, TV>(this IDictionary<TK, TV> dic)
    {
        return dic[dic.Keys.Skip(RandomInt(dic.Keys.Count - 1))
            .Take(1).FirstOrDefault()];
    }

    public static KeyValuePair<TK, TV> Random<TK, TV>(this IDictionary<TK, TV> dic)
    {
        return dic.Skip(RandomInt(dic.Keys.Count - 1))
            .Take(1).FirstOrDefault();
    }

    public static T Random<T>(this IEnumerable<T> src)
    {
        var count = src.Count();
        if (count <= 0) return default;
        return src.Skip(RandomInt(count)).Take(1).FirstOrDefault();
    }

    public static bool EqualsDefaultValue<T>(T value)
    {
        return EqualityComparer<T>.Default.Equals(value, default);
    }

    /// <summary>
    ///     Select a random item with non uniform probability. Weight only determine the order, and the fittness is elitism^ix,
    ///     ix=1..n
    ///     See: "Fitness proportionate selection"
    /// </summary>
    /// <param name="elitism">
    ///     The how many times more probable the highest scoring item is choosen than the lowest scoring
    ///     item.
    /// </param>
    public static T RandomWeighted<T>(
        this IEnumerable<T> src,
        Func<T, double> weight,
        double elitism)
    {
        var count = src.Count();
        var inc = Math.Pow(elitism, 1.0 / (count - 1));

        var wsrc = src.Select(s => new
            {
                Obj = s,
                Weight = weight(s)
            })
            .OrderByDescending(s => s.Weight)
            .Select((s, ix) => new
            {
                s.Obj,
                Space = Math.Pow(inc, count - ix + 1)
            })
            .ToArray();

        var pos = 0.0;
        var spacesum = wsrc.Sum(s => s.Space);
        var target = RandomDouble(spacesum);

        foreach (var one in wsrc)
        {
            pos += one.Space;
            if (pos >= target)
            {
                Logging.LogDebugData($"RandomWeighted: {one.Obj}");
                return one.Obj;
            }
        }

        return src.Random();
    }

    private static readonly byte[] ZeroArray = new byte[0];

    public static byte[] RandomBytes(int bytes)
    {
        if (bytes == 0) return ZeroArray;

        var buf = new byte[bytes];
        _rnd.GetBytes(buf);
        return buf;
    }

    public static byte[] RandomNz(int bytes)
    {
        if (bytes == 0) return ZeroArray;

        var buf = new byte[bytes];
        _rnd.GetNonZeroBytes(buf);
        return buf;
    }

    public static uint RandomUint()
    {
        var buf = new byte[4];
        _rnd.GetBytes(buf);
        return BitConverter.ToUInt32(buf, 0);
    }

    public static uint RandomUintNz()
    {
        var buf = new byte[4];
        _rnd.GetNonZeroBytes(buf);
        return BitConverter.ToUInt32(buf, 0);
    }

    public static int RandomInt(int max)
    {
        var buf = new byte[4];
        _rnd.GetBytes(buf);
        return Math.Abs(BitConverter.ToInt32(buf, 0) % max);
    }

    public static float RandomFloat(float max)
    {
        return (float)RandomDouble() * max;
    }

    public static double RandomDouble(double max)
    {
        return RandomDouble() * max;
    }

    public static double RandomDouble()
    {
        var buf = new byte[8];
        _rnd.GetBytes(buf);
        var result = BitConverter.ToInt64(buf) & 0x001fffffffffffff;
        return result / (double)(1L << 53);
    }

    public static void Populate<T>(this IList<T> list, T value)
    {
        for (var i = 0; i < list.Count; ++i) list[i] = value;
    }

    public static IEnumerable<T> Populate<T>(T value, int count)
    {
        for (var i = 0; i < count; ++i) yield return value;
    }

    public static IEnumerable<T> Populate<T>(Func<T> gen, int count)
    {
        for (var i = 0; i < count; ++i) yield return gen();
    }

    private static IEnumerable<IEnumerable<T>> CartesianProduct<T>(
        this IEnumerable<IEnumerable<T>> sequences)
    {
        IEnumerable<IEnumerable<T>> empty = new[] { Enumerable.Empty<T>() };
        return sequences.Aggregate(
            empty,
            (accumulator, sequence) =>
                from accseq in accumulator
                from item in sequence
                select accseq.Concat(new[] { item }));
    }

    public static void ShuffleList<T>(this IList<T> list)
    {
        for (var i = 0; i < list.Count; i++)
        {
            var tmp = list[i];
            var ix = i + RandomInt(list.Count - i);
            list[i] = list[ix];
            list[ix] = tmp;
        }
    }

    public static IEnumerable<T> Shuffle<T>(this IEnumerable<T> source)
    {
        var list = source.ToArray();
        for (var i = 0; i < list.Length; ++i)
        {
            var ix = i + RandomInt(list.Length - i);
            yield return list[ix];
            list[ix] = list[i];
        }
    }

    public static float AbsDev(this IEnumerable<float> list)
    {
        var avg = list.Average();
        var count = list.Count();
        var result = list.Sum(one => Math.Abs(one - avg));
        return 1f / count * result;
    }

    public static float StdDev(this IEnumerable<float> list)
    {
        var result = 0f;
        var avg = list.Average();
        var count = 0;
        foreach (var one in list)
        {
            var v = one - avg;
            result += v * v;
            ++count;
        }

        return (float)Math.Sqrt(1f / (count - 1) * result);
    }

    public static float StdDev<T>(this IEnumerable<T> list, Func<T, float> select)
    {
        var result = 0f;
        var avg = list.Average(v => select(v));
        var count = 0;
        foreach (var one in list)
        {
            var v = select(one) - avg;
            result += v * v;
            ++count;
        }

        return (float)Math.Sqrt(1f / (count - 1) * result);
    }

    public static float CentMovem3<T>(this IEnumerable<T> list, Func<T, float> select)
    {
        var result = 0f;
        var avg = list.Average(v => select(v));
        var count = 0;
        foreach (var one in list)
        {
            var v = select(one) - avg;
            result += v * v * v;
            ++count;
        }

        return 1f / count * result;
    }

    public static float Skew<T>(this IEnumerable<T> list, Func<T, float> select)
    {
        return (float)(list.CentMovem3(v => select(v)) / Math.Pow(list.StdDev(v => select(v)), 3));
    }

    public struct HistogramBin
    {
        public float Start;
        public int Count;
    }

    public static HistogramBin[] Histogram<T>(this IEnumerable<T> list,
        Func<T, float> select,
        int bins,
        float lowerabsdevs = float.MaxValue,
        float upperabsdevs = float.MaxValue)
    {
        if (list == null || !list.Any()) return default;
        var dbgcount = list.Count();

        var result = new HistogramBin[bins];

        var avg = 0f;
        var absdev = 0f;

        var values = list.Select(v => select(v));

        if (lowerabsdevs != float.MaxValue || upperabsdevs != float.MaxValue)
        {
            avg = values.Average();
            absdev = values.AbsDev();
        }

        var min = values.Min();
        var max = values.Max();

        if (lowerabsdevs != float.MaxValue && list.Count() > 3) min = Math.Max(avg - absdev * lowerabsdevs, min);

        if (upperabsdevs != float.MaxValue && list.Count() > 3) max = Math.Min(avg + absdev * upperabsdevs, max);

        if (min == max) return result;

        for (var i = 0; i < bins; ++i) result[i].Start = i * ((max - min) / bins) + min;

        foreach (var one in values)
        {
            var val = one;

            if (lowerabsdevs != float.MaxValue && list.Count() > 3) val = Math.Max(avg - absdev * lowerabsdevs, val);

            if (upperabsdevs != float.MaxValue && list.Count() > 3) val = Math.Min(avg + absdev * upperabsdevs, val);

            var ix = Math.Max(0,
                Math.Min(
                    result.Length - 1,
                    (int)(bins * (val - min) / (max - min))));
            ++result[ix].Count;
        }

        return result;
    }

    public static int ComputeHash(this byte[] data)
    {
        return ComputeHash((ReadOnlySpan<byte>)data);
    }

    /// <summary>
    ///     FNV-1a over a span, with the same avalanche step the byte[] overload has always used.
    /// </summary>
    /// <remarks>
    ///     Batch 6-1 (docs/PRODUCTION-PLAN.md) added this so the tunnel traces can digest an
    ///     <c>I2PByteBlock</c> without copying it out first. It is a correlation handle for
    ///     following one message across two routers' logs, not a checksum — do not use it where
    ///     collisions matter.
    /// </remarks>
    public static int ComputeHash(this ReadOnlySpan<byte> data)
    {
        unchecked
        {
            const int p = 16777619;
            var hash = (int)2166136261;

            for (var i = 0; i < data.Length; ++i)
                hash = (hash ^ data[i]) * p;

            hash += hash << 13;
            hash ^= hash >> 7;
            hash += hash << 3;
            hash ^= hash >> 17;
            hash += hash << 5;
            return hash;
        }
    }

    public static int Get16BytePadding(int responselength)
    {
        return 0xF & (0x10 - (responselength & 0xF));
    }

    public static void RemoveAll<T>(this LinkedList<T> list, Func<T, bool> deleteeval)
    {
        var one = list.First;
        while (one != null)
        {
            var next = one.Next;

            if (deleteeval(one.Value)) list.Remove(one);

            one = next;
        }
    }

    public static IEnumerable<IEnumerable<T>> Chunk<T>(this IEnumerable<T> source, Func<IEnumerable<T>, int> chunksize)
    {
        while (source.Any())
        {
            var c = chunksize(source);
            yield return source.Take(c);
            source = source.Skip(c);
        }
    }

    public static IEnumerable<string> Chunks(this string str, int chunksize)
    {
        for (var i = 0; i < str.Length; i += chunksize)
            yield return str.Substring(i, Math.Min(chunksize, str.Length - i));
    }

    #endregion

    #region Encodings

    public static byte[] Base32ToByteArray(string input)
    {
        if (string.IsNullOrEmpty(input)) throw new ArgumentException("Null input");

        input = input.TrimEnd('=');
        var bytecount = input.Length * 5 / 8;
        var result = new byte[bytecount];

        byte curbyte = 0, bitsremaining = 8;
        int mask = 0, ix = 0;

        foreach (var c in input)
        {
            var cval = Base32CharToInt(c);

            if (bitsremaining > 5)
            {
                mask = cval << (bitsremaining - 5);
                curbyte = (byte)(curbyte | mask);
                bitsremaining -= 5;
            }
            else
            {
                mask = cval >> (5 - bitsremaining);
                curbyte = (byte)(curbyte | mask);
                result[ix++] = curbyte;
                curbyte = (byte)(cval << (3 + bitsremaining));
                bitsremaining += 3;
            }
        }

        if (ix != bytecount) result[ix] = curbyte;

        return result;
    }

    public static string ToBase32String(byte[] input)
    {
        return ToBase32String(new I2PByteBlock(input));
    }

    public static string ToBase32String(I2PByteBlock input)
    {
        if (input.IsEmpty || input.Length == 0) return "";

        var result = new StringBuilder();
        var charcount = (int)Math.Ceiling(input.Length / 5d) * 8;

        byte nextchar = 0;
        byte bitsremaining = 5;

        foreach (var b in input)
        {
            nextchar = (byte)(nextchar | (b >> (8 - bitsremaining)));
            result.Append(ToBase32Char(nextchar));

            if (bitsremaining < 4)
            {
                nextchar = (byte)((b >> (3 - bitsremaining)) & 31);
                result.Append(ToBase32Char(nextchar));
                bitsremaining += 5;
            }

            bitsremaining -= 3;
            nextchar = (byte)((b << bitsremaining) & 31);
        }

        if (result.Length != charcount) result.Append(ToBase32Char(nextchar));

        return result.ToString();
    }

    private static int Base32CharToInt(char c)
    {
        var value = (int)c;

        // 65-90 == uppercase letters
        if (value < 91 && value > 64) return value - 65;
        // 50-55 == numbers 2-7
        if (value < 56 && value > 49) return value - 24;
        // 97-122 == lowercase letters
        if (value < 123 && value > 96) return value - 97;

        throw new ArgumentException("Character is not a Base32 character.", "c");
    }

    private static char ToBase32Char(byte b)
    {
        if (b < 26) return (char)(b + 97);

        if (b < 32) return (char)(b + 24);

        throw new ArgumentException("Byte is not a value Base32 value.", "b");
    }

    #endregion
}