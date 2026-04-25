using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

[TestFixture]
public class UtilsTest
{
    [Test]
    public void TestTickCounter()
    {
        var start = new TickCounter();

        Assert.IsTrue(TickCounter.MaxDelta.DeltaToNowMilliseconds > 0);
        Assert.IsTrue(TickCounter.MaxDelta.DeltaToNow > TickSpan.Milliseconds(0));

        var maxd = TickCounter.MaxDelta;
        Thread.Sleep(200);

        Assert.IsTrue(maxd.DeltaToNowMilliseconds > 0);
        Assert.IsTrue(maxd.DeltaToNowMilliseconds > int.MaxValue / 2);

        Assert.IsTrue(maxd.DeltaToNow > TickSpan.Milliseconds(0));
        Assert.IsTrue(maxd.DeltaToNow > TickSpan.Milliseconds(int.MaxValue / 2));

        Assert.IsTrue(start.DeltaToNowMilliseconds > 0);
        Assert.IsTrue(start.DeltaToNow > TickSpan.Milliseconds(0));

        Assert.IsTrue((int)Math.Round((TickCounter.Now - start).ToSeconds / 3f)
                      == (int)Math.Round(start.DeltaToNowSeconds / 3f));

        Assert.IsTrue((int)Math.Round(((TickCounter.Now - start) / 3f).ToSeconds)
                      == (int)Math.Round((start.DeltaToNow / 3f).ToSeconds));

        var startCopy = new TickCounter(start.Ticks);

        Thread.Sleep(BufUtils.RandomInt(300) + 200);

        var startdelta = start.DeltaToNowMilliseconds;
        var startdeltaspan = start.DeltaToNow;
        var now1 = new TickCounter();

        Assert.IsTrue(start.ToString().Length > 0);

        Assert.IsTrue((now1 - start).ToMilliseconds > 0);
        Assert.IsTrue((now1 - start).ToMilliseconds / 100 == startdelta / 100);

        Assert.IsTrue(now1 - start > TickSpan.Milliseconds(0));
        Assert.IsTrue((now1 - start) / 100 == startdeltaspan / 100);
    }

    [Test]
    public void TestTickCounterWraparound()
    {
        // Range is 0 to 0x7FFFFFFF (2^31 - 1)
        var start = 0x7FFFFFFF;
        var end = 0;
        Assert.AreEqual(1, TickCounter.TimeDeltaMs(end, start), "Wraparound from 0x7FFFFFFF to 0 should be 1");

        start = 0x7FFFFFFF;
        end = 100;
        Assert.AreEqual(101, TickCounter.TimeDeltaMs(end, start), "Wraparound from 0x7FFFFFFF to 100 should be 101");

        start = 0x7FFFFFF0;
        end = 0x10;
        Assert.AreEqual(0x10 + (0x7FFFFFFF - 0x7FFFFFF0) + 1, TickCounter.TimeDeltaMs(end, start));

        // Normal case
        start = 100;
        end = 200;
        Assert.AreEqual(100, TickCounter.TimeDeltaMs(end, start));

        // Max delta case
        start = 1;
        end = 0;
        Assert.AreEqual(0, TickCounter.TimeDeltaMs(end, start), "Delta from 1 to 0 should be 0 (jitter)");

        // Future case (jitter)
        start = 1000;
        end = 999;
        Assert.AreEqual(0, TickCounter.TimeDeltaMs(end, start), "Jitter should return 0");

        start = 60000; // 1 min
        end = 0;
        Assert.AreEqual(0, TickCounter.TimeDeltaMs(end, start), "1 min negative difference should return 0");

        // Real large difference
        start = 0x40000000; // 12 days
        end = 0;
        Assert.AreEqual(0x40000000, TickCounter.TimeDeltaMs(end, start), "12 days difference should be preserved");

        // Wraparound is still fine
        start = 0x7FFFFFFF;
        end = 0;
        Assert.AreEqual(1, TickCounter.TimeDeltaMs(end, start));
    }

    [Test]
    public void TestGZip()
    {
        var smalldata = BufUtils.RandomBytes(200);
        var bigdata = BufUtils.RandomBytes(2 * 1024 * 1024);

        var smalldataZero = new byte[200];
        var bigdataZero = new byte[2 * 1024 * 1024];

        var b1 = LzUtils.BcgZipCompressNew(new I2PByteBlock(smalldata));
        var b2 = LzUtils.BcgZipDecompressNew(b1);
        Assert.IsTrue(b2 == new I2PByteBlock(smalldata));

        b1 = LzUtils.BcgZipCompressNew(new I2PByteBlock(bigdata));
        b2 = LzUtils.BcgZipDecompressNew(b1);
        Assert.IsTrue(b2 == new I2PByteBlock(bigdata));

        b1 = LzUtils.BcgZipCompressNew(new I2PByteBlock(smalldataZero));
        b2 = LzUtils.BcgZipDecompressNew(b1);
        Assert.IsTrue(b2 == new I2PByteBlock(smalldataZero));

        b1 = LzUtils.BcgZipCompressNew(new I2PByteBlock(bigdataZero));
        b2 = LzUtils.BcgZipDecompressNew(b1);
        Assert.IsTrue(b2 == new I2PByteBlock(bigdataZero));

        var ba1 = LzUtils.BcgZipCompress(bigdata);
        b2 = LzUtils.BcgZipDecompressNew(new I2PByteBlock(ba1));
        Assert.IsTrue(b2 == new I2PByteBlock(bigdata));

        b1 = LzUtils.BcgZipCompressNew(new I2PByteBlock(bigdataZero));
        var ba2 = LzUtils.BcgZipDecompressNew(b1);
        Assert.IsTrue(ba2 == new I2PByteBlock(bigdataZero));

        for (var i = bigdata.Length / 10; i < bigdata.Length - bigdata.Length / 10; ++i) bigdata[i] = 42;
        b1 = LzUtils.BcgZipCompressNew(new I2PByteBlock(bigdata));
        b2 = LzUtils.BcgZipDecompressNew(b1);
        Assert.IsTrue(b2 == new I2PByteBlock(bigdata));
    }

    [Test]
    public void TestRoulette()
    {
        var samples = 10000;
        var ftweight = 30f;
        var spaceboost = 1000;
        var minexpected = 1.0 / 256 * samples * 3;

        for (var runs = 0; runs < 20; ++runs)
        {
            var l = BufUtils.RandomBytes(samples).AsEnumerable();
            var r = new RouletteSelection<byte, byte>(
                l, v => v,
                k => k == 42 ? ftweight : 1f,
                samples,
                Math.Pow(spaceboost, 1.0 / samples));

            var is42 = l.Sum(_ => r.GetWeightedRandom(null) == 42 ? 1 : 0);

            Assert.IsTrue(is42 > minexpected);
        }
    }

    [Test]
    public void TestRandomWeghted()
    {
        var samples = new[] { 1, 2, 3, 30, 60 };

        var isone = 0;
        var issixty = 0;

        for (var runs = 0; runs < 10000; ++runs)
        {
            var l = samples.RandomWeighted(i => i, 200);
            if (l == 1) ++isone;
            if (l == 60) ++issixty;
        }

        Assert.IsTrue(issixty > 130 * isone);
    }

    [Test]
    public void TestBase32()
    {
        /* Test vectors from RFC 4648 */
        /*
        Assert.IsTrue( TestBase32Enc( "", "" ) );
        Assert.IsTrue( TestBase32Enc( "f", "MY======" ) );
        Assert.IsTrue( TestBase32Enc( "fo", "MZXQ====" ) );
        Assert.IsTrue( TestBase32Enc( "foo", "MZXW6===" ) );
        Assert.IsTrue( TestBase32Enc( "foob", "MZXW6YQ=" ) );
        Assert.IsTrue( TestBase32Enc( "fooba", "MZXW6YTB" ) );
        Assert.IsTrue( TestBase32Enc( "foobar", "MZXW6YTBOI======" ) );
         */
        Assert.IsTrue(TestBase32Enc("", ""));
        Assert.IsTrue(TestBase32Enc("f", "MY"));
        Assert.IsTrue(TestBase32Enc("fo", "MZXQ"));
        Assert.IsTrue(TestBase32Enc("foo", "MZXW6"));
        Assert.IsTrue(TestBase32Enc("foob", "MZXW6YQ"));
        Assert.IsTrue(TestBase32Enc("fooba", "MZXW6YTB"));
        Assert.IsTrue(TestBase32Enc("foobar", "MZXW6YTBOI"));
    }

    private bool TestBase32Enc(string src, string expected)
    {
        var enc = Encoding.ASCII.GetBytes(src);
        var encb32 = BufUtils.ToBase32String(enc);
        return encb32 == expected.ToLower();
    }

    [Test]
    public void TestRandomDouble()
    {
        var values = Enumerable
            .Range(0, 10000)
            .Select(i => BufUtils.RandomDouble())
            .ToArray();

        var expecteddev = Math.Sqrt(1.0 / 12);

        Assert.IsTrue(values.All(b => b >= 0.0 && b < 1.0));
        Assert.IsTrue(Math.Abs(values.Average() - 0.5) < 0.02);

        var sddiff = values.Select(v => (float)v).StdDev() - expecteddev;
        Assert.IsTrue(Math.Abs(sddiff) < 0.01);
    }

    [Test]
    public void TestRandom()
    {
        var values = Enumerable
            .Range(0, 21)
            .Select(i => BufUtils.RandomDouble(1.0))
            .ToArray();

        var bag = values.SelectMany(i1 => values.SelectMany(i2 => values))
            .Select(i3 => values.Random());

        Assert.IsTrue(bag.All(b => values.Any(i => i == b)));
    }

    [Test]
    public void TestShuffle()
    {
        var ints = Enumerable.Range(0, 200);
        var bag = ints.Select(i => BufUtils.RandomDouble(1)).ToArray();
        var shuffled = BufUtils.Shuffle(bag).ToArray();
        Assert.IsTrue(bag.All(b => shuffled.Any(i => i == b)));
    }

    private class Twi
    {
        public bool IsDisposed { get; protected set; }
    }

    private class TwId : Twi, IDisposable
    {
        void IDisposable.Dispose()
        {
            IsDisposed = true;
        }
    }

    [Test]
    public void TestTimeWindowDictionary()
    {
        var twd = new TimeWindowDictionary<int, Twi>(TickSpan.Seconds(1));

        var oneinstance = new Twi();

        twd[1] = oneinstance;
        twd[100] = oneinstance;
        twd[101] = oneinstance;
        Assert.IsFalse(twd[1].IsDisposed);

        Thread.Sleep(1100);

        Assert.IsFalse(oneinstance.IsDisposed);
        Assert.IsFalse(twd.TryGetValue(1, out _));

        oneinstance = new TwId();

        twd[2] = oneinstance;
        Assert.IsFalse(twd[2].IsDisposed);

        Thread.Sleep(1100);

        Assert.IsFalse(twd.TryGetValue(2, out _));

        ((IDisposable)twd).Dispose();
        Assert.IsTrue(oneinstance.IsDisposed);
    }

    [Test]
    public void TestNetworkMaskIpv4Construction()
    {
        var nm1 = new IpAddressMask("0.0.0.0//0.0.0.255");
        Assert.IsTrue(nm1.Address.GetAddressBytes().All(b => b == 0));
        Assert.IsTrue(nm1.Mask.GetAddressBytes()[3] == 0xff);

        var nm2 = new IpAddressMask("0.0.0.255/8");
        var nm2Ab = nm2.Address.GetAddressBytes();
        var nm2Nm = nm2.Mask.GetAddressBytes();
        Assert.IsTrue(nm2Ab.Select(b => (int)b).Sum() == 0xff);
        Assert.IsTrue(nm2Nm[0] == 0xff);
        Assert.IsTrue(nm2Nm[1] == 0x00);

        var nm3 = new IpAddressMask("92.00.00.255/19");
        var nm3Ab = nm3.Address.GetAddressBytes();
        var nm3Nm = nm3.Mask.GetAddressBytes();
        Assert.IsTrue(nm3Ab[0] == 0x5c);
        Assert.IsTrue(nm3Ab[3] == 0xff);
        Assert.IsTrue(nm3Nm[0] == 0xff);
        Assert.IsTrue(nm3Nm[1] == 0xff);
        Assert.IsTrue(nm3Nm[2] == 0xe0);

        var nm4 = new IpAddressMask("00.92.255.00/32");
        var nm4Ab = nm4.Address.GetAddressBytes();
        var nm4Nm = nm4.Mask.GetAddressBytes();
        Assert.IsTrue(nm4Ab[1] == 0x5c);
        Assert.IsTrue(nm4Ab[2] == 0xff);
        Assert.IsTrue(nm4Nm.All(b => b == 0xff));
    }

    [Test]
    public void TestNetworkMaskIpv6Construction()
    {
        var nm1 = new IpAddressMask("::0//::ff");
        Assert.IsTrue(nm1.Address.GetAddressBytes().All(b => b == 0));
        Assert.IsTrue(nm1.Mask.GetAddressBytes()[15] == 0xff);

        var nm2 = new IpAddressMask("::ff/16");
        var nm2Ab = nm2.Address.GetAddressBytes();
        var nm2Nm = nm2.Mask.GetAddressBytes();
        Assert.IsTrue(nm2Ab.Select(b => (int)b).Sum() == 0xff);
        Assert.IsTrue(nm2Nm[0] == 0xff);
        Assert.IsTrue(nm2Nm[1] == 0xff);
        Assert.IsTrue(nm2Nm[2] == 0x00);

        var nm3 = new IpAddressMask("5c00::00ff/19");
        var nm3Ab = nm3.Address.GetAddressBytes();
        var nm3Nm = nm3.Mask.GetAddressBytes();
        Assert.IsTrue(nm3Ab[0] == 0x5c);
        Assert.IsTrue(nm3Ab[15] == 0xff);
        Assert.IsTrue(nm3Nm[0] == 0xff);
        Assert.IsTrue(nm3Nm[1] == 0xff);
        Assert.IsTrue(nm3Nm[2] == 0xe0);

        var nm4 = new IpAddressMask("005c::ff00/128");
        var nm4Ab = nm4.Address.GetAddressBytes();
        var nm4Nm = nm4.Mask.GetAddressBytes();
        Assert.IsTrue(nm4Ab[1] == 0x5c);
        Assert.IsTrue(nm4Ab[14] == 0xff);
        Assert.IsTrue(nm4Nm.All(b => b == 0xff));
    }

    [Test]
    public void TestNetworkMaskIpv4BelongsTo()
    {
        var nm1 = new IpAddressMask("192.168.255.255/16");
        var a1Belongs = IPAddress.Parse("192.168.2.52");
        var a1Not = IPAddress.Parse("192.169.2.52");

        Assert.IsTrue(nm1.BelongsTo(a1Belongs));
        Assert.IsFalse(nm1.BelongsTo(a1Not));
    }

    [Test]
    public void TestNetworkMaskIpv6BelongsTo()
    {
        var nm1 = new IpAddressMask("fe00::ffff/9");
        var a1Belongs = IPAddress.Parse("fe00::12:13:14");
        var a1Not = IPAddress.Parse("2001::12:13:14");

        Assert.IsTrue(nm1.BelongsTo(a1Belongs));
        Assert.IsFalse(nm1.BelongsTo(a1Not));
    }

    [Test]
    public void TestRunBatchWait()
    {
        const int testCount = 1000;
        var rbw = new RunBatchWait(testCount);

        for (var i = 0; i < testCount; ++i)
        {
            if (i % 15 == 0) Thread.Sleep(50);

            if (!ThreadPool.QueueUserWorkItem(cb =>
                {
                    Thread.Sleep(10);
                    rbw.Set();
                }))
                rbw.Set();
        }

        if (!rbw.WaitOne(2000)) Assert.Fail();
    }

    [Test]
    public void TestMurMurHash3()
    {
        // From https://stackoverflow.com/questions/14747343/murmurhash3-test-vectors
        /*
            | Input        | Seed       | Expected   |
            |--------------|------------|------------|
            | (no bytes)   | 0          | 0          | with zero data and zero seed, everything becomes zero
            | (no bytes)   | 1          | 0x514E28B7 | ignores nearly all the math
            | (no bytes)   | 0xffffffff | 0x81F16F39 | make sure your seed uses unsigned 32-bit math
            | FF FF FF FF  | 0          | 0x76293B50 | make sure 4-byte chunks use unsigned math
            | 21 43 65 87  | 0          | 0xF55B516B | Endian order. UInt32 should end up as 0x87654321
            | 21 43 65 87  | 0x5082EDEE | 0x2362F9DE | Special seed value eliminates initial key with xor
            | 21 43 65     | 0          | 0x7E4A8634 | Only three bytes. Should end up as 0x654321
            | 21 43        | 0          | 0xA0F7B07A | Only two bytes. Should end up as 0x4321
            | 21           | 0          | 0x72661CF4 | Only one byte. Should end up as 0x21
            | 00 00 00 00  | 0          | 0x2362F9DE | Make sure compiler doesn't see zero and convert to null
            | 00 00 00     | 0          | 0x85F0B427 |
            | 00 00        | 0          | 0x30F4C306 |
            | 00           | 0          | 0x514E28B7 |
        */

        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[0]), 0) == 0);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[0]), 1) == 0x514E28B7);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[0]), 0xffffffff) == 0x81F16F39);

        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0xff, 0xff, 0xff, 0xff }), 0) == 0x76293B50);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0x21, 0x43, 0x65, 0x87 }), 0) == 0xF55B516B);

        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0x21, 0x43, 0x65, 0x87 }), 0x5082EDEE) ==
                      0x2362F9DE);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0x21, 0x43, 0x65 }), 0) == 0x7E4A8634);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0x21, 0x43 }), 0) == 0xA0F7B07A);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0x21 }), 0) == 0x72661CF4);

        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0, 0, 0, 0 }), 0) == 0x2362F9DE);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0, 0, 0 }), 0) == 0x85F0B427);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0, 0 }), 0) == 0x30F4C306);
        Assert.IsTrue(MurMurHash3.Hash(new I2PBufferCursor(new byte[] { 0 }), 0) == 0x514E28B7);
    }
}