using System;
using System.IO;
using Org.BouncyCastle.Utilities.Zlib;

namespace I2PCore.Utils;

public static class LzUtils
{
    private static uint[] _crcTable;

    public static uint
        Adler32Slow(byte[] data, long len) /* where data is the location of the data in physical memory and
                                                          len is the length of the data in bytes */
    {
        const uint modAdler = 65521;
        uint a = 1, b = 0;
        long index;

        /* Process each byte of the data in order */
        for (index = 0; index < len; ++index)
        {
            a = (a + data[index]) % modAdler;
            b = (b + a) % modAdler;
        }

        return (b << 16) | a;
    }

    public static uint Adler32(uint adler, I2PByteBlock data)
    {
        const int @base = 65521; /* largest prime smaller than 65536 */
        const int nmax = 5552;

        uint sum2;
        uint n;

        var len = data.Length;

        /* split Adler-32 into component sums */
        sum2 = (adler >> 16) & 0xffff;
        adler &= 0xffff;

        /* in case user likes doing a byte at a time, keep it fast */
        if (data.Length == 1)
        {
            adler += data[0];
            if (adler >= @base)
                adler -= @base;
            sum2 += adler;
            if (sum2 >= @base)
                sum2 -= @base;
            return adler | (sum2 << 16);
        }

        /* initial Adler-32 value (deferred check for len == 1 speed) */
        if (data.IsEmpty)
            return 1;

        /* in case short lengths are provided, keep it somewhat fast */
        if (data.Length < 16)
        {
            var ix = 0;
            while (len-- > 0)
            {
                adler += data[ix++];
                sum2 += adler;
            }

            if (adler >= @base)
                adler -= @base;
            sum2 %= @base; /* only added so many BASE's */
            return adler | (sum2 << 16);
        }

        var i = 0;
        /* do length NMAX blocks -- requires just one modulo operation */
        while (len >= nmax)
        {
            len -= nmax;
            n = nmax / 16; /* NMAX is divisible by 16 */
            do
            {
                //DO16(data);          /* 16 sums unrolled */
                adler += data[i];
                sum2 += adler;
                adler += data[i + 1];
                sum2 += adler;
                adler += data[i + 2];
                sum2 += adler;
                adler += data[i + 3];
                sum2 += adler;
                adler += data[i + 4];
                sum2 += adler;
                adler += data[i + 5];
                sum2 += adler;
                adler += data[i + 6];
                sum2 += adler;
                adler += data[i + 7];
                sum2 += adler;
                adler += data[i + 8];
                sum2 += adler;
                adler += data[i + 9];
                sum2 += adler;
                adler += data[i + 10];
                sum2 += adler;
                adler += data[i + 11];
                sum2 += adler;
                adler += data[i + 12];
                sum2 += adler;
                adler += data[i + 13];
                sum2 += adler;
                adler += data[i + 14];
                sum2 += adler;
                adler += data[i + 15];
                sum2 += adler;
                i += 16;
            } while (--n > 0);

            adler %= @base;
            sum2 %= @base;
        }

        /* do remaining bytes (less than NMAX, still just one modulo) */
        if (len > 0)
        {
            /* avoid modulos if none remaining */
            while (len >= 16)
            {
                len -= 16;
                adler += data[i];
                sum2 += adler;
                adler += data[i + 1];
                sum2 += adler;
                adler += data[i + 2];
                sum2 += adler;
                adler += data[i + 3];
                sum2 += adler;
                adler += data[i + 4];
                sum2 += adler;
                adler += data[i + 5];
                sum2 += adler;
                adler += data[i + 6];
                sum2 += adler;
                adler += data[i + 7];
                sum2 += adler;
                adler += data[i + 8];
                sum2 += adler;
                adler += data[i + 9];
                sum2 += adler;
                adler += data[i + 10];
                sum2 += adler;
                adler += data[i + 11];
                sum2 += adler;
                adler += data[i + 12];
                sum2 += adler;
                adler += data[i + 13];
                sum2 += adler;
                adler += data[i + 14];
                sum2 += adler;
                adler += data[i + 15];
                sum2 += adler;
                i += 16;
            }

            while (len-- > 0)
            {
                adler += data[i++];
                sum2 += adler;
            }

            adler %= @base;
            sum2 %= @base;
        }

        /* return recombined sums */
        return adler | (sum2 << 16);
    }

    private static void BuildTable()
    {
        var table = new uint[256];

        for (var n = 0; n < 256; ++n)
        {
            var c = (uint)n;
            for (var k = 0; k < 8; ++k)
                if ((c & 1) != 0)
                    c = 0xedb88320 ^ (c >> 1);
                else
                    c = c >> 1;

            table[n] = c;
        }

        _crcTable = table;
    }

    public static uint Crc32(byte[] buf)
    {
        var c = 0xffffffff;

        if (_crcTable == null) BuildTable();

        for (var n = 0; n < buf.Length; ++n) c = _crcTable[(c ^ buf[n]) & 0xff] ^ (c >> 8);
        return c ^ 0xffffffff;
    }

    public static uint Crc32(I2PByteBlock buf)
    {
        var c = 0xffffffff;

        if (_crcTable == null) BuildTable();

        for (var n = 0; n < buf.Length; ++n) c = _crcTable[(c ^ buf[n]) & 0xff] ^ (c >> 8);
        return c ^ 0xffffffff;
    }

    public static byte[] BcgZipCompress(byte[] buf)
    {
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(0x1f);
            ms.WriteByte(0x8b);
            ms.WriteByte(0x08);
            ms.WriteByte(0x00);
            ms.WriteByte(0x00);
            ms.WriteByte(0x00);
            ms.WriteByte(0x00);
            ms.WriteByte(0x00);
            ms.WriteByte(0x02);
            ms.WriteByte(0xFF);

            using (var gzs = new ZOutputStream(ms, 6, true))
            {
                gzs.Write(buf, 0, buf.Length);
                gzs.Flush();
            }

            var crc = Crc32(buf);

            // ZOutputStream closes the outer stream...
            using (var ms2 = new MemoryStream())
            {
                StreamUtils.Write(ms2, ms.ToArray());
                ms2.WriteUInt32(crc);
                ms2.WriteInt32(buf.Length);

                var msb = ms2.ToArray();
                /*
                using ( var foos = new FileStream( "test.gz", FileMode.Create, FileAccess.Write ) )
                {
                foos.Write( msb );
                }
                */

                return msb;
            }
        }
    }

    public static I2PByteBlock BcgZipCompressNew(I2PByteBlock buf)
    {
        var crc = Crc32(buf);

        var dest = new byte[buf.Length + 4096];
        var destix = 0;

        dest[destix++] = 0x1f;
        dest[destix++] = 0x8b;
        dest[destix++] = 0x08;
        dest[destix++] = 0x00;
        dest[destix++] = 0x00;
        dest[destix++] = 0x00;
        dest[destix++] = 0x00;
        dest[destix++] = 0x00;
        dest[destix++] = 0x02;
        dest[destix++] = 0xFF;

        var z = new ZStream();
        z.deflateInit(6, true);

        z.next_in_index = buf.BaseArrayOffset;
        z.next_in = buf.BaseArray;
        z.avail_in = buf.Length;

        bigger_dest:

        z.next_out = dest;
        z.next_out_index = destix;
        z.avail_out = dest.Length - destix;
        var err = z.deflate(JZlib.Z_FINISH);
        if (err != JZlib.Z_OK && err != JZlib.Z_STREAM_END) throw new IOException("deflating: " + z.msg);

        if (z.avail_out == 0)
        {
            var newdest = new byte[dest.Length * 2];
            Array.Copy(dest, newdest, dest.Length);
            destix = dest.Length;
            dest = newdest;
            goto bigger_dest;
        }

        if (z.avail_out < 8)
        {
            var newdest = new byte[dest.Length + 8];
            Array.Copy(dest, newdest, dest.Length);
            destix = dest.Length;
            dest = newdest;
            goto bigger_dest;
        }

        var result = new I2PByteBlock(dest, 0, dest.Length - z.avail_out + 8);

        result.WriteUInt32LittleEndian(crc, result.Length - 8);
        result.WriteUInt32LittleEndian((uint)buf.Length, result.Length - 4);

        z.deflateEnd();

        /*
        using ( var foos = new FileStream( "test.gz", FileMode.Create, FileAccess.Write ) )
        {
        foos.Write( msb );
        }
        */
        return result;
    }

    public static byte[] BcgZipDecompress(I2PByteBlock buf)
    {
        var reader = new I2PBufferCursor(buf);

        using (var ms = new MemoryStream())
        {
            // Skip gzip header
            var gzheader = reader.ReadBlock(10);
            var flag = gzheader.ReadByte(3);
            if ((flag & 0x04) != 0) reader.Seek(reader.ReadUInt16LittleEndian()); // "Extra"
            if ((flag & 0x08) != 0)
                while (reader.ReadByte() != 0)
                    ; // "Name"
            if ((flag & 0x10) != 0)
                while (reader.ReadByte() != 0)
                    ; // "Comment"
            if ((flag & 0x02) != 0) reader.ReadUInt16LittleEndian(); // "CRC16"

            ms.Write(reader.BaseArray, reader.BaseArrayOffset, reader.Remaining);
            ms.Position = 0;

            using (var gzs = new ZInputStream(ms, true))
            {
                var gzdata = StreamUtils.Read(gzs);
                return gzdata;
            }
        }
    }

    public static I2PByteBlock BcgZipDecompressNew(I2PByteBlock buf)
    {
        var reader = new I2PBufferCursor(buf);

        // Skip gzip header
        var gzheader = reader.ReadBlock(10);
        var flag = gzheader.ReadByte(3);
        if ((flag & 0x04) != 0) reader.Seek(reader.ReadUInt16LittleEndian()); // "Extra"
        if ((flag & 0x08) != 0)
            while (reader.ReadByte() != 0)
                ; // "Name"
        if ((flag & 0x10) != 0)
            while (reader.ReadByte() != 0)
                ; // "Comment"
        if ((flag & 0x02) != 0) reader.ReadUInt16LittleEndian(); // "CRC16"

        var z = new ZStream();
        z.inflateInit(true);

        var dest = new byte[buf.Length * 2];
        var destix = 0;

        z.next_in_index = reader.BaseArrayOffset;
        z.next_in = reader.BaseArray;
        z.avail_in = reader.Remaining - 8;

        bigger_dest:

        z.next_out = dest;
        z.next_out_index = destix;
        z.avail_out = dest.Length - destix;
        var err = z.inflate(JZlib.Z_FINISH);
        if (err != JZlib.Z_BUF_ERROR && err != JZlib.Z_OK && err != JZlib.Z_STREAM_END)
            throw new IOException("inflating: " + z.msg);

        if (z.avail_out == 0)
        {
            var newdest = new byte[dest.Length * 2];
            Array.Copy(dest, newdest, dest.Length);
            destix = dest.Length;
            dest = newdest;
            goto bigger_dest;
        }

        var result = new I2PByteBlock(dest, 0, dest.Length - z.avail_out);
        z.inflateEnd();

        return result;
    }
}