using System;
using System.Net;
using System.Net.Sockets;

namespace I2PCore.Utils;

public class IpAddressMask
{
    public IpAddressMask(string mask)
    {
        if (!mask.Contains('/'))
            throw new ArgumentException("Mask needs to contain address and netmask");

        var split = mask.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (split.Length != 2)
            throw new ArgumentException("Address/Mask needed");

        var isbitcount = true;

        if (mask.Contains("//")) isbitcount = false;

        Address = IPAddress.Parse(split[0]);

        if (isbitcount)
        {
            var bits = int.Parse(split[1]);
            var maxbits = Address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (bits < 0 || bits > maxbits)
                throw new ArgumentException($"Mask bits must be in the rage 0 -> {maxbits}");

            var maskbits = new byte[Address.AddressFamily == AddressFamily.InterNetwork ? 4 : 16];
            var ix = 0;
            while (bits >= 8)
            {
                maskbits[ix++] = 0xff;
                bits -= 8;
            }

            for (var i = 0; i < bits; ++i) maskbits[ix] = (byte)((maskbits[ix] >> 1) | 0x80);

            Mask = new IPAddress(maskbits);
        }
        else
        {
            Mask = IPAddress.Parse(split[1]);

            if (Address.AddressFamily != Mask.AddressFamily)
                throw new ArgumentException("Address and Mask must belong to the same AddressFamily");
        }
    }

    public IPAddress Address { get; protected set; }
    public IPAddress Mask { get; protected set; }

    public static byte[] Combine(IPAddress a, IPAddress b, Func<byte, byte, byte> op)
    {
        if (a.AddressFamily != b.AddressFamily)
            throw new ArgumentException("Addresses must belong to the same AddressFamily");

        var ab = a.GetAddressBytes();
        var bb = b.GetAddressBytes();
        var result = new byte[ab.Length];

        for (var i = 0; i < ab.Length; ++i) result[i] = op(ab[i], bb[i]);

        return result;
    }

    public static byte[] And(IPAddress a, IPAddress b)
    {
        return Combine(a, b, (ab, bb) => (byte)(ab & bb));
    }

    public static byte[] Xor(IPAddress a, IPAddress b)
    {
        return Combine(a, b, (ab, bb) => (byte)(ab ^ bb));
    }

    public bool BelongsTo(IPAddress addr)
    {
        var mysubnet = And(Address, Mask);
        var addrsubnet = And(addr, Mask);

        return new I2PByteBlock(mysubnet) == new I2PByteBlock(addrsubnet);
    }
}