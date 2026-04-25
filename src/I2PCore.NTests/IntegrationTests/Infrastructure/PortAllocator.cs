using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace I2PTests.IntegrationTests.Infrastructure;

/// <summary>
///     Allocates unique ports for integration tests in a safe range (29000-29099)
///     that avoids the live Java I2P router (4444, 4448, 7654-7658, 32000, 52384).
/// </summary>
public class PortAllocator
{
    // Safe range far from any live I2P services
    private const int RangeStart = 29000;
    private const int RangeEnd = 29099;
    private readonly HashSet<int> _allocated = new();
    private readonly object _lock = new();

    private int _nextPort;

    public PortAllocator()
    {
        _nextPort = RangeStart;
    }

    /// <summary>
    ///     Allocate the next available port, verifying it's not already in use.
    /// </summary>
    public int Allocate()
    {
        lock (_lock)
        {
            while (_nextPort <= RangeEnd)
            {
                var port = _nextPort++;
                if (_allocated.Contains(port))
                    continue;

                if (!IsPortAvailable(port))
                    continue;

                _allocated.Add(port);
                return port;
            }

            throw new InvalidOperationException(
                $"No available ports in range {RangeStart}-{RangeEnd}");
        }
    }

    /// <summary>
    ///     Allocate a specific number of consecutive ports.
    ///     Returns the first port in the range.
    /// </summary>
    public (int first, int[] all) AllocateRange(int count)
    {
        var ports = new int[count];
        for (var i = 0; i < count; i++)
            ports[i] = Allocate();
        return (ports[0], ports);
    }

    private static bool IsPortAvailable(int port)
    {
        try
        {
            using var tcp = new TcpListener(IPAddress.Loopback, port);
            tcp.Start();
            tcp.Stop();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>
    ///     Well-known port assignments for the test network.
    ///     2-router network uses A + i2pdA.
    ///     4-router network uses all four.
    /// </summary>
    public static class WellKnown
    {
        // C# Router A (in-process) — 29000-29009
        public const int CSharpNtcp2 = 29000;
        public const int CSharpSsu2 = 29001;
        public const int CSharpSam = 29002;
        public const int CSharpI2cp = 29003;

        // i2pd Router A — 29010-29019
        // NOTE: i2pd SAM creates a UDP socket at (sam_port - 1) for datagram support.
        // SAM must not be at (ssu2_port + 1) to avoid binding conflict.
        public const int I2pdNtcp2 = 29010;
        public const int I2pdSsu2 = 29011;

        public const int I2pdI2cp = 29013;

        // SAM at 29015 → SAM UDP at 29014, no conflict with SSU2 (29011)
        public const int I2pdSam = 29015;
        public const int I2pdHttp = 29016;

        // C# Router B (external process) — 29020-29029
        public const int CSharpBNtcp2 = 29020;
        public const int CSharpBSsu2 = 29021;
        public const int CSharpBSam = 29022;
        public const int CSharpBI2cp = 29023;
        public const int CSharpBHttpProxy = 29024;

        // i2pd Router B — 29030-29039
        // Same SAM UDP conflict rule: SAM at 29035 → SAM UDP at 29034, no conflict with SSU2 (29031)
        public const int I2pdBNtcp2 = 29030;
        public const int I2pdBSsu2 = 29031;
        public const int I2pdBI2cp = 29033;
        public const int I2pdBSam = 29035;
        public const int I2pdBHttp = 29036;
    }

    /// <summary>
    ///     Port assignments for the 10-router scaled test network.
    ///     5 C# routers + 5 i2pd routers, range 29100-29199.
    ///     Each router gets a 10-port block.
    ///     i2pd SAM at offset +5 to avoid UDP conflict with SSU2 at +1.
    /// </summary>
    public static class Scaled
    {
        // C# Router 0 (in-process, floodfill)
        public const int Cs0Ntcp2 = 29100;
        public const int Cs0Ssu2 = 29101;
        public const int Cs0Sam = 29102;
        public const int Cs0I2cp = 29103;

        // C# Router 1 (process, floodfill)
        public const int Cs1Ntcp2 = 29110;
        public const int Cs1Ssu2 = 29111;
        public const int Cs1Sam = 29112;
        public const int Cs1I2cp = 29113;
        public const int Cs1Http = 29114;

        // C# Router 2 (process)
        public const int Cs2Ntcp2 = 29120;
        public const int Cs2Ssu2 = 29121;
        public const int Cs2Sam = 29122;
        public const int Cs2I2cp = 29123;
        public const int Cs2Http = 29124;

        // C# Router 3 (process)
        public const int Cs3Ntcp2 = 29130;
        public const int Cs3Ssu2 = 29131;
        public const int Cs3Sam = 29132;
        public const int Cs3I2cp = 29133;
        public const int Cs3Http = 29134;

        // C# Router 4 (process)
        public const int Cs4Ntcp2 = 29140;
        public const int Cs4Ssu2 = 29141;
        public const int Cs4Sam = 29142;
        public const int Cs4I2cp = 29143;
        public const int Cs4Http = 29144;

        // i2pd 0 (floodfill)
        public const int I2pd0Ntcp2 = 29150;
        public const int I2pd0Ssu2 = 29151;
        public const int I2pd0I2cp = 29153;
        public const int I2pd0Sam = 29155;
        public const int I2pd0Http = 29156;

        // i2pd 1 (floodfill)
        public const int I2pd1Ntcp2 = 29160;
        public const int I2pd1Ssu2 = 29161;
        public const int I2pd1I2cp = 29163;
        public const int I2pd1Sam = 29165;
        public const int I2pd1Http = 29166;

        // i2pd 2
        public const int I2pd2Ntcp2 = 29170;
        public const int I2pd2Ssu2 = 29171;
        public const int I2pd2I2cp = 29173;
        public const int I2pd2Sam = 29175;
        public const int I2pd2Http = 29176;

        // i2pd 3
        public const int I2pd3Ntcp2 = 29180;
        public const int I2pd3Ssu2 = 29181;
        public const int I2pd3I2cp = 29183;
        public const int I2pd3Sam = 29185;
        public const int I2pd3Http = 29186;

        // i2pd 4
        public const int I2pd4Ntcp2 = 29190;
        public const int I2pd4Ssu2 = 29191;
        public const int I2pd4I2cp = 29193;
        public const int I2pd4Sam = 29195;
        public const int I2pd4Http = 29196;

        /// <summary>
        ///     All NTCP2 (TCP) ports in the scaled network, for stale process cleanup.
        /// </summary>
        public static readonly int[] AllNtcp2Ports = new[]
        {
            Cs0Ntcp2, Cs1Ntcp2, Cs2Ntcp2, Cs3Ntcp2, Cs4Ntcp2,
            I2pd0Ntcp2, I2pd1Ntcp2, I2pd2Ntcp2, I2pd3Ntcp2, I2pd4Ntcp2
        };

        /// <summary>
        ///     All TCP ports (NTCP2 + SAM + I2CP) for thorough cleanup.
        /// </summary>
        public static readonly int[] AllTcpPorts = new[]
        {
            Cs0Ntcp2, Cs0Sam, Cs0I2cp,
            Cs1Ntcp2, Cs1Sam, Cs1I2cp,
            Cs2Ntcp2, Cs2Sam, Cs2I2cp,
            Cs3Ntcp2, Cs3Sam, Cs3I2cp,
            Cs4Ntcp2, Cs4Sam, Cs4I2cp,
            I2pd0Ntcp2, I2pd0Sam, I2pd0I2cp,
            I2pd1Ntcp2, I2pd1Sam, I2pd1I2cp,
            I2pd2Ntcp2, I2pd2Sam, I2pd2I2cp,
            I2pd3Ntcp2, I2pd3Sam, I2pd3I2cp,
            I2pd4Ntcp2, I2pd4Sam, I2pd4I2cp
        };
    }
}