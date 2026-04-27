using System.Buffers;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using I2PCore.SessionLayer;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PRouterAddress : I2PType
{
    public byte Cost;
    public I2PDate Expiration; // Must be all 0!
    public I2PMapping Options;
    public I2PString TransportStyle;

    public I2PRouterAddress(IPAddress addr, int port, byte cost, string transportstyle)
    {
        Cost = cost;
        Expiration = I2PDate.Zero;
        TransportStyle = new I2PString(transportstyle);
        Options = new I2PMapping();

        Options["host"] = addr.ToString();
        Options["port"] = port.ToString();
    }

    public I2PRouterAddress(I2PBufferCursor buf)
    {
        Cost = buf.ReadByte();
        Expiration = new I2PDate(buf);
        TransportStyle = new I2PString(buf);
        Options = new I2PMapping(buf);
    }

    public IPAddress Host
    {
        get
        {
            if (!Options.TryGet("host", out var hoststr))
                if (!Options.TryGet("h", out hoststr))
                    return null;

            var host = hoststr.ToString();

            var fam = IpTestHostName(host);
            if (fam == AddressFamily.InterNetwork || fam == AddressFamily.InterNetworkV6)
                return IPAddress.Parse(host);

            var al = Dns.GetHostEntry(host).AddressList.Where(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (al.Any()) return al.Random();
            return null;
        }
    }

    public int Port
    {
        get
        {
            if (Options.TryGet("port", out var port)) return int.Parse(port.ToString());
            if (Options.TryGet("p", out port)) return int.Parse(port.ToString());
            return -1;
        }
    }

    public bool HaveHostAndPort => (Options.Contains("host") || Options.Contains("h")) &&
                                   (Options.Contains("port") || Options.Contains("p"));

    public void Write(IBufferWriter<byte> dest)
    {
        // Routers MUST set this (expire) field to all zeros. As of release 0.9.12, 
        // a non-zero expiration field is again recognized, however we must 
        // wait several releases to use this field, until the vast majority 
        // of the network recognizes it.
        // TODO: Hmmm?

        dest.WriteByte(Cost);
        Expiration.Write(dest);
        TransportStyle.Write(dest);
        Options.Write(dest);
    }

    public static AddressFamily IpTestHostName(string host)
    {
        if (IPAddress.TryParse(host, out var address)) return address.AddressFamily;

        return AddressFamily.Unknown;
    }

    /// <summary>
    ///     Returns true if this address has a host we can actually connect to,
    ///     given our current IPv4/IPv6 settings.
    /// </summary>
    public static bool IsReachableAddress(I2PRouterAddress addr)
    {
        var host = addr.Options.TryGet("host")?.ToString()
                   ?? addr.Options.TryGet("h")?.ToString();
        if (host == null) return false;

        var family = IpTestHostName(host);
        if (family == AddressFamily.InterNetwork) return RouterContext.UseIpV4;
        if (family == AddressFamily.InterNetworkV6) return RouterContext.UseIpV6;

        return false; // Unknown/unresolvable host
    }

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("I2PRouterAddress");

        result.AppendLine("Cost         : " + Cost);
        result.AppendLine("Expiration 0 : " + Expiration);
        result.AppendLine("Transport    : " + TransportStyle);
        result.AppendLine("Options      : " + Options);

        return result.ToString();
    }
}