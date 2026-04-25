using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using I2PCore.Utils;

namespace I2PCore.SessionLayer;

public partial class RouterContext
{
    private readonly NetworkInterfaceType[] InterfaceTypes = new[]
    {
        NetworkInterfaceType.Ethernet,
        NetworkInterfaceType.Wireless80211
    };

    public IPAddress SsuReportedExternalAddress;
    public int UPnpExternalTcpPort;
    public bool UPnpExternalTcpPortMapped;
    public int UPnpExternalUdpPort;
    public bool UPnpExternalUdpPortMapped;

    public IPAddress ExtIpv4Address
    {
        get
        {
            if (SsuReportedExternalAddress != null) return SsuReportedExternalAddress;

            if (DefaultExtAddress != null) return DefaultExtAddress;

            return GetAllLocalInterfaces(
                    InterfaceTypes,
                    new[]
                    {
                        AddressFamily.InterNetwork
                    })
                ?.Random()?.Address;
        }
    }

    public static IEnumerable<UnicastIPAddressInformation> GetAllLocalInterfaces(
        IEnumerable<NetworkInterfaceType> types,
        IEnumerable<AddressFamily> families)
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(x => types.Any(t => t == x.NetworkInterfaceType)
                        && x.OperationalStatus == OperationalStatus.Up)
            .SelectMany(x => x.GetIPProperties().UnicastAddresses)
            .Where(x => families.Any(f => f == x.Address.AddressFamily))
            .ToArray();
    }

    public void SsuReportedAddr(IPAddress extaddr)
    {
        if (extaddr == null) return;
        if (SsuReportedExternalAddress != null && SsuReportedExternalAddress.Equals(extaddr)) return;

        SsuReportedExternalAddress = extaddr;
        ApplyNewSettings();
    }

    internal void UpnpNatPortMapAdded(IPAddress addr, string protocol, int port)
    {
        if (protocol == "TCP" && UPnpExternalTcpPortMapped && UPnpExternalTcpPort == port) return;
        if (protocol == "UDP" && UPnpExternalUdpPortMapped && UPnpExternalUdpPort == port) return;

        if (protocol == "TCP")
        {
            UPnpExternalTcpPortMapped = true;
            UPnpExternalTcpPort = port;
        }
        else
        {
            UPnpExternalUdpPortMapped = true;
            UPnpExternalUdpPort = port;
        }

        ApplyNewSettings();
    }
}