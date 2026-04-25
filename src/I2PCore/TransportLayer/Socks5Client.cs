using System;
using System.Net;
using System.Net.Sockets;

namespace I2PCore.TransportLayer;

/// <summary>
///     SOCKS5 client for outbound transport proxy support.
///     Allows connecting to I2P routers through a SOCKS5 proxy (e.g., Tor).
///     Compatible with i2pd's Socks5.h proxy support.
/// </summary>
public static class Socks5Client
{
    // SOCKS5 protocol constants
    private const byte SOCKS5_VERSION = 0x05;
    private const byte SOCKS5_AUTH_NONE = 0x00;
    private const byte SOCKS5_CMD_CONNECT = 0x01;
    private const byte SOCKS5_ATYP_IPV4 = 0x01;
    private const byte SOCKS5_ATYP_DOMAIN = 0x03;
    private const byte SOCKS5_ATYP_IPV6 = 0x04;
    private const byte SOCKS5_REPLY_SUCCESS = 0x00;

    /// <summary>
    ///     Global proxy configuration. Set to null to disable proxy.
    /// </summary>
    public static Socks5ProxyConfig ProxyConfig { get; set; }

    /// <summary>
    ///     Check if proxy is enabled
    /// </summary>
    public static bool UsingProxy => ProxyConfig != null;

    /// <summary>
    ///     Connect a TcpClient through the SOCKS5 proxy to the target endpoint.
    /// </summary>
    public static void ConnectThroughProxy(TcpClient client, IPEndPoint target)
    {
        if (ProxyConfig == null)
            throw new InvalidOperationException("SOCKS5 proxy not configured");

        // Step 1: Connect to the proxy server
        client.Connect(ProxyConfig.ProxyHost, ProxyConfig.ProxyPort);

        var stream = client.GetStream();
        stream.ReadTimeout = 30000;
        stream.WriteTimeout = 30000;

        // Step 2: SOCKS5 handshake (method negotiation)
        // Send: VER(1) NMETHODS(1) METHODS(1..255)
        var handshake = new byte[] { SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE };
        stream.Write(handshake, 0, handshake.Length);

        // Receive: VER(1) METHOD(1)
        var response = new byte[2];
        ReadFull(stream, response, 2);

        if (response[0] != SOCKS5_VERSION)
            throw new Socks5Exception($"SOCKS5 handshake: unexpected version {response[0]}");

        if (response[1] != SOCKS5_AUTH_NONE)
            throw new Socks5Exception($"SOCKS5 handshake: proxy requires unsupported auth method {response[1]}");

        // Step 3: SOCKS5 CONNECT request
        byte[] connectRequest;
        var addressBytes = target.Address.GetAddressBytes();

        if (target.Address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPv6: VER(1) CMD(1) RSV(1) ATYP(1) ADDR(16) PORT(2)
            connectRequest = new byte[4 + 16 + 2];
            connectRequest[0] = SOCKS5_VERSION;
            connectRequest[1] = SOCKS5_CMD_CONNECT;
            connectRequest[2] = 0x00; // Reserved
            connectRequest[3] = SOCKS5_ATYP_IPV6;
            Array.Copy(addressBytes, 0, connectRequest, 4, 16);
            connectRequest[20] = (byte)(target.Port >> 8);
            connectRequest[21] = (byte)(target.Port & 0xFF);
        }
        else
        {
            // IPv4: VER(1) CMD(1) RSV(1) ATYP(1) ADDR(4) PORT(2)
            connectRequest = new byte[4 + 4 + 2];
            connectRequest[0] = SOCKS5_VERSION;
            connectRequest[1] = SOCKS5_CMD_CONNECT;
            connectRequest[2] = 0x00; // Reserved
            connectRequest[3] = SOCKS5_ATYP_IPV4;
            Array.Copy(addressBytes, 0, connectRequest, 4, 4);
            connectRequest[8] = (byte)(target.Port >> 8);
            connectRequest[9] = (byte)(target.Port & 0xFF);
        }

        stream.Write(connectRequest, 0, connectRequest.Length);

        // Step 4: Read SOCKS5 reply
        // VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(variable) BND.PORT(2)
        var replyHeader = new byte[4];
        ReadFull(stream, replyHeader, 4);

        if (replyHeader[0] != SOCKS5_VERSION)
            throw new Socks5Exception($"SOCKS5 reply: unexpected version {replyHeader[0]}");

        if (replyHeader[1] != SOCKS5_REPLY_SUCCESS)
            throw new Socks5Exception($"SOCKS5 connect failed: {GetReplyErrorMessage(replyHeader[1])}");

        // Read and discard the bound address
        switch (replyHeader[3])
        {
            case SOCKS5_ATYP_IPV4:
                ReadFull(stream, new byte[4 + 2], 6); // 4 addr + 2 port
                break;
            case SOCKS5_ATYP_IPV6:
                ReadFull(stream, new byte[16 + 2], 18); // 16 addr + 2 port
                break;
            case SOCKS5_ATYP_DOMAIN:
                var domainLen = new byte[1];
                ReadFull(stream, domainLen, 1);
                ReadFull(stream, new byte[domainLen[0] + 2], domainLen[0] + 2);
                break;
            default:
                throw new Socks5Exception($"SOCKS5 reply: unknown address type {replyHeader[3]}");
        }

        // Connection established through proxy - TCP stream is now tunneled
    }

    private static void ReadFull(NetworkStream stream, byte[] buffer, int count)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var bytesRead = stream.Read(buffer, totalRead, count - totalRead);
            if (bytesRead == 0)
                throw new Socks5Exception("SOCKS5: Connection closed during handshake");
            totalRead += bytesRead;
        }
    }

    private static string GetReplyErrorMessage(byte replyCode)
    {
        return replyCode switch
        {
            0x01 => "General SOCKS server failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused",
            0x06 => "TTL expired",
            0x07 => "Command not supported",
            0x08 => "Address type not supported",
            _ => $"Unknown error (0x{replyCode:X2})"
        };
    }
}

/// <summary>
///     SOCKS5 proxy configuration
/// </summary>
public class Socks5ProxyConfig
{
    public Socks5ProxyConfig(string host, int port)
    {
        ProxyHost = host ?? throw new ArgumentNullException(nameof(host));
        ProxyPort = port;
    }

    public string ProxyHost { get; set; }
    public int ProxyPort { get; set; }
}

/// <summary>
///     Exception for SOCKS5 protocol errors
/// </summary>
public class Socks5Exception : Exception
{
    public Socks5Exception(string message) : base(message)
    {
    }
}