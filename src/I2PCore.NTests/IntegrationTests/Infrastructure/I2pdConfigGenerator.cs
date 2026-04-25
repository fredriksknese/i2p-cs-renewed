using System.IO;
using System.Text;

namespace I2PTests.IntegrationTests.Infrastructure;

/// <summary>
///     Generates i2pd configuration files for the private test network (netid=99).
///     All services bound to 127.0.0.1 with ports in the 29010-29019 range.
/// </summary>
public static class I2pdConfigGenerator
{
    public const int TestNetworkId = 99;

    /// <summary>
    ///     Generate the main i2pd.conf for the test network.
    /// </summary>
    public static string GenerateConfig(
        string dataDir,
        int ntcp2Port = PortAllocator.WellKnown.I2pdNtcp2,
        int ssu2Port = PortAllocator.WellKnown.I2pdSsu2,
        int samPort = PortAllocator.WellKnown.I2pdSam,
        int i2cpPort = PortAllocator.WellKnown.I2pdI2cp,
        int httpPort = PortAllocator.WellKnown.I2pdHttp,
        // Enable floodfill by default: on our private 2-router test network, no external
        // floodfill routers exist, so i2pd must act as its own floodfill to publish
        // LeaseSets. Without this, SAM SESSION CREATE never receives a response.
        bool floodfill = true,
        bool notransit = false,
        string logFile = null,
        int ntcpSoft = 5,
        int ntcpHard = 10)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# Auto-generated i2pd config for integration testing");
        sb.AppendLine($"# Test network ID: {TestNetworkId}");
        sb.AppendLine();
        sb.AppendLine($"netid = {TestNetworkId}");
        sb.AppendLine("ipv4 = true");
        sb.AppendLine("ipv6 = false");
        sb.AppendLine("nat = false");
        sb.AppendLine("host = 127.0.0.1");
        sb.AppendLine("reservedrange = false");
        sb.AppendLine($"port = {ntcp2Port}");
        sb.AppendLine("bandwidth = X");
        sb.AppendLine($"floodfill = {(floodfill ? "true" : "false")}");
        sb.AppendLine($"notransit = {(notransit ? "true" : "false")}");
        sb.AppendLine("httpproxy.addresshelper = false");
        sb.AppendLine();
        sb.AppendLine($"datadir = {dataDir}");
        sb.AppendLine("log = file");
        sb.AppendLine($"logfile = {logFile ?? "/tmp/i2pd_test_latest.log"}");
        sb.AppendLine("loglevel = debug");
        sb.AppendLine();

        // NTCP2
        sb.AppendLine("[ntcp2]");
        sb.AppendLine("enabled = true");
        sb.AppendLine($"port = {ntcp2Port}");
        sb.AppendLine("published = true");
        sb.AppendLine();

        // SSU2
        sb.AppendLine("[ssu2]");
        sb.AppendLine("enabled = true");
        sb.AppendLine($"port = {ssu2Port}");
        sb.AppendLine("published = true");
        sb.AppendLine();

        // Reseed — disabled for private network
        sb.AppendLine("[reseed]");
        sb.AppendLine("verify = false");
        sb.AppendLine("urls =");
        sb.AppendLine();

        // SAM — on non-conflicting port
        sb.AppendLine("[sam]");
        sb.AppendLine("enabled = true");
        sb.AppendLine("address = 127.0.0.1");
        sb.AppendLine($"port = {samPort}");
        sb.AppendLine();

        // I2CP — on non-conflicting port
        sb.AppendLine("[i2cp]");
        sb.AppendLine("enabled = true");
        sb.AppendLine("address = 127.0.0.1");
        sb.AppendLine($"port = {i2cpPort}");
        sb.AppendLine();

        // HTTP console — on non-conflicting port
        sb.AppendLine("[http]");
        sb.AppendLine("enabled = true");
        sb.AppendLine("address = 127.0.0.1");
        sb.AppendLine($"port = {httpPort}");
        sb.AppendLine();

        // HTTP proxy — disabled to avoid conflicts with live router
        sb.AppendLine("[httpproxy]");
        sb.AppendLine("enabled = false");
        sb.AppendLine();

        // SOCKS proxy — disabled
        sb.AppendLine("[socksproxy]");
        sb.AppendLine("enabled = false");
        sb.AppendLine();

        // Limits — minimal for testing
        sb.AppendLine("[limits]");
        sb.AppendLine($"ntcpsoft = {ntcpSoft}");
        sb.AppendLine($"ntcphard = {ntcpHard}");

        return sb.ToString();
    }

    /// <summary>
    ///     Write the config to disk and return the config file path.
    ///     Also creates the data directory if needed.
    /// </summary>
    public static string WriteConfig(string baseDir, string configContent = null)
    {
        Directory.CreateDirectory(baseDir);

        var netDbDir = Path.Combine(baseDir, "netDb");
        Directory.CreateDirectory(netDbDir);

        var certsDir = Path.Combine(baseDir, "certificates");
        Directory.CreateDirectory(certsDir);

        var content = configContent ?? GenerateConfig(baseDir);
        var configPath = Path.Combine(baseDir, "i2pd.conf");
        File.WriteAllText(configPath, content);

        return configPath;
    }
}