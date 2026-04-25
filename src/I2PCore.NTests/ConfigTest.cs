using System.IO;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

[TestFixture]
public class ConfigTest
{
    /// <summary>
    ///     Test default option values match i2pd defaults.
    /// </summary>
    [Test]
    public void TestDefaultOptions()
    {
        var config = new I2PConfig();

        Assert.AreEqual("true", config.GetOption("ipv4"), "IPv4 should default to true");
        Assert.AreEqual("false", config.GetOption("ipv6"), "IPv6 should default to false");
        Assert.AreEqual("false", config.GetOption("floodfill"), "Floodfill should default to false");
        Assert.AreEqual("true", config.GetOption("ntcp2.enabled"), "NTCP2 should default to true");
        Assert.AreEqual("true", config.GetOption("ssu2.enabled"), "SSU2 should default to true");
        Assert.AreEqual("7070", config.GetOption("http.port"), "HTTP port should default to 7070");
        Assert.AreEqual("4444", config.GetOption("httpproxy.port"), "HTTP proxy port should default to 4444");
        Assert.AreEqual("7656", config.GetOption("sam.port"), "SAM port should default to 7656");
        Assert.AreEqual("2", config.GetOption("netid"), "NetID should default to 2");
    }

    /// <summary>
    ///     Test command-line argument parsing.
    /// </summary>
    [Test]
    public void TestCommandLineParsing()
    {
        var config = new I2PConfig();
        config.ParseCommandLine(new[]
        {
            "--port=12345",
            "--ipv6",
            "--bandwidth", "P",
            "--floodfill=true"
        });

        Assert.AreEqual("12345", config.GetOption("port"));
        Assert.AreEqual("true", config.GetOption("ipv6"));
        Assert.AreEqual("P", config.GetOption("bandwidth"));
        Assert.AreEqual("true", config.GetOption("floodfill"));
    }

    /// <summary>
    ///     Test INI file parsing with sections.
    /// </summary>
    [Test]
    public void TestIniFileParsing()
    {
        var tmpFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmpFile, @"
# Global options
log = file
loglevel = warn
ipv4 = true
ipv6 = true

[http]
enabled = true
address = 0.0.0.0
port = 8080

[httpproxy]
enabled = false
port = 4445
");

            var config = new I2PConfig();
            config.ParseConfigFile(tmpFile);

            // Global options
            Assert.AreEqual("file", config.GetOption("log"));
            Assert.AreEqual("warn", config.GetOption("loglevel"));

            // Section options accessible as section.key
            Assert.AreEqual("8080", config.GetOption("http.port"));
            Assert.AreEqual("0.0.0.0", config.GetOption("http.address"));
            Assert.AreEqual("false", config.GetOption("httpproxy.enabled"));

            // Section access
            var httpSection = config.GetSection("http");
            Assert.AreEqual("true", httpSection["enabled"]);
            Assert.AreEqual("8080", httpSection["port"]);
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }

    /// <summary>
    ///     Test that command-line overrides defaults.
    /// </summary>
    [Test]
    public void TestCommandLineOverridesDefaults()
    {
        var config = new I2PConfig();

        // Default should be "7070"
        Assert.AreEqual("7070", config.GetOption("http.port"));

        // Override via command line
        config.ParseCommandLine(new[] { "--http.port=9090" });

        Assert.AreEqual("9090", config.GetOption("http.port"));
    }

    /// <summary>
    ///     Test boolean option parsing.
    /// </summary>
    [Test]
    public void TestBoolOptions()
    {
        var config = new I2PConfig();
        config.SetOption("test.true1", "true");
        config.SetOption("test.true2", "1");
        config.SetOption("test.true3", "yes");
        config.SetOption("test.false1", "false");
        config.SetOption("test.false2", "0");
        config.SetOption("test.false3", "no");

        Assert.IsTrue(config.GetOptionBool("test.true1"));
        Assert.IsTrue(config.GetOptionBool("test.true2"));
        Assert.IsTrue(config.GetOptionBool("test.true3"));
        Assert.IsFalse(config.GetOptionBool("test.false1"));
        Assert.IsFalse(config.GetOptionBool("test.false2"));
        Assert.IsFalse(config.GetOptionBool("test.false3"));
    }

    /// <summary>
    ///     Test integer option parsing.
    /// </summary>
    [Test]
    public void TestIntOptions()
    {
        var config = new I2PConfig();
        config.SetOption("test.num", "42");

        Assert.AreEqual(42, config.GetOptionInt("test.num"));
        Assert.AreEqual(99, config.GetOptionInt("nonexistent", 99),
            "Missing key should return default");
    }

    /// <summary>
    ///     Verify all i2pd-compatible default options are present.
    /// </summary>
    [Test]
    public void TestAllExpectedDefaults()
    {
        var config = new I2PConfig();

        // Transport defaults
        Assert.IsNotNull(config.GetOption("ntcp2.enabled"));
        Assert.IsNotNull(config.GetOption("ssu2.enabled"));
        Assert.IsNotNull(config.GetOption("ntcp2.published"));
        Assert.IsNotNull(config.GetOption("ssu2.published"));

        // Client defaults
        Assert.IsNotNull(config.GetOption("sam.enabled"));
        Assert.IsNotNull(config.GetOption("sam.port"));
        Assert.IsNotNull(config.GetOption("bob.enabled"));
        Assert.IsNotNull(config.GetOption("i2cp.enabled"));
        Assert.IsNotNull(config.GetOption("httpproxy.enabled"));
        Assert.IsNotNull(config.GetOption("socksproxy.enabled"));

        // Limits
        Assert.IsNotNull(config.GetOption("limits.transittunnels"));
        Assert.IsNotNull(config.GetOption("limits.ntcpsoft"));
        Assert.IsNotNull(config.GetOption("limits.ntcphard"));

        // UPnP
        Assert.IsNotNull(config.GetOption("upnp.enabled"));

        // Reseed
        Assert.IsNotNull(config.GetOption("reseed.verify"));

        // Exploratory tunnels
        Assert.IsNotNull(config.GetOption("exploratory.inbound.length"));
        Assert.IsNotNull(config.GetOption("exploratory.outbound.length"));
    }
}