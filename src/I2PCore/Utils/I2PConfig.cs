using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace I2PCore.Utils;

/// <summary>
///     INI-style configuration file parser for i2pd-compatible configuration.
///     Supports: key=value pairs, [sections], # comments, quoted values.
///     Compatible with i2pd.conf and tunnels.conf formats.
/// </summary>
public class I2PConfig
{
    // Default values matching i2pd defaults
    private static readonly Dictionary<string, string> Defaults = new(StringComparer.OrdinalIgnoreCase)
    {
        // General
        ["log"] = "stdout",
        ["loglevel"] = "info",
        ["logclftime"] = "false",
        ["daemon"] = "false",
        ["service"] = "false",
        ["ipv4"] = "true",
        ["ipv6"] = "false",
        ["notransit"] = "false",
        ["floodfill"] = "false",
        ["bandwidth"] = "",
        ["share"] = "100",
        ["netid"] = "2",
        ["nat"] = "true",

        // HTTP server
        ["http.enabled"] = "true",
        ["http.address"] = "127.0.0.1",
        ["http.port"] = "7070",

        // HTTP proxy
        ["httpproxy.enabled"] = "true",
        ["httpproxy.address"] = "127.0.0.1",
        ["httpproxy.port"] = "4444",

        // SOCKS proxy
        ["socksproxy.enabled"] = "true",
        ["socksproxy.address"] = "127.0.0.1",
        ["socksproxy.port"] = "4447",

        // SAM
        ["sam.enabled"] = "true",
        ["sam.address"] = "127.0.0.1",
        ["sam.port"] = "7656",

        // BOB
        ["bob.enabled"] = "false",
        ["bob.address"] = "127.0.0.1",
        ["bob.port"] = "2827",

        // I2CP
        ["i2cp.enabled"] = "false",
        ["i2cp.address"] = "127.0.0.1",
        ["i2cp.port"] = "7654",

        // I2PControl
        ["i2pcontrol.enabled"] = "false",
        ["i2pcontrol.address"] = "127.0.0.1",
        ["i2pcontrol.port"] = "7650",

        // Transports
        ["ntcp2.enabled"] = "true",
        ["ntcp2.port"] = "0",
        ["ssu2.enabled"] = "true",
        ["ssu2.port"] = "0",

        // Reseed
        ["reseed.verify"] = "false",
        ["reseed.threshold"] = "25",

        // Addressbook
        ["addressbook.enabled"] = "true",

        // Limits
        ["limits.transittunnels"] = "25000",
        ["limits.ntcpsoft"] = "128",
        ["limits.ntcphard"] = "256",
        ["limits.openfiles"] = "0",

        // Family
        ["family"] = "",
        ["family.key"] = "",

        // NTCP2 advanced
        ["ntcp2.published"] = "true",
        ["ntcp2.proxy"] = "",

        // SSU2 advanced
        ["ssu2.published"] = "true",

        // Addressbook subscriptions
        ["addressbook.defaulturl"] = "http://reg.i2p/hosts.txt",
        ["addressbook.subscriptions"] = "",

        // Reseed advanced
        ["reseed.urls"] = "",
        ["reseed.floodfill"] = "",

        // Exploratory tunnel settings
        ["exploratory.inbound.length"] = "2",
        ["exploratory.inbound.quantity"] = "3",
        ["exploratory.outbound.length"] = "2",
        ["exploratory.outbound.quantity"] = "3",

        // Persist
        ["persist.profiles"] = "true",

        // Meshnets (Yggdrasil)
        ["meshnets.yggdrasil"] = "false",
        ["meshnets.yggaddress"] = "",

        // UPnP
        ["upnp.enabled"] = "true",
        ["upnp.name"] = "I2P",

        // Nettime
        ["nettime.enabled"] = "true",
        ["nettime.ntpservers"] = "pool.ntp.org",

        // Graceful shutdown
        ["gracefulshutdown.timeout"] = "600"
    };

    private readonly Dictionary<string, string> _options = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, string>> _sections = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    ///     Parse command-line arguments (--key=value or --key value)
    /// </summary>
    public void ParseCommandLine(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("--"))
            {
                var keyval = arg[2..];
                var eqIdx = keyval.IndexOf('=');
                if (eqIdx >= 0)
                    _options[keyval[..eqIdx]] = keyval[(eqIdx + 1)..];
                else if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                    _options[keyval] = args[++i];
                else
                    _options[keyval] = "true";
            }
        }
    }

    /// <summary>
    ///     Parse an INI configuration file
    /// </summary>
    public void ParseConfigFile(string path)
    {
        if (!File.Exists(path)) return;

        string currentSection = null;

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith(';'))
                continue;

            // Section header
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentSection = line[1..^1].Trim();
                if (!_sections.ContainsKey(currentSection))
                    _sections[currentSection] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                continue;
            }

            // Key=value
            var eqIdx = line.IndexOf('=');
            if (eqIdx < 0) continue;

            var key = line[..eqIdx].Trim();
            var value = line[(eqIdx + 1)..].Trim();

            // Remove quotes
            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
                value = value[1..^1];

            if (currentSection != null)
            {
                _sections[currentSection][key] = value;
                // Also store as section.key in flat options
                _options[$"{currentSection}.{key}"] = value;
            }
            else
            {
                _options[key] = value;
            }
        }
    }

    /// <summary>
    ///     Parse tunnels.conf file (each section defines a tunnel)
    /// </summary>
    public void ParseTunnelsConfig(string path)
    {
        if (!File.Exists(path)) return;
        ParseConfigFile(path); // Same INI format
    }

    /// <summary>
    ///     Get a string option
    /// </summary>
    public string GetOption(string key, string defaultValue = null)
    {
        if (_options.TryGetValue(key, out var val)) return val;
        if (Defaults.TryGetValue(key, out var def)) return def;
        return defaultValue;
    }

    /// <summary>
    ///     Get an integer option
    /// </summary>
    public int GetOptionInt(string key, int defaultValue = 0)
    {
        var val = GetOption(key);
        return int.TryParse(val, out var result) ? result : defaultValue;
    }

    /// <summary>
    ///     Get a boolean option
    /// </summary>
    public bool GetOptionBool(string key, bool defaultValue = false)
    {
        var val = GetOption(key);
        if (val == null) return defaultValue;
        return val == "true" || val == "1" || val == "yes";
    }

    /// <summary>
    ///     Get all key-value pairs in a section
    /// </summary>
    public Dictionary<string, string> GetSection(string section)
    {
        return _sections.TryGetValue(section, out var dict)
            ? new Dictionary<string, string>(dict)
            : new Dictionary<string, string>();
    }

    /// <summary>
    ///     Get all section names
    /// </summary>
    public IEnumerable<string> GetSections()
    {
        return _sections.Keys;
    }

    /// <summary>
    ///     Set an option programmatically
    /// </summary>
    public void SetOption(string key, string value)
    {
        _options[key] = value;
    }

    public void SetSectionOption(string section, string key, string value)
    {
        if (!_sections.ContainsKey(section))
            _sections[section] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        _sections[section][key] = value;
        _options[$"{section}.{key}"] = value;
    }

    public void RemoveSection(string section)
    {
        if (_sections.Remove(section, out var dict))
            foreach (var key in dict.Keys)
                _options.Remove($"{section}.{key}");
    }

    public void SaveConfigFile(string path)
    {
        using var writer = new StreamWriter(path);
        // Global options first
        foreach (var opt in _options.Where(o => !o.Key.Contains('.')))
            writer.WriteLine(opt.Key + "=" + opt.Value);

        foreach (var section in _sections)
        {
            writer.WriteLine();
            writer.WriteLine($"[{section.Key}]");
            foreach (var opt in section.Value) writer.WriteLine($"{opt.Key}={opt.Value}");
        }
    }
}