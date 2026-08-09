using System;
using System.Collections.Generic;
using System.IO;

namespace I2PTests;

/// <summary>
///     Locates and parses the checked-in golden vectors under <c>TestData/</c>.
///     Batch 3-5 (docs/PRODUCTION-PLAN.md).
///
///     <para>
///         Vectors are captured from a real i2pd by the Integration-category producers (see
///         <c>SSU2GoldenVectorCapture</c>), then checked in so the tests over them are ordinary
///         unit tests that need no i2pd, no network and no ports.
///     </para>
///     <para>
///         The format is deliberately a text header of <c>key=HEX</c> lines: it diffs readably,
///         it can be grepped, and it needs no parser beyond the twenty lines below. A binary
///         container would bring its own bugs to a file whose entire purpose is being trusted.
///     </para>
/// </summary>
public static class GoldenVectors
{
    public const string Ssu2TokenRequest = "ssu2_tokenrequest_i2pd.txt";

    /// <summary>
    ///     Batch 4-2c. i2pd's Session Request, which it only sends after a Retry it accepted — so
    ///     the existence of this file is itself evidence that our Retry is correct. It carries the
    ///     ephemeral key, and is therefore the reference batch 4-0b needs to settle whether bytes
    ///     16..64 are one 48-byte ChaCha20 pass or two restarted ones.
    /// </summary>
    public const string Ssu2SessionRequest = "ssu2_sessionrequest_i2pd.txt";

    /// <summary>
    ///     The <c>TestData</c> directory next to the test assembly. Files there are copied to the
    ///     output directory by the csproj, so this works from the build output rather than
    ///     depending on where the repository happens to sit.
    /// </summary>
    public static string Directory()
    {
        return Path.Combine(AppContext.BaseDirectory, "TestData");
    }

    public static string Path_(string name)
    {
        return Path.Combine(Directory(), name);
    }

    public static bool Exists(string name)
    {
        return File.Exists(Path_(name));
    }

    /// <summary>
    ///     Read a vector as its <c>key</c> → bytes map. Lines starting with <c>#</c> are comments
    ///     and carry the provenance — which i2pd version, which network — that makes a checked-in
    ///     blob auditable later.
    /// </summary>
    public static Dictionary<string, byte[]> Read(string name)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        foreach (var raw in File.ReadAllLines(Path_(name)))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;

            result[line[..eq]] = Convert.FromHexString(line[(eq + 1)..]);
        }

        return result;
    }

    /// <summary>Provenance comment lines, for a test that wants to report where a vector came from.</summary>
    public static IEnumerable<string> Provenance(string name)
    {
        foreach (var raw in File.ReadAllLines(Path_(name)))
        {
            var line = raw.Trim();
            if (line.StartsWith('#')) yield return line.TrimStart('#').Trim();
        }
    }
}
