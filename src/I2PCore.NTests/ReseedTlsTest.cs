using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using I2PCore;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 1-1 (docs/PRODUCTION-PLAN.md). Reseed is the router's entire initial view of the
///     network. Before this batch both download paths disabled TLS certificate validation
///     outright, so anyone on the path could pick every peer the router would ever know.
///     These tests hold the line: validation is on unless an operator explicitly asks for it.
/// </summary>
[TestFixture]
[NonParallelizable]
public class ReseedTlsTest
{
    [TearDown]
    public void RestoreDefault()
    {
        Bootstrap.InsecureReseed = false;
    }

    /// <summary>
    ///     A null callback is what makes HttpClientHandler fall through to the platform's
    ///     ordinary chain validation against the system trust store.
    /// </summary>
    [Test]
    public void ReseedValidatesCertificatesByDefault()
    {
        ClassicAssert.IsFalse( Bootstrap.InsecureReseed,
            "InsecureReseed must default to off" );

        using var handler = Bootstrap.CreateReseedHandler();

        ClassicAssert.IsNull( handler.ServerCertificateCustomValidationCallback,
            "reseed downloads must use system TLS validation, not a custom accept-all callback" );
    }

    /// <summary>
    ///     The escape hatch has to actually work — batch 1-2 tightens SU3 verification on top of
    ///     this, and R3 in the plan depends on --insecure-reseed existing beforehand.
    /// </summary>
    [Test]
    public void InsecureReseedRestoresAcceptAnyCertificate()
    {
        Bootstrap.InsecureReseed = true;

        using var handler = Bootstrap.CreateReseedHandler();

        ClassicAssert.AreEqual(
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
            handler.ServerCertificateCustomValidationCallback,
            "--insecure-reseed must restore the previous accept-any behaviour" );
    }

    [Test]
    public void InsecureReseedIsRevocable()
    {
        Bootstrap.InsecureReseed = true;
        Bootstrap.InsecureReseed = false;

        using var handler = Bootstrap.CreateReseedHandler();

        ClassicAssert.IsNull( handler.ServerCertificateCustomValidationCallback );
    }

    /// <summary>
    ///     Guards against the deleted pattern reappearing anywhere in the library. An
    ///     unconditional accept-all validator is only ever correct behind
    ///     <see cref="Bootstrap.InsecureReseed" />, which is a runtime check, not a literal.
    /// </summary>
    [Test]
    public void NoUnconditionalCertificateAcceptanceInI2PCore()
    {
        var root = FindI2PCoreSourceRoot();

        if ( root == null )
            Assert.Ignore( "I2PCore source tree not found next to the test assembly" );

        // Matches `ServerCertificateCustomValidationCallback = <lambda returning true>` and
        // `= HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`, on one line.
        var pattern = new Regex(
            @"ServerCertificateCustomValidationCallback\s*=\s*(\([^)]*\)\s*=>\s*true|delegate|HttpClientHandler\.Dangerous)",
            RegexOptions.Compiled );

        var offenders = Directory
            .EnumerateFiles( root, "*.cs", SearchOption.AllDirectories )
            .Where( f => !f.Contains( $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}" ) )
            .SelectMany( f => File.ReadLines( f )
                .Select( ( line, n ) => ( f, n: n + 1, line ) )
                .Where( t => pattern.IsMatch( t.line ) ) )
            // The one legitimate site: Bootstrap.CreateReseedHandler(), reached only when the
            // operator has set InsecureReseed.
            .Where( t => Path.GetFileName( t.f ) != "Bootstrap.cs" )
            .Select( t => $"{Path.GetFileName( t.f )}:{t.n}" )
            .ToList();

        ClassicAssert.IsEmpty( offenders,
            "TLS certificate validation must not be disabled outside Bootstrap.CreateReseedHandler(): "
            + string.Join( ", ", offenders ) );
    }

    private static string FindI2PCoreSourceRoot()
    {
        var dir = new DirectoryInfo( AppContext.BaseDirectory );

        while ( dir != null )
        {
            var candidate = Path.Combine( dir.FullName, "src", "I2PCore" );
            if ( Directory.Exists( candidate ) ) return candidate;

            dir = dir.Parent;
        }

        return null;
    }
}
