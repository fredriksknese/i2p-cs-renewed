using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using I2PCore.TransportLayer.SSU2;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 1-3 (docs/PRODUCTION-PLAN.md). Gate 1 requires zero <c>new Random(</c> under
///     <c>src/I2PCore</c>.
///     <para>
///         <see cref="Random" /> is a public-state PRNG. Its output went into NTCP2 and SSU2
///         padding, padding lengths, and SSU2 packet numbers — all values an observer either sees
///         directly or can infer the length of. Recovering the generator state from observed
///         output is a known attack on xoshiro-class generators, and every such value must
///         instead come from <see cref="BufUtils" />'s <c>RandomNumberGenerator</c>.
///     </para>
/// </summary>
[TestFixture]
public class CsprngGuardTest
{
    [Test]
    public void NoSystemRandomUnderI2PCore()
    {
        var root = FindSourceDir( "I2PCore" );

        if ( root == null )
            Assert.Ignore( "I2PCore source tree not found next to the test assembly" );

        var offenders = ScanFor( root, new Regex( @"new\s+Random\s*\(", RegexOptions.Compiled ) );

        ClassicAssert.IsEmpty( offenders,
            "System.Random must not be used in I2PCore; use BufUtils (RandomBytes/RandomInt/"
            + "RandomUint/Randomize), which is backed by RandomNumberGenerator: "
            + string.Join( ", ", offenders ) );
    }

    /// <summary>
    ///     <c>Random.Shared</c> and <c>Random.Next</c> on a cached instance would slip past a check
    ///     that only looks for construction.
    /// </summary>
    [Test]
    public void NoSharedSystemRandomUnderI2PCore()
    {
        var root = FindSourceDir( "I2PCore" );

        if ( root == null )
            Assert.Ignore( "I2PCore source tree not found next to the test assembly" );

        var offenders = ScanFor( root, new Regex( @"Random\.Shared", RegexOptions.Compiled ) );

        ClassicAssert.IsEmpty( offenders,
            "Random.Shared is still a non-cryptographic PRNG: " + string.Join( ", ", offenders ) );
    }

    /// <summary>
    ///     The packet number is sent in the clear and used as an AEAD nonce input. The old
    ///     implementation cast <c>Random.Next()</c> to uint, so the high bit was always zero —
    ///     half the space was unreachable regardless of the generator's quality. 2000 draws make
    ///     a false failure here about 1 in 2^2000 if the top bit is uniform.
    /// </summary>
    [Test]
    public void Ssu2PacketNumbersSpanTheFullUintRange()
    {
        var seen = new HashSet<uint>();
        var highBitSet = 0;

        for ( var i = 0; i < 2000; i++ )
        {
            var n = SSU2Helpers.GenerateRandomPacketNumber();
            seen.Add( n );
            if ( ( n & 0x80000000 ) != 0 ) highBitSet++;
        }

        ClassicAssert.Greater( highBitSet, 0,
            "no packet number had its high bit set — the generator cannot reach half the range" );

        ClassicAssert.Greater( seen.Count, 1990,
            "packet numbers repeated far more than chance allows over 2000 draws" );
    }

    private static List<string> ScanFor( string root, Regex pattern )
    {
        return Directory
            .EnumerateFiles( root, "*.cs", SearchOption.AllDirectories )
            .Where( f => !f.Contains( $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}" ) )
            .Where( f => !f.Contains( $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}" ) )
            .SelectMany( f => File.ReadLines( f )
                .Select( ( line, n ) => ( f, n: n + 1, line ) )
                .Where( t => pattern.IsMatch( t.line ) ) )
            .Select( t => $"{Path.GetFileName( t.f )}:{t.n}" )
            .ToList();
    }

    private static string FindSourceDir( string project )
    {
        var dir = new DirectoryInfo( AppContext.BaseDirectory );

        while ( dir != null )
        {
            var candidate = Path.Combine( dir.FullName, "src", project );
            if ( Directory.Exists( candidate ) ) return candidate;

            dir = dir.Parent;
        }

        return null;
    }
}
