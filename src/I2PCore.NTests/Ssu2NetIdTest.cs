using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using I2PCore.Data;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TransportLayer.SSU2.Messages;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-0d (docs/PRODUCTION-PLAN.md). SSU2 built every outgoing header with a literal
///     <c>NetId = 2</c> while validating incoming ones against
///     <see cref="I2PConstants.I2PNetworkId" />.
///
///     <para>
///         <b>The send path was pinned to the live network while the receive path honoured
///         configuration</b>, so on any other netid SSU2 rejected its own traffic:
///         <c>SSU2SecurityValidator.ValidateVersionAndNetId</c> compares against the configured
///         id, and <c>SSU2Helpers</c> does the same. Every integration test runs on netid 99 and
///         CLAUDE.md mandates netid 3 for local work, so **no SSU2 handshake could complete on
///         any netid this project is allowed to use** — which is a large part of why Phase 4 had
///         nothing to measure.
///     </para>
///     <para>
///         Five sites carried the literal: <c>SSU2Session</c> (Session Request and Session
///         Created), <c>SSU2RelayHandler</c>, and the <c>SessionRequest</c> / <c>SessionCreated</c>
///         message constructors — the first of which spelled the assumption out as
///         <c>// I2P mainnet</c>. Batch 3-3 recorded two of them; the other three were found by
///         grepping for the pattern rather than the symptom.
///     </para>
/// </summary>
[TestFixture]
public class Ssu2NetIdTest
{
    /// <summary>
    ///     A plain substring search for "NetId = 2" is wrong, and was caught being wrong on this
    ///     fixture's first run: <c>SSU2Blocks.cs</c> declares the termination reason
    ///     <c>WrongNetId = 21</c>, which contains it. The lookbehind rejects an identifier ending
    ///     in NetId, and the trailing boundary rejects 21, 20 and so on.
    /// </summary>
    private static readonly Regex Hardcoded =
        new( @"(?<![A-Za-z_])NetId\s*=\s*(?:2|0x02)\b", RegexOptions.Compiled );

    private int _originalNetworkId;

    /// <summary>
    ///     <see cref="I2PConstants.I2PNetworkId" /> is a mutable process-wide static, so these
    ///     tests must put it back however they exit — NUnit shuffles fixture order, and a leaked
    ///     netid would silently retarget whatever runs next.
    /// </summary>
    [SetUp]
    public void SetUp()
    {
        _originalNetworkId = I2PConstants.I2PNetworkId;
    }

    [TearDown]
    public void TearDown()
    {
        I2PConstants.I2PNetworkId = _originalNetworkId;
    }

    /// <summary>
    ///     The functional statement of the bug: a header built while configured for the test
    ///     network must not announce the live one. Confirmed to fail with `NetId = 2` reinstated
    ///     (announces 2, expected 99).
    /// </summary>
    [Test]
    public void AHeaderAnnouncesTheConfiguredNetworkAndNotTheLiveOne()
    {
        I2PConstants.I2PNetworkId = 99;

        ClassicAssert.AreEqual( 99, new SessionRequest().Header.NetId,
            "a Session Request built on netid 99 announced a different network" );
        ClassicAssert.AreEqual( 99, new SessionCreated().Header.NetId,
            "a Session Created built on netid 99 announced a different network" );
    }

    /// <summary>
    ///     The consequence that actually blocked Phase 4, stated as a round trip: what we send
    ///     has to be something we would accept. This fails with the defect reinstated because
    ///     the sender says 2 and the validator wants 99.
    /// </summary>
    [Test]
    public void WhatWeSendIsSomethingWeWouldAccept()
    {
        foreach ( var netId in new[] { 2, 3, 99 } )
        {
            I2PConstants.I2PNetworkId = netId;

            var header = new SessionRequest().Header;

            ClassicAssert.IsTrue(
                SSU2SecurityValidator.ValidateVersionAndNetId( header.Version, header.NetId ),
                $"on netid {netId} we build a Session Request our own validator rejects" );
        }
    }

    /// <summary>
    ///     Netid 3 is the one CLAUDE.md and the plan require for all local and integration
    ///     testing until Gate 6, so it gets its own assertion rather than living inside the loop
    ///     above — if this regresses, the safe testing configuration is the one that broke.
    /// </summary>
    [Test]
    public void TheMandatedTestNetworkIdIsUsable()
    {
        I2PConstants.I2PNetworkId = 3;

        ClassicAssert.AreEqual( 3, new SessionRequest().Header.NetId,
            "netid 3 is required for all pre-Gate-6 testing; SSU2 must be able to speak it" );
    }

    /// <summary>
    ///     Stops the literal coming back. A behavioural test only covers the constructors it
    ///     calls, and two of the five sites are inside <c>SSU2Session</c> methods that need a
    ///     live session to reach.
    /// </summary>
    [Test]
    public void NoSsu2CodeHardcodesTheNetworkId()
    {
        var offenders = Ssu2Sources()
            .Select( f => ( file: Path.GetFileName( f ), text: File.ReadAllText( f ) ) )
            .Where( f => Hardcoded.IsMatch( StripComments( f.text ) ) )
            .Select( f => f.file )
            .ToArray();

        CollectionAssert.IsEmpty( offenders,
            "these files hardcode the network id in an SSU2 header. Use "
            + "(byte)I2PConstants.I2PNetworkId — netid 2 is the live network, and a literal here "
            + "means SSU2 cannot run on the netid the plan mandates for testing." );
    }

    /// <summary>
    ///     Batch 3-6's lesson: an audit that scans nothing passes.
    /// </summary>
    [Test]
    public void TheScanActuallyReadsTheSsu2Sources()
    {
        var files = Ssu2Sources();

        ClassicAssert.Greater( files.Length, 10,
            "the SSU2 source scan found almost nothing — it is looking in the wrong place, "
            + "which would make NoSsu2CodeHardcodesTheNetworkId vacuous" );
        ClassicAssert.IsTrue( files.Any( f => Path.GetFileName( f ) == "SSU2Session.cs" ),
            "SSU2Session.cs carries two of the five original sites and was not scanned" );
    }

    private static string StripComments( string source )
    {
        return string.Join( "\n", source
            .Split( '\n' )
            .Select( line =>
            {
                var comment = line.IndexOf( "//", StringComparison.Ordinal );
                return comment >= 0 ? line[..comment] : line;
            } ) );
    }

    private static string[] Ssu2Sources()
    {
        var dir = new DirectoryInfo( AppContext.BaseDirectory );

        while ( dir != null )
        {
            var candidate = Path.Combine(
                dir.FullName, "src", "I2PCore", "TransportLayer", "SSU2" );
            if ( Directory.Exists( candidate ) )
                return Directory.GetFiles( candidate, "*.cs", SearchOption.AllDirectories );

            dir = dir.Parent;
        }

        return Array.Empty<string>();
    }
}
