using System;
using System.IO;
using System.Text;
using I2PCore;
using I2PCore.Data;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 1-2 (docs/PRODUCTION-PLAN.md). SU3 signature verification, fail-closed.
///     <para>
///         The fixture is a real archive fetched from https://i2p.novg.net/i2pseeds.su3 on
///         2026-08-07, signed by igor@novg.net with SigType 6 (RSA_SHA512_4096). Its signer's
///         certificate is one of the 14 pinned in I2PCore/certificates/reseed/. Nothing here
///         imports routers into NetDb — these tests exercise verification and the accept/reject
///         decision only.
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class Su3SignatureTest
{
    [SetUp]
    public void LoadFixture()
    {
        var path = Path.Combine( AppContext.BaseDirectory, "TestData", "igor_at_novg.net.su3" );

        if ( !File.Exists( path ) )
            Assert.Fail( $"SU3 fixture missing at {path}" );

        Su3 = File.ReadAllBytes( path );
        Bootstrap.InsecureReseed = false;
    }

    [TearDown]
    public void RestoreDefault()
    {
        Bootstrap.InsecureReseed = false;
    }

    private byte[] Su3;

    /// <summary>
    ///     Offset of the first content byte: fixed 40-byte header + version + signer id.
    /// </summary>
    private int ContentOffset => 40 + Su3[13] + Su3[15];

    private static (I2Psu3Header Header, I2PByteBlock Signed, I2PByteBlock Signature) Split( byte[] su3 )
    {
        var reader = new I2PBufferCursor( new I2PByteBlock( su3 ) );
        var start = reader.Position;
        var header = new I2Psu3Header( reader );

        reader.ReadBlock( (int)header.ContentLength );
        var signed = reader.BlockSince( start );
        var signature = reader.ReadBlock( header.SignatureLength );

        return ( header, signed, signature );
    }

    /// <summary>
    ///     The whole point of the batch: this used to return false for every real archive, which
    ///     is why the caller had been rewritten to accept unverified data.
    /// </summary>
    [Test]
    public void RealArchiveVerifies()
    {
        var (header, signed, signature) = Split( Su3 );

        ClassicAssert.AreEqual( "igor@novg.net", header.SignerId );
        ClassicAssert.AreEqual( 6, header.SignatureType, "SigType 6 is RSA_SHA512_4096" );
        ClassicAssert.AreEqual( 512, header.SignatureLength );

        ClassicAssert.IsTrue( Bootstrap.VerifySu3Signature( header, signed, signature ),
            "a genuine, correctly signed reseed archive must verify" );
    }

    [Test]
    public void TamperedContentIsRejected()
    {
        var tampered = (byte[])Su3.Clone();
        tampered[ContentOffset + 512] ^= 0x01;

        var (header, signed, signature) = Split( tampered );

        ClassicAssert.IsFalse( Bootstrap.VerifySu3Signature( header, signed, signature ),
            "flipping one bit of content must break verification" );
    }

    [Test]
    public void TamperedSignatureIsRejected()
    {
        var tampered = (byte[])Su3.Clone();
        tampered[^1] ^= 0x01;

        var (header, signed, signature) = Split( tampered );

        ClassicAssert.IsFalse( Bootstrap.VerifySu3Signature( header, signed, signature ) );
    }

    /// <summary>
    ///     Re-signing under a different pinned signer is the realistic attack: an attacker who can
    ///     serve an archive picks whichever signer they have a key for. We must verify against the
    ///     certificate named in the header and nothing else.
    /// </summary>
    [Test]
    public void SignerSubstitutionIsRejected()
    {
        var substituted = ReplaceSignerId( Su3, "acetone@mail.i2p" );

        var (header, signed, signature) = Split( substituted );

        ClassicAssert.AreEqual( "acetone@mail.i2p", header.SignerId );
        ClassicAssert.IsFalse( Bootstrap.VerifySu3Signature( header, signed, signature ),
            "the archive is signed by igor@novg.net; acetone's key must not verify it" );
    }

    [Test]
    public void UnknownSignerIsRejected()
    {
        var substituted = ReplaceSignerId( Su3, "attacker@example.com" );

        var (header, signed, signature) = Split( substituted );

        ClassicAssert.IsFalse( Bootstrap.VerifySu3Signature( header, signed, signature ),
            "no pinned certificate means no verification, which means no trust" );
    }

    /// <summary>
    ///     A signature length that disagrees with the declared SigType must be refused before any
    ///     crypto runs, so a header cannot steer the parse.
    /// </summary>
    [Test]
    public void SignatureLengthMustMatchSigType()
    {
        var mangled = (byte[])Su3.Clone();
        mangled[8] = 0;
        mangled[9] = 4; // RSA_SHA256_2048, which requires a 256-byte signature

        var (header, signed, signature) = Split( mangled );

        ClassicAssert.IsFalse( Bootstrap.VerifySu3Signature( header, signed, signature ) );
    }

    [Test]
    public void UnknownSigTypeIsRejected()
    {
        var mangled = (byte[])Su3.Clone();
        mangled[8] = 0;
        mangled[9] = 99;

        var (header, signed, signature) = Split( mangled );

        ClassicAssert.IsFalse( Bootstrap.VerifySu3Signature( header, signed, signature ) );
    }

    // ---- the accept/reject decision in GetRouterInfoFiles ----

    [Test]
    public void ValidArchiveIsAccepted()
    {
        using var arch = Bootstrap.GetRouterInfoFiles( new I2PByteBlock( Su3 ) );

        ClassicAssert.IsNotNull( arch, "a verified archive must be handed to the importer" );
        ClassicAssert.Greater( arch.Entries.Count, 0 );
    }

    /// <summary>
    ///     Before this batch a tampered archive was imported anyway, on the stated grounds that
    ///     "HTTPS transport provides integrity" — while TLS validation was disabled two functions
    ///     away. Returning null makes NetworkBootstrap() move on to the next reseed host.
    /// </summary>
    [Test]
    public void TamperedArchiveIsRejectedNotImported()
    {
        var tampered = (byte[])Su3.Clone();
        tampered[ContentOffset + 512] ^= 0x01;

        var arch = Bootstrap.GetRouterInfoFiles( new I2PByteBlock( tampered ) );

        ClassicAssert.IsNull( arch, "a tampered SU3 must be rejected, not imported with a warning" );
    }

    /// <summary>
    ///     R3 in the plan: the escape hatch has to keep reseed working for anyone the fail-closed
    ///     path locks out.
    /// </summary>
    [Test]
    public void InsecureReseedAcceptsTamperedArchive()
    {
        var tampered = (byte[])Su3.Clone();
        tampered[ContentOffset + 512] ^= 0x01;

        Bootstrap.InsecureReseed = true;

        using var arch = Bootstrap.GetRouterInfoFiles( new I2PByteBlock( tampered ) );

        ClassicAssert.IsNotNull( arch, "--insecure-reseed must downgrade rejection to a warning" );
    }

    /// <summary>
    ///     Rewrite the signer id in place, keeping the header self-consistent. The signature is
    ///     left alone, so the archive is exactly what an attacker replaying someone else's bytes
    ///     under a different name would produce.
    /// </summary>
    private static byte[] ReplaceSignerId( byte[] su3, string signerId )
    {
        var oldLen = su3[15];
        var newId = Encoding.UTF8.GetBytes( signerId );
        var idOffset = 40 + su3[13];

        var result = new byte[su3.Length - oldLen + newId.Length];

        Array.Copy( su3, 0, result, 0, idOffset );
        Array.Copy( newId, 0, result, idOffset, newId.Length );
        Array.Copy( su3, idOffset + oldLen, result, idOffset + newId.Length,
            su3.Length - idOffset - oldLen );

        result[15] = (byte)newId.Length;

        return result;
    }
}
