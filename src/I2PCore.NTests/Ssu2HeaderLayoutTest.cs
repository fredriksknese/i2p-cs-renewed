using System;
using System.Linq;
using I2PCore.Crypto;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PTests;

/// <summary>
///     Batch 4-0 (docs/PRODUCTION-PLAN.md). Pins the *second* divergence from i2pd that fixing
///     the ChaCha20 block counter uncovered, so batch <b>4-0b</b> has a concrete target rather
///     than a paragraph of prose.
///
///     <para>
///         <b>The convention, taken from i2pd 2.61.0 source</b>, not from the "SSU2 spec lines
///         761-798" citations that used to sit in <c>SSU2HeaderEncryption</c> and refer to a
///         document not in this repository. For Session Request and Session Created, i2pd
///         encrypts packet bytes 16..64 as a <b>single 48-byte ChaCha20 pass</b> — header bytes
///         16-31 (source connection ID, token) plus the 32-byte ephemeral key — with a zero
///         nonce:
///     </para>
///     <code>
///         // libi2pd/SSU2Session.cpp, SendSessionRequest
///         const uint8_t nonce[12] = {0}; // always 0
///         m_Server.ChaCha20 (headerX, 48, m_Address->i, nonce, headerX);
///
///         // libi2pd/SSU2Session.cpp, ProcessSessionRequest
///         m_Server.ChaCha20 (buf + 16, 48, i2p::context.GetSSU2IntroKey (), nonce, headerX);
///     </code>
///     <para>
///         TokenRequest, Retry and PeerTest use a 16-byte pass over bytes 16-31 instead, because
///         they carry no ephemeral key — <c>ChaCha20 (h + 16, 16, ...)</c>. That is the shape our
///         <c>EncryptLongHeaderComplete</c> implements, and it is correct for those messages.
///         It is the 48-byte case we get wrong.
///     </para>
///     <para>
///         <b>Why this is not fixed in 4-0.</b> There is no captured i2pd Session Request to
///         verify a fix against: i2pd opens with a TokenRequest we cannot yet answer (batch 3-5),
///         so batch 3-5's harness never elicited one. Rewriting the handshake byte layout with
///         no reference bytes would be merging a protocol change behind a test that only agrees
///         with itself — the exact failure this whole plan keeps rediscovering. 4-2 unblocks the
///         capture; 4-0b does the fix against it.
///     </para>
/// </summary>
[TestFixture]
public class Ssu2HeaderLayoutTest
{
    private static readonly byte[] Key = Enumerable.Range( 0, 32 ).Select( i => (byte)( i * 7 + 3 ) ).ToArray();
    private static readonly byte[] EphemeralKey = Enumerable.Range( 0, 32 ).Select( i => (byte)( 200 - i ) ).ToArray();

    /// <summary>
    ///     Green, and it stays green after 4-0b: it asserts what i2pd does, not what we do.
    ///     The counterpart of <c>Ssu2GoldenVectorTest.I2pdHeaderMaskComesFromChaCha20BlockOne</c>
    ///     — describe the peer's convention in a test, so a fix is checkable against a number.
    /// </summary>
    [Test]
    public void TheEphemeralKeyRegionIsTheSecondHalfOfOneFortyEightByteKeystream()
    {
        var stream = I2pdKeyStream( Key, new byte[12], 48 );

        // Bytes 16..48 of that one keystream are what covers the ephemeral key. If the region
        // were two independent passes, this slice would instead equal stream[0..32].
        var forEphemeralKey = stream.Skip( 16 ).Take( 32 ).ToArray();
        var fromRestartedStream = stream.Take( 32 ).ToArray();

        ClassicAssert.AreNotEqual( fromRestartedStream, forEphemeralKey,
            "the two conventions must actually differ, or this fixture proves nothing" );
    }

    /// <summary>
    ///     Red, owner batch 4-0b. <c>ObfuscateEphemeralKey</c> restarts the keystream, so it
    ///     XORs the key with bytes 0..32 where i2pd uses 16..48 of the same stream.
    /// </summary>
    [Test]
    [Category( TestCategories.Experimental )]
    public void ObfuscateEphemeralKeyUsesTheContinuationOfTheHeaderKeystream()
    {
        var expected = Xor( EphemeralKey, I2pdKeyStream( Key, new byte[12], 48 ).Skip( 16 ).Take( 32 ).ToArray() );

        var actual = SSU2HeaderEncryption.ObfuscateEphemeralKey( EphemeralKey, Key );

        CollectionAssert.AreEqual( expected, actual,
            "the ephemeral key must be XORed with keystream bytes 16..48 of the same 48-byte "
            + "pass that covers header bytes 16-31, not with a keystream restarted at 0" );
    }

    /// <summary>
    ///     Red, owner batch 4-0b, and the sharper statement of the same defect:
    ///     <c>SessionRequest.ToByteArray</c> calls <c>EncryptLongHeaderInPacket</c>, which stops
    ///     at byte 16. Header bytes 16-31 of a Session Request — the source connection ID and the
    ///     token — are therefore transmitted in the clear.
    /// </summary>
    [Test]
    [Category( TestCategories.Experimental )]
    public void SessionRequestObscuresItsSourceConnectionIdAndToken()
    {
        // A 96-byte packet: 32 header, 32 ephemeral key, 32 payload. Only the header matters.
        var packet = Enumerable.Range( 0, 96 ).Select( i => (byte)i ).ToArray();
        var plaintextRegion = packet.Skip( 16 ).Take( 16 ).ToArray();

        SSU2HeaderEncryption.EncryptLongHeaderInPacket( packet, 0, Key, Key );

        CollectionAssert.AreNotEqual( plaintextRegion, packet.Skip( 16 ).Take( 16 ).ToArray(),
            "bytes 16-31 of a Session Request header carry the source connection ID and token "
            + "and must not go out unencrypted" );
    }

    /// <summary>
    ///     i2pd's ChaCha20 keystream: block counter 1, per <c>libi2pd/Crypto.cpp</c>
    ///     (<c>iv[0] = htole32 (1)</c>). Duplicated from the golden-vector fixture on purpose —
    ///     a reference implementation shared with the code under test would hide exactly the
    ///     class of bug these fixtures exist to catch.
    /// </summary>
    private static byte[] I2pdKeyStream( byte[] key, byte[] nonce, int length )
    {
        var engine = new ChaCha7539Engine();
        engine.Init( true, new ParametersWithIV( new KeyParameter( key ), nonce ) );

        var all = new byte[64 + length];
        engine.ProcessBytes( new byte[64 + length], 0, 64 + length, all, 0 );

        return all.Skip( 64 ).Take( length ).ToArray();
    }

    private static byte[] Xor( byte[] a, byte[] b )
    {
        return a.Zip( b, ( x, y ) => (byte)( x ^ y ) ).ToArray();
    }
}
