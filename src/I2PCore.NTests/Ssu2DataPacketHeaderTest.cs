using System;
using System.Linq;
using I2PCore.Crypto;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-1a (docs/PRODUCTION-PLAN.md). The SSU2 <b>data phase</b> carried its own
///     self-agreeing convention error — the same shape as batch 4-0's header-keystream defect,
///     and unreached for the same reason: SSU2 has never completed a handshake, so no data packet
///     has ever been built and parsed in anger.
///
///     <para>
///         <c>BuildEncryptedPacket</c> hand-rolled a 16-byte header that is not an SSU2 short
///         header — two bytes of connection ID at 0-1, the packet number at 4, a type byte at 2 —
///         while every reader in the codebase takes the type from offset 12. <c>Parse</c>
///         mirrored the same invented layout, so build/parse round-tripped perfectly and nothing
///         failed. Truncating the 64-bit connection ID to its top 16 bits was the worse half:
///         two sessions agreeing in those bits were indistinguishable.
///     </para>
///     <para>
///         <b>These tests deliberately do not assert against <c>SSU2DataPacket</c>'s own
///         round trip.</b> That is exactly what passed throughout. They assert against
///         <see cref="SSU2Header" />, which is the one definition of the wire format and which
///         the long-header path has always used, and against hand-computed offsets.
///     </para>
///     <para>
///         <b>Not verified against i2pd.</b> Batch 3-5 could not capture a Data packet — that
///         needs a completed handshake, which is blocked on 4-0b and 4-2. What is proven here is
///         internal consistency with `SSU2Header` plus agreement with the offsets the rest of the
///         codebase reads. Interop remains unverified, and the plan should not record otherwise.
///     </para>
/// </summary>
[TestFixture]
public class Ssu2DataPacketHeaderTest
{
    private static readonly byte[] DataKey = Enumerable.Range( 0, 32 ).Select( i => (byte)( i + 1 ) ).ToArray();
    private static readonly byte[] HeaderKey1 = Enumerable.Range( 0, 32 ).Select( i => (byte)( i * 3 + 7 ) ).ToArray();
    private static readonly byte[] HeaderKey2 = Enumerable.Range( 0, 32 ).Select( i => (byte)( 250 - i ) ).ToArray();

    private const ulong ConnId = 0x0123456789ABCDEF;
    private const uint PacketNum = 0x11223344;

    /// <summary>
    ///     The defect, stated where it cannot hide: the header a data packet puts on the wire
    ///     must be the header <see cref="SSU2Header" /> defines. Confirmed to fail against the
    ///     old hand-rolled layout.
    /// </summary>
    [Test]
    public void TheDataHeaderIsTheOneSsu2HeaderDefines()
    {
        var plaintextHeader = Unmask( BuildPacket() );

        var expected = new SSU2Header
        {
            IsLongHeader = false,
            DestinationConnectionId = ConnId,
            PacketNumber = PacketNum,
            Type = SSU2Header.TYPE_DATA
        }.ToByteArray();

        CollectionAssert.AreEqual( expected, plaintextHeader,
            "the data packet's header does not match SSU2Header's own serialization" );
    }

    /// <summary>
    ///     The offsets spelled out, so a failure says which field moved rather than just
    ///     "arrays differ". These are the offsets every other reader in the codebase uses —
    ///     `SSU2Session.ProcessReceivedPacket` peeks the type at 12.
    /// </summary>
    [Test]
    public void ConnectionIdPacketNumberAndTypeSitAtTheOffsetsEveryReaderUses()
    {
        var h = Unmask( BuildPacket() );

        ClassicAssert.AreEqual( ConnId, ReadUInt64BE( h, 0 ),
            "destination connection ID must occupy bytes 0-7 in full" );
        ClassicAssert.AreEqual( PacketNum, ReadUInt32BE( h, 8 ),
            "packet number must sit at bytes 8-11, not 4-7" );
        ClassicAssert.AreEqual( SSU2Header.TYPE_DATA, h[12],
            "type must sit at byte 12, which is where the receive path peeks it" );
    }

    /// <summary>
    ///     The truncation, called out on its own because it is a correctness bug rather than a
    ///     layout one: the old code kept only the top 16 bits, so two connection IDs agreeing
    ///     there parsed as the same session.
    /// </summary>
    [Test]
    public void TheFullSixtyFourBitConnectionIdSurvivesARoundTrip()
    {
        var parsed = SSU2DataPacket.Parse( BuildPacket(), DataKey, HeaderKey1, HeaderKey2 );

        ClassicAssert.AreEqual( ConnId, parsed.Header.DestinationConnectionId,
            "the connection ID was truncated; only its top bytes survived" );
    }

    /// <summary>
    ///     <c>BuildWithBlock</c> took a data key and a header key and used neither, returning the
    ///     bare block list. Everything <c>SendBlock</c> ever sent — relay tag requests, peer
    ///     tests — went out unframed and unencrypted.
    /// </summary>
    [Test]
    public void BuildWithBlockActuallyEncryptsWhatItIsGivenKeysFor()
    {
        var blockData = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };

        var packet = SSU2DataPacket.BuildWithBlock(
            SSU2BlockType.Padding, blockData, ConnId, PacketNum,
            DataKey, HeaderKey1, HeaderKey2 );

        ClassicAssert.Greater( packet.Length, 16 + blockData.Length,
            "an encrypted packet must carry a 16-byte header and a 16-byte AEAD tag; this is "
            + "barely longer than the plaintext block, so nothing was framed or encrypted" );

        ClassicAssert.IsFalse(
            ContainsSequence( packet, blockData ),
            "the block's plaintext bytes appear in the packet, so it went out in the clear" );

        var parsed = SSU2DataPacket.Parse( packet, DataKey, HeaderKey1, HeaderKey2 );
        CollectionAssert.AreEqual( blockData, parsed.Blocks.Single().Data );
    }

    /// <summary>
    ///     The third site: the receive path peeked the type by handing a whole packet to
    ///     <c>DecryptShortHeader</c>, which throws for any array that is not exactly 16 bytes —
    ///     so every data packet bigger than its own header was thrown into the outer catch and
    ///     dropped. Asserts the in-packet form is usable on a realistic packet.
    /// </summary>
    [Test]
    public void TheHeaderCanBeUnmaskedInsideAFullSizePacket()
    {
        var packet = BuildPacket();
        ClassicAssert.Greater( packet.Length, 16, "fixture must use a packet longer than a header" );

        Assert.DoesNotThrow( () =>
                SSU2HeaderEncryption.DecryptShortHeaderInPacket( packet, 0, HeaderKey1, HeaderKey2 ),
            "unmasking a short header inside a real packet must not throw" );
    }

    private static byte[] BuildPacket()
    {
        var packet = new SSU2DataPacket
        {
            Header = new SSU2Header
            {
                IsLongHeader = false,
                DestinationConnectionId = ConnId,
                PacketNumber = PacketNum
            }
        };
        packet.Blocks.Add( new SSU2BlockWrapper
        {
            BlockType = SSU2BlockType.Padding,
            Data = new byte[24]
        } );

        return packet.BuildEncryptedPacket( DataKey, HeaderKey1, HeaderKey2 );
    }

    /// <summary>Recover the 16 plaintext header bytes from a built packet.</summary>
    private static byte[] Unmask( byte[] packet )
    {
        var copy = (byte[])packet.Clone();
        SSU2HeaderEncryption.DecryptShortHeaderInPacket( copy, 0, HeaderKey1, HeaderKey2 );
        return copy.Take( 16 ).ToArray();
    }

    private static ulong ReadUInt64BE( byte[] b, int off )
    {
        ulong v = 0;
        for ( var i = 0; i < 8; ++i ) v = ( v << 8 ) | b[off + i];
        return v;
    }

    private static uint ReadUInt32BE( byte[] b, int off )
    {
        uint v = 0;
        for ( var i = 0; i < 4; ++i ) v = ( v << 8 ) | b[off + i];
        return v;
    }

    private static bool ContainsSequence( byte[] haystack, byte[] needle )
    {
        for ( var i = 0; i + needle.Length <= haystack.Length; ++i )
            if ( haystack.Skip( i ).Take( needle.Length ).SequenceEqual( needle ) )
                return true;

        return false;
    }
}
