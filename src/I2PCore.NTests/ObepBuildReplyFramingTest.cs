using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.ECIES;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Batch 3-13 (docs/PRODUCTION-PLAN.md). The tunnel build reply we send as an outbound
///     endpoint, read the way the peer reads it.
///
///     <para>
///         Two independent reasons i2pd threw ours away, both settled from its source rather than
///         from ours. **The payload framing:** a one-time symmetric garlic has no session to parse
///         blocks against, so <c>SymmetricKeyTagSet::HandleNextMessage</c> reads exactly one block
///         and requires it to be the clove — anything else is "Garlic: Symmetric key tagset
///         unexpected block", which the CI run for batch 3-12 logged 370 times, once per reply we
///         sent, beside 689 "Pending build request timeout, deleted". We led with a DateTime block;
///         i2pd's own symmetric wrap passes <c>datetime = false</c>. **The message ID:** the
///         creator matches a reply against its pending tunnels by I2NP message ID, and the ID it
///         waits for is the one it put in the endpoint record's send-message-ID field, not the ID
///         of the request message — which i2pd fills with <c>RAND_bytes</c>.
///     </para>
///     <para>
///         The decode below is deliberately hand-written against i2pd's layout
///         (<c>GarlicDestination::HandleECIESx25519GarlicClove</c>) instead of calling our own
///         parser. Both defects were invisible precisely because our reader and our writer agreed
///         with each other.
///     </para>
/// </summary>
[TestFixture]
public class ObepBuildReplyFramingTest
{
    // i2pd Garlic.h: eECIESx25519BlkDateTime = 0, eECIESx25519BlkGalicClove = 11,
    // eECIESx25519BlkPadding = 254.
    private const byte BlockDateTime = 0;
    private const byte BlockGarlicClove = 11;

    private const byte ShortTunnelBuildReplyType = 26;

    private const uint RecordSendMessageId = 0x5EDA1D01;
    private const uint RequestMessageId = 0xB0B0B0B0;

    private const int RecordCount = 4;

    private byte[] _garlicKey;
    private ulong _garlicTag;

    [SetUp]
    public void Setup()
    {
        _garlicKey = BufUtils.RandomBytes( 32 );
        _garlicTag = BitConverter.ToUInt64( BufUtils.RandomBytes( 8 ), 0 );
    }

    /// <summary>A build message as it arrives at the endpoint: real record layout, decoy contents.</summary>
    private static ShortTunnelBuildMessage ArrivingRequestMessage()
    {
        var records = Enumerable
            .Range( 0, RecordCount )
            .Select( _ => BufUtils.RandomBytes( ShortTunnelBuildMessage.RecordSize ) )
            .ToList();

        return new ShortTunnelBuildMessage( records ) { MessageId = RequestMessageId };
    }

    /// <summary>
    ///     The record we decrypted out of that message. Only the send message ID matters here; it
    ///     is deliberately different from the arriving message's ID, as it is on the wire from
    ///     i2pd.
    /// </summary>
    private static ShortBuildRequestRecord OurRecord()
    {
        return new ShortBuildRequestRecord
        {
            ReceiveTunnelId = new I2PTunnelId( 4242u ),
            NextTunnelId = new I2PTunnelId( 2424u ),
            Flags = (byte)ShortBuildRequestRecord.BuildRequestFlags.OutboundEndpoint,
            RequestTime = (uint)( DateTime.UtcNow - I2PDate.RefDate ).TotalMinutes,
            RequestExpiration = 600,
            NextMessageId = RecordSendMessageId
        };
    }

    /// <summary>Undoes the transport framing: 4-byte length, 8-byte tag, AEAD under the tag as AD.</summary>
    private byte[] DecryptReply( GarlicMessage garlic )
    {
        var data = garlic.EgData.ToByteArray();
        Assert.Greater( data.Length, 8, "garlic must carry a tag and a ciphertext" );

        var tagBytes = data[..8];
        Assert.AreEqual( BufUtils.Flip64( _garlicTag ), BitConverter.ToUInt64( tagBytes, 0 ),
            "the reply must be addressed with the tag derived from the build record" );

        var plain = ChaCha20Poly1305.Decrypt( _garlicKey, new byte[12], data[8..], tagBytes );

        Assert.IsNotNull( plain, "the reply must decrypt under the garlic key from the build record" );
        return plain;
    }

    /// <summary>
    ///     i2pd's rule, transcribed: read one block header, require the clove, ignore the rest.
    /// </summary>
    private static (byte Type, byte[] Data) FirstBlock( byte[] plain )
    {
        Assert.GreaterOrEqual( plain.Length, 3, "a payload shorter than a block header cannot be read" );

        var type = plain[0];
        var length = ( plain[1] << 8 ) | plain[2];

        Assert.LessOrEqual( 3 + length, plain.Length, "block length must stay inside the payload" );

        return ( type, plain[3..( 3 + length )] );
    }

    [Test]
    public void TheReplyPayloadLeadsWithTheGarlicClove()
    {
        var garlic = TunnelProvider.CreateObepBuildReply(
            ArrivingRequestMessage(), OurRecord(), _garlicKey, _garlicTag );

        var plain = DecryptReply( garlic );
        var ( type, _ ) = FirstBlock( plain );

        Assert.AreNotEqual( BlockDateTime, type,
            "a DateTime block ahead of the clove is what i2pd reports as "
            + "'Symmetric key tagset unexpected block 0' and drops the reply for" );
        Assert.AreEqual( BlockGarlicClove, type,
            "a one-time symmetric garlic must open with the clove — i2pd reads one block and no more" );
    }

    [Test]
    public void TheCloveCarriesTheBuildReplyAsI2pdDecodesIt()
    {
        var stbm = ArrivingRequestMessage();

        var garlic = TunnelProvider.CreateObepBuildReply( stbm, OurRecord(), _garlicKey, _garlicTag );

        var ( _, clove ) = FirstBlock( DecryptReply( garlic ) );

        // HandleECIESx25519GarlicClove: flag(1) | type(1) | msgID(4) | expiration(4) | payload
        Assert.GreaterOrEqual( clove.Length, 10, "clove is shorter than its own header" );
        Assert.AreEqual( 0, ( clove[0] >> 5 ) & 0x03,
            "delivery type must be local — the gateway hands the clove to the router itself" );
        Assert.AreEqual( ShortTunnelBuildReplyType, clove[1],
            "the endpoint answers a ShortTunnelBuild with a ShortTunnelBuildReply, type 26" );

        var payload = clove[10..];
        Assert.AreEqual( RecordCount, payload[0], "reply carries every record, count first" );
        Assert.AreEqual( 1 + RecordCount * ShortTunnelBuildReplyMessage.RecordSize, payload.Length,
            "reply payload is the count byte plus the records, unchanged in size" );

        var arriving = stbm.Records[0].ToByteArray();
        Assert.IsTrue( payload.Skip( 1 ).Take( arriving.Length ).SequenceEqual( arriving ),
            "records are returned as they arrived, our own slot already overwritten by the caller" );
    }

    [Test]
    public void TheReplyIsAddressedWithTheRecordsSendMessageId()
    {
        var stbm = ArrivingRequestMessage();

        var garlic = TunnelProvider.CreateObepBuildReply( stbm, OurRecord(), _garlicKey, _garlicTag );

        var ( _, clove ) = FirstBlock( DecryptReply( garlic ) );
        var cloveMessageId = ( (uint)clove[2] << 24 ) | ( (uint)clove[3] << 16 )
                                                      | ( (uint)clove[4] << 8 ) | clove[5];

        Assert.AreEqual( RecordSendMessageId, cloveMessageId,
            "the creator waits on the send message ID it wrote into the endpoint record" );
        Assert.AreNotEqual( stbm.MessageId, cloveMessageId,
            "the arriving request's message ID is i2pd's random header ID and matches nothing" );
    }
}
