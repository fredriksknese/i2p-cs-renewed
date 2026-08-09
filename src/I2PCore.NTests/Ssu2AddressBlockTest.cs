using System.Net;
using I2PCore.TransportLayer.SSU2;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 4-0n (docs/PRODUCTION-PLAN.md). The Address block is how a responder tells us the
///     address it sees us on, and ours agreed with itself and with nothing on the network — the
///     seventh instance of this plan's signature defect, and the one that stopped the first
///     otherwise-successful SSU2 handshake with i2pd.
///
///     <para>
///         PR #41's CI run got as far as decrypting and authenticating i2pd's Session Created and
///         then threw:
///     </para>
///     <code>
///         Invalid Address block size: 29260
///            at AddressBlock.Parse            SSU2Blocks.cs:182
///            at ParseSessionCreatedBlocks     SSU2Session.cs:2026
///            at ProcessSessionCreated         SSU2Session.cs:1229
///     </code>
///     <para>
///         <b>29260 is not a length — it is our own SSU2 port</b>, which is exactly what i2pd puts
///         in the block. Two defects produced it, and they cancel out in a round trip:
///     </para>
///     <list type="number">
///         <item>
///             <c>ParseSessionCreatedBlocks</c> consumes the block type and its two-byte size and
///             hands <c>Parse</c> the <b>payload</b>; <c>Parse</c> then read a size <b>again</b>,
///             eating the first two payload bytes.
///         </item>
///         <item>
///             On the wire the payload is <b>port first, then address</b>. <c>Serialize</c> wrote
///             address first, so the two bytes <c>Parse</c> ate were the port.
///         </item>
///     </list>
///     <para>
///         <b>These tests are written against the wire layout, not against our own serializer.</b>
///         A round-trip assertion passes on the broken code — that is what hid this for the whole
///         life of the transport, and it is why the first test below is byte-literal.
///     </para>
/// </summary>
[TestFixture]
public class Ssu2AddressBlockTest
{
    /// <summary>The port i2pd reported, and the number that appeared in the exception.</summary>
    private const ushort ObservedPort = 29260;

    /// <summary>
    ///     The CI failure, reduced to one call. These six bytes are an Address block payload as
    ///     i2pd writes it: port 29260 (<c>0x724C</c>) then 127.0.0.1 — the address and port the
    ///     live test's C# router listens on, which is what i2pd was reporting back to us.
    /// </summary>
    [Test]
    public void AnAddressBlockReadsThePayloadItIsHanded()
    {
        var payload = new byte[] { 0x72, 0x4C, 0x7F, 0x00, 0x00, 0x01 };

        var block = new AddressBlock();
        block.Parse( new I2PBufferCursor( payload ) );

        ClassicAssert.AreEqual( ObservedPort, block.Port,
            "the port was not read from the front of the payload; the caller has already consumed "
            + "the block header, so Parse must not read a size of its own" );
        ClassicAssert.AreEqual( IPAddress.Parse( "127.0.0.1" ),
            new IPAddress( block.IPAddress ) );
    }

    /// <summary>
    ///     The other half, and the reason a round trip cannot catch this: what we *write* has to
    ///     be what a peer reads. i2pd puts the port first, so an Address block we send with the
    ///     address first is one i2pd mis-parses in the same way we mis-parsed its own.
    /// </summary>
    [Test]
    public void AnAddressBlockWritesThePortBeforeTheAddress()
    {
        var serialised = new AddressBlock
        {
            IPAddress = IPAddress.Parse( "127.0.0.1" ).GetAddressBytes(),
            Port = ObservedPort
        }.Serialize();

        CollectionAssert.AreEqual(
            new byte[] { 13, 0x00, 0x06, 0x72, 0x4C, 0x7F, 0x00, 0x00, 0x01 }, serialised,
            "an Address block is type 13, a two-byte size of 6, then port then address. Ours is "
            + "carried in every Retry we send, so this is what i2pd reads back." );
    }

    /// <summary>IPv6 takes the same shape with a 16-byte address and a size of 18.</summary>
    [Test]
    public void AnIpV6AddressBlockKeepsTheSameLayout()
    {
        var address = IPAddress.Parse( "2001:db8::1" );

        var serialised = new AddressBlock
        {
            IPAddress = address.GetAddressBytes(),
            Port = ObservedPort
        }.Serialize();

        ClassicAssert.AreEqual( 3 + 18, serialised.Length );
        ClassicAssert.AreEqual( 18, ( serialised[1] << 8 ) | serialised[2] );
        ClassicAssert.AreEqual( 0x72, serialised[3], "port comes first for IPv6 too" );
        ClassicAssert.AreEqual( 0x4C, serialised[4] );

        var block = new AddressBlock();
        block.Parse( new I2PBufferCursor( serialised[3..] ) );

        ClassicAssert.AreEqual( ObservedPort, block.Port );
        ClassicAssert.AreEqual( address, new IPAddress( block.IPAddress ) );
    }

    /// <summary>
    ///     A payload that is neither 6 nor 18 bytes is malformed and must be refused rather than
    ///     read past — the guard the old code was trying to be, applied to the length it actually
    ///     has rather than to a field it invented.
    /// </summary>
    [Test]
    public void AMalformedAddressBlockIsRefused()
    {
        var block = new AddressBlock();

        Assert.Throws<System.Exception>(
            () => block.Parse( new I2PBufferCursor( new byte[] { 0x72, 0x4C, 0x7F } ) ),
            "a three-byte payload is not an address" );
    }
}
