using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using NUnit.Framework;

namespace I2PTests;

[TestFixture]
public class I2NPEndiannessTest
{
    [Test]
    public void TestI2NPHeaderEndianness()
    {
        var msg = new DeliveryStatusMessage();
        msg.MessageId = 0x12345678;

        var header = msg.CreateHeader16;
        var bytes = header.HeaderAndPayload.ToByteArray();

        // Header format: Type(1), MsgID(4), Expiration(8), Size(2), Checksum(1)
        // Big Endian check for MsgID at offset 1
        Assert.That(bytes[1], Is.EqualTo(0x12));
        Assert.That(bytes[2], Is.EqualTo(0x34));
        Assert.That(bytes[3], Is.EqualTo(0x56));
        Assert.That(bytes[4], Is.EqualTo(0x78));
    }

    [Test]
    public void TestDeliveryStatusEndianness()
    {
        var msg = new DeliveryStatusMessage();
        msg.StatusMessageId = 0x87654321;

        var bytes = msg.Payload.ToByteArray();

        // Payload format: StatusMsgID(4), Timestamp(8)
        // Big Endian check for StatusMsgID at offset 0
        Assert.That(bytes[0], Is.EqualTo(0x87));
        Assert.That(bytes[1], Is.EqualTo(0x65));
        Assert.That(bytes[2], Is.EqualTo(0x43));
        Assert.That(bytes[3], Is.EqualTo(0x21));
    }

    [Test]
    public void TestTunnelDataEndianness()
    {
        var tunnelId = new I2PTunnelId(0xAABBCCDD);
        var msg = new TunnelDataMessage(tunnelId);

        var bytes = msg.Payload.ToByteArray();

        // Payload format: TunnelID(4), IV(16), ...
        // Big Endian check for TunnelID at offset 0
        Assert.That(bytes[0], Is.EqualTo(0xAA));
        Assert.That(bytes[1], Is.EqualTo(0xBB));
        Assert.That(bytes[2], Is.EqualTo(0xCC));
        Assert.That(bytes[3], Is.EqualTo(0xDD));
    }
}