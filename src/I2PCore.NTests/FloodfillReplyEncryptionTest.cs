using System;
using System.Linq;
using I2PCore;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;

namespace I2PTests;

/// <summary>
///     Batch 3-16 (docs/PRODUCTION-PLAN.md) — a floodfill must read the reply tag it was given and
///     answer under it.
/// </summary>
/// <remarks>
///     Two defects, one field group. i2pd's <c>CreateLeaseSetDatabaseLookupMsg</c> sets flags
///     <c>0x15</c> — delivery, LeaseSet lookup, ECIES — with the <c>0x02</c> encryption bit
///     <b>clear</b>, and then writes <c>replyKey(32) || numTags(1) || tag(8)</c> anyway. Our parser
///     gated the tag count on that clear bit, so the tag was never read; and
///     <c>FloodfillServer</c> then answered in the clear whatever it had been asked for.
///     <para>
///     The lookup here is built <b>byte by byte to i2pd's layout</b> rather than by our own writer.
///     A round trip through <c>DatabaseLookupMessage</c>'s own constructor passes against the
///     broken code — that is precisely what hid this — because that writer set both flags.
///     </para>
/// </remarks>
[TestFixture]
public class FloodfillReplyEncryptionTest
{
    // i2pd: DATABASE_LOOKUP_DELIVERY_FLAG | DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP |
    //       DATABASE_LOOKUP_ECIES_FLAG  ==  0x01 | 0x04 | 0x10
    private const byte I2pdLeaseSetLookupFlags = 0x15;

    private static readonly byte[] ReplyKey = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i)).ToArray();
    private static readonly byte[] ReplyTag = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

    /// <summary>
    ///     A LeaseSet lookup laid out exactly as i2pd's <c>CreateLeaseSetDatabaseLookupMsg</c> writes
    ///     it: key, reply tunnel gateway, flags, reply tunnel id, excluded count, then the key and
    ///     the single 8-byte tag.
    /// </summary>
    private static DatabaseLookupMessage I2pdStyleLeaseSetLookup(byte flags = I2pdLeaseSetLookupFlags)
    {
        var buf = new System.Buffers.ArrayBufferWriter<byte>();

        buf.WriteBytes(Enumerable.Repeat((byte)0x11, 32).ToArray()); // key looked up
        buf.WriteBytes(Enumerable.Repeat((byte)0x22, 32).ToArray()); // reply tunnel gateway
        buf.WriteByte(flags);
        buf.WriteUInt32BigEndian(0x33445566); // reply tunnel id
        buf.WriteUInt16BigEndian(0); // no excluded peers
        buf.WriteBytes(ReplyKey);
        buf.WriteByte(1); // exactly one tag, as i2pd always writes
        buf.WriteBytes(ReplyTag);

        return new DatabaseLookupMessage(new I2PBufferCursor(buf.WrittenSpan.ToArray()));
    }

    [Test]
    public void I2pdsLeaseSetLookupCarriesAReplyTagWeCanRead()
    {
        var lookup = I2pdStyleLeaseSetLookup();

        Assert.That((byte)lookup.LookupType & 0x02, Is.Zero,
            "i2pd does not set the encryption flag on a LeaseSet lookup — if it did, this test " +
            "would not be testing the defect.");

        Assert.That(lookup.ReplyKey, Is.Not.Null);
        Assert.That(lookup.ReplyKey.Key.ToByteArray(), Is.EqualTo(ReplyKey));

        // This is the assertion that was red: Tags was empty.
        Assert.That(lookup.Tags.Count, Is.EqualTo(1));
        Assert.That(lookup.Tags[0].Value.ToByteArray(), Is.EqualTo(ReplyTag));
    }

    [Test]
    public void TheTunnelIdAndExcludeListStillParseAroundTheKey()
    {
        var lookup = I2pdStyleLeaseSetLookup();

        Assert.That((uint)lookup.TunnelId, Is.EqualTo(0x33445566u));
        Assert.That(lookup.ExcludeList, Is.Empty);
        Assert.That(lookup.Key.Hash.ToByteArray(), Is.EqualTo(Enumerable.Repeat((byte)0x11, 32).ToArray()));
    }

    [Test]
    public void ALegacyAesLookupStillReadsItsThirtyTwoByteTags()
    {
        // Encryption flag set, ECIES clear: tags are 32 bytes each, as before this batch.
        var buf = new System.Buffers.ArrayBufferWriter<byte>();
        buf.WriteBytes(Enumerable.Repeat((byte)0x11, 32).ToArray());
        buf.WriteBytes(Enumerable.Repeat((byte)0x22, 32).ToArray());
        buf.WriteByte(0x01 | 0x02 | 0x04); // tunnel | encryption | leaseset
        buf.WriteUInt32BigEndian(7);
        buf.WriteUInt16BigEndian(0);
        buf.WriteBytes(ReplyKey);
        buf.WriteByte(1);
        buf.WriteBytes(Enumerable.Repeat((byte)0x5A, 32).ToArray());

        var lookup = new DatabaseLookupMessage(new I2PBufferCursor(buf.WrittenSpan.ToArray()));

        Assert.That(lookup.Tags.Count, Is.EqualTo(1));
        Assert.That(lookup.Tags[0].Value.Length, Is.EqualTo(32));
    }

    [Test]
    public void WhatWeWriteIsWhatWeRead()
    {
        // The writer used to emit the tag block only when the Encryption flag was set. It now
        // writes the group whenever there is a key, matching both reference implementations.
        var keyinfo = new DatabaseLookupKeyInfo
        {
            EncryptionFlag = false,
            EciesFlag = true,
            ReplyKey = new I2PByteBlock(ReplyKey),
            Tags = new[] { new I2PByteBlock(ReplyTag) }
        };

        var written = new DatabaseLookupMessage(
            new I2PIdentHash(new I2PBufferCursor(Enumerable.Repeat((byte)0x11, 32).ToArray())),
            new I2PIdentHash(new I2PBufferCursor(Enumerable.Repeat((byte)0x22, 32).ToArray())),
            new I2PTunnelId(9u),
            DatabaseLookupMessage.LookupTypes.LeaseSet,
            null,
            keyinfo);

        var reparsed = new DatabaseLookupMessage(new I2PBufferCursor(written.Payload.ToByteArray()));

        Assert.That(reparsed.ReplyKey.Key.ToByteArray(), Is.EqualTo(ReplyKey));
        Assert.That(reparsed.Tags.Count, Is.EqualTo(1));
        Assert.That(reparsed.Tags[0].Value.ToByteArray(), Is.EqualTo(ReplyTag));
    }

    /// <summary>
    ///     The reply is decrypted here the way i2pd decrypts it — take the leading 8 bytes as the
    ///     tag, use them as the AEAD associated data with a zero nonce and the requester's key —
    ///     rather than by handing it back to our own reader.
    /// </summary>
    [Test]
    public void AReplyToAnEciesLookupIsWrappedUnderTheTagTheRequesterChose()
    {
        var lookup = I2pdStyleLeaseSetLookup();
        var plain = new DeliveryStatusMessage(0x0BADF00D);

        var wrapped = FloodfillServer.WrapReplyForRequester(lookup, plain);

        Assert.That(wrapped, Is.Not.SameAs(plain), "The reply went out in the clear.");
        Assert.That(wrapped.MessageType, Is.EqualTo(I2NpMessage.MessageTypes.Garlic));

        // .Data strips the 4-byte I2NP garlic length prefix; what follows is tag(8) || ciphertext.
        var payload = ((GarlicMessage)wrapped).Data.ToByteArray();
        Assert.That(payload.Take(8).ToArray(), Is.EqualTo(ReplyTag),
            "The garlic must lead with the requester's own tag bytes, unaltered.");

        var plaintext = ChaCha20Poly1305.Decrypt(
            ReplyKey,
            new byte[12],
            payload.Skip(8).ToArray(),
            ReplyTag);

        var blocks = ECIESBlockFormat.ParseBlocks(plaintext);
        Assert.That(blocks.First(), Is.InstanceOf<GarlicCloveBlock>(),
            "A one-time tagset reads exactly one block and it must be the clove — batch 3-13.");

        // Clove: delivery instructions (1 byte, local) + I2NP type + msg id + expiry + payload
        var clove = ((GarlicCloveBlock)blocks.First()).Data;
        Assert.That(clove[0], Is.EqualTo(0), "Local delivery instructions");
        Assert.That(clove[1], Is.EqualTo((byte)I2NpMessage.MessageTypes.DeliveryStatus));
    }

    [Test]
    public void ALookupWithNoReplyKeyIsAnsweredInTheClear()
    {
        var lookup = I2pdStyleLeaseSetLookup(0x01 | 0x04); // tunnel | leaseset, no encryption at all
        var plain = new DeliveryStatusMessage(1);

        Assert.That(FloodfillServer.WrapReplyForRequester(lookup, plain), Is.SameAs(plain));
    }

    [Test]
    public void ALegacyAesReplyIsNotSilentlySentUnderADifferentEncryption()
    {
        // Encryption without ECIES is the ElGamal/AES form, which this router does not implement.
        // The honest outcome is a plaintext reply and a warning, not a ChaCha20 garlic the
        // requester holds no key for.
        var buf = new System.Buffers.ArrayBufferWriter<byte>();
        buf.WriteBytes(Enumerable.Repeat((byte)0x11, 32).ToArray());
        buf.WriteBytes(Enumerable.Repeat((byte)0x22, 32).ToArray());
        buf.WriteByte(0x01 | 0x02 | 0x04);
        buf.WriteUInt32BigEndian(7);
        buf.WriteUInt16BigEndian(0);
        buf.WriteBytes(ReplyKey);
        buf.WriteByte(1);
        buf.WriteBytes(Enumerable.Repeat((byte)0x5A, 32).ToArray());

        var lookup = new DatabaseLookupMessage(new I2PBufferCursor(buf.WrittenSpan.ToArray()));
        var plain = new DeliveryStatusMessage(1);

        Assert.That(FloodfillServer.WrapReplyForRequester(lookup, plain), Is.SameAs(plain));
    }

    [Test]
    public void TheGarlicTagIsTakenAsBytesAndNotThroughAnInteger()
    {
        // The byte[] overload exists so a floodfill echoes the request's bytes unchanged. Feeding
        // the same eight bytes through the ulong overload must land on the same wire tag, or one
        // of the two callers is byte-swapped.
        var asUlong = BufUtils.Flip64(BitConverter.ToUInt64(ReplyTag, 0));

        var viaBytes = I2PCore.TunnelLayer.TunnelProvider.CreateOneTimeGarlicMessage(
            new DeliveryStatusMessage(1), ReplyKey, ReplyTag);
        var viaUlong = I2PCore.TunnelLayer.TunnelProvider.CreateOneTimeGarlicMessage(
            new DeliveryStatusMessage(1), ReplyKey, asUlong);

        Assert.That(viaBytes.Data.ToByteArray().Take(8).ToArray(), Is.EqualTo(ReplyTag));
        Assert.That(viaUlong.Data.ToByteArray().Take(8).ToArray(), Is.EqualTo(ReplyTag));
    }
}
