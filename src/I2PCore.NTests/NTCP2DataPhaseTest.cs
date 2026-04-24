using System;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using I2PCore.TransportLayer.NTCP2;
using I2PCore.TransportLayer.Crypto;
using I2PCore.Utils;
using I2PCore.Data;

using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PTests
{
    [TestFixture]
    public class NTCP2DataPhaseTest
    {
        private const string NTCP2_PROTOCOL = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

        [Test]
        public void TestNTCP2I2NPBlockFormatting()
        {
            // Create a dummy I2NP message
            var msg = new DeliveryStatusMessage(0x11223344);
            msg.MessageId = 0x12345678;
            msg.Expiration = new I2PDate(DateTime.UtcNow.AddMinutes(10));

            // Build NTCP2 frame (first frame includes DateTime)
            var frame = NTCP2DataFrame.BuildWithI2NPMessage(msg, true);
            
            // Check that we have 2 blocks (DateTime and I2NP)
            Assert.AreEqual(2, frame.Blocks.Count);
            Assert.AreEqual(NTCP2BlockType.DateTime, frame.Blocks[0].BlockType);
            Assert.AreEqual(NTCP2BlockType.I2NP, frame.Blocks[1].BlockType);
            
            // The data should have the 9-byte header: Type(1), MsgID(4), Expiration(4)
            var blockData = frame.Blocks[1].Data;
            Assert.AreEqual((byte)msg.MessageType, blockData[0]);
            
            var reader = new BufRefLen(blockData);
            reader.Read8(); // Skip Type
            Assert.AreEqual(msg.MessageId, reader.ReadFlip32());
            Assert.AreEqual((uint)((ulong)msg.Expiration / 1000), reader.ReadFlip32());

            // Parse it back
            var parsedHeader = frame.Blocks[1].ParseAsI2NPHeader();
            Assert.IsNotNull(parsedHeader);
            Assert.AreEqual(msg.MessageType, parsedHeader.MessageType);
            Assert.AreEqual(msg.MessageId, ((Ii2NpHeader16)parsedHeader).MessageId);
            
            // Expiration might lose precision because it's converted to seconds
            var originalSeconds = (ulong)msg.Expiration / 1000;
            var parsedSeconds = (ulong)parsedHeader.Expiration / 1000;
            Assert.AreEqual(originalSeconds, parsedSeconds);
        }

        [Test]
        public void TestNTCP2DataFrameParse()
        {
            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();

            var alice = new NoiseXK(NTCP2_PROTOCOL);
            alice.InitializeAsAlice(alicePriv, alicePub, bobPub);

            var bob = new NoiseXK(NTCP2_PROTOCOL);
            bob.InitializeAsBob(bobPriv, bobPub);

            // Complete handshake to get to data phase
            var (aliceEph, msg1Enc) = alice.CreateMessage1(new byte[0]);
            bob.ProcessMessage1(aliceEph, msg1Enc);

            var (bobEph, msg2Enc) = bob.CreateMessage2(new byte[0]);
            alice.ProcessMessage2(bobEph, msg2Enc);

            var msg3p1 = alice.CreateMessage3Part1();
            bob.ProcessMessage3Part1(msg3p1);

            var msg3p2 = alice.CreateMessage3Part2(new byte[0]);
            bob.ProcessMessage3Part2(msg3p2);

            // Now in data phase. Split keys.
            alice.Split(true);
            bob.Split(false);

            // Alice sends a data frame to Bob
            var frame = new NTCP2DataFrame();
            frame.Blocks.Add(new NTCP2BlockWrapper
            {
                BlockType = NTCP2BlockType.DateTime,
                Data = new byte[4]
            });
            
            // SipHash keys for Alice (send) and Bob (receive)
            var sipKeys = new byte[32];
            for (int i = 0; i < 32; i++) sipKeys[i] = (byte)i;
            
            var aliceSip = new NTCP2SipHash(sipKeys);
            var bobSip = new NTCP2SipHash(sipKeys);

            var encryptedFrame = frame.BuildEncryptedFrame(alice, aliceSip);

            // Bob receives encryptedFrame
            // First 2 bytes are obfuscated length
            var reader = new BufRef(encryptedFrame);
            var obfuscatedLength = reader.ReadFlip16();
            
            var frameLength = bobSip.DeobfuscateLength(obfuscatedLength);
            Assert.AreEqual(encryptedFrame.Length - 2, (int)frameLength);

            var framePayload = reader.ReadBufRef(frameLength);
            
            // This is what failed before:
            var parsedFrame = NTCP2DataFrame.Parse(framePayload, bob, frameLength);
            
            Assert.IsNotNull(parsedFrame);
            Assert.AreEqual(frameLength, (ushort)parsedFrame.Length);
            Assert.AreEqual(1, parsedFrame.Blocks.Count);
            Assert.AreEqual(NTCP2BlockType.DateTime, parsedFrame.Blocks[0].BlockType);
        }

        [Test]
        public void TestNTCP2RouterInfoBlock()
        {
            // Use existing router info for testing
            var riPath = "/home/user/.config/I2Pz/debug/our_routerinfo.dat";
            if (!System.IO.File.Exists(riPath)) 
            {
                Assert.Ignore("our_routerinfo.dat not found");
                return;
            }

            var riBytes = System.IO.File.ReadAllBytes(riPath);
            var ri = new I2PRouterInfo(new BufRefLen(riBytes), false);
            
            var frame = NTCP2DataFrame.BuildWithRouterInfo(ri, true);
            
            Assert.AreEqual(2, frame.Blocks.Count);
            Assert.AreEqual(NTCP2BlockType.DateTime, frame.Blocks[0].BlockType);
            Assert.AreEqual(NTCP2BlockType.RouterInfo, frame.Blocks[1].BlockType);
            
            // Flags should be first byte of data
            Assert.AreEqual(0, frame.Blocks[1].Data[0]);
        }
    }
}
