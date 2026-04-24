using System;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using I2PCore.TransportLayer.NTCP2;
using I2PCore.Utils;

namespace I2PTests
{
    /// <summary>
    /// NTCP2 Noise XK handshake and data frame tests.
    /// Verifies the cryptographic handshake at the Noise protocol level
    /// to ensure 1-to-1 compatibility with i2pd.
    ///
    /// i2pd uses: InitNoiseXKState() with pre-computed SHA256 of
    /// "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
    /// </summary>
    [TestFixture]
    public class NTCP2HandshakeTest
    {
        private const string NTCP2_PROTOCOL = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

        [SetUp]
        public void Setup()
        {
            Logging.LogToDebug = true;
        }

        /// <summary>
        /// Run a complete 3-message Noise XK handshake between Alice and Bob.
        /// Returns the two NoiseXK instances in post-handshake state (ready for data).
        /// </summary>
        private static (NoiseXK alice, NoiseXK bob) CompleteHandshake(
            byte[] alicePriv, byte[] alicePub,
            byte[] bobPriv, byte[] bobPub )
        {
            var alice = new NoiseXK( NTCP2_PROTOCOL );
            alice.InitializeAsAlice( alicePriv, alicePub, bobPub );

            var bob = new NoiseXK( NTCP2_PROTOCOL );
            bob.InitializeAsBob( bobPriv, bobPub );

            // Message 1: Alice -> Bob (e, es)
            var (aliceEph, msg1Enc) = alice.CreateMessage1( new byte[16] );
            var msg1Dec = bob.ProcessMessage1( aliceEph, msg1Enc );
            if ( msg1Dec == null ) throw new Exception( "Message 1 decryption failed" );

            // Message 2: Bob -> Alice (e, ee)
            var (bobEph, msg2Enc) = bob.CreateMessage2( new byte[16] );
            var msg2Dec = alice.ProcessMessage2( bobEph, msg2Enc );
            if ( msg2Dec == null ) throw new Exception( "Message 2 decryption failed" );

            // Message 3 Part 1: Alice -> Bob (s, se) - encrypted static key
            var msg3Part1 = alice.CreateMessage3Part1();
            var recoveredPub = bob.ProcessMessage3Part1( msg3Part1 );
            if ( recoveredPub == null ) throw new Exception( "Message 3 Part 1 failed" );

            // Message 3 Part 2: encrypted payload
            var msg3Part2 = alice.CreateMessage3Part2( new byte[32] );
            var msg3Dec = bob.ProcessMessage3Part2( msg3Part2 );
            Assert.IsNotNull( msg3Dec, "Message 3 Part 2 failed" );

            return (alice, bob);
        }

        [Test]
        public void TestNTCP2BobM3P2LenEcho()
        {
            // Simulate Bob receiving a SessionRequest with specific m3p2len
            var bob = new NoiseXK(NTCP2_PROTOCOL);
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();
            bob.InitializeAsBob(bobPriv, bobPub);

            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var alice = new NoiseXK(NTCP2_PROTOCOL);
            alice.InitializeAsAlice(alicePriv, alicePub, bobPub);

            // Alice creates Message 1 with m3p2len = 1234
            // Options: networkId(1), version(1), padLen(2), m3p2len(2), reserved(2), tsA(4), reserved(4)
            var options = new byte[16];
            options[0] = 2; // networkId
            options[1] = 2; // version
            options[4] = 0x04; // m3p2len = 1234 (0x04D2)
            options[5] = 0xD2;
            
            var (aliceEph, msg1Enc) = alice.CreateMessage1(options);
            var msg1Dec = bob.ProcessMessage1(aliceEph, msg1Enc);
            
            Assert.IsNotNull(msg1Dec);
            var reader = new BufRef(msg1Dec);
            reader.Read8(); // networkId
            reader.Read8(); // version
            reader.ReadFlip16(); // padLen
            var m3p2len = reader.ReadFlip16();
            Assert.AreEqual(1234, m3p2len);
            
            // Verify that Bob's ProcessMessage1 correctly identifies the fields
        }

        [Test]
        public void TestNTCP2SessionCreatedOptionsFormat()
        {
            // Simulate Bob sending SessionCreated options
            // Spec lines 617-621: 2B Rsvd, 2B padLen, 4B Reserved, 4B tsB, 4B Reserved
            var bob = new NoiseXK(NTCP2_PROTOCOL);
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();
            bob.InitializeAsBob(bobPriv, bobPub);

            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var alice = new NoiseXK(NTCP2_PROTOCOL);
            alice.InitializeAsAlice(alicePriv, alicePub, bobPub);

            // Alice -> Bob: Message 1
            var (aliceEph, msg1Enc) = alice.CreateMessage1(new byte[16]);
            bob.ProcessMessage1(aliceEph, msg1Enc);

            // Bob -> Alice: Message 2
            // We use a mock session or just the logic from NTCP2Session.BuildSessionCreatedPayload
            // Since we want to test the format, we can't easily use NTCP2Session without more setup.
            // But we can test if Alice's ProcessMessage2 can parse it if it follows the spec.

            var payload = new byte[16];
            var writer = new BufRefLen(payload);
            writer.WriteFlip16(0); // Rsvd
            writer.WriteFlip16(64); // padLen
            writer.WriteFlip32(0); // Reserved
            uint tsB = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            writer.WriteFlip32(tsB); // tsB
            writer.WriteFlip32(0); // Reserved

            var (bobEph, msg2Enc) = bob.CreateMessage2(payload);
            var msg2Dec = alice.ProcessMessage2(bobEph, msg2Enc);

            Assert.IsNotNull(msg2Dec);
            Assert.AreEqual(16, msg2Dec.Length);

            var reader = new BufRefLen(msg2Dec);
            Assert.AreEqual(0, reader.ReadFlip16()); // Rsvd
            Assert.AreEqual(64, reader.ReadFlip16()); // padLen
            Assert.AreEqual(0, reader.ReadFlip32()); // Reserved
            Assert.AreEqual(tsB, reader.ReadFlip32()); // tsB
            Assert.AreEqual(0, reader.ReadFlip32()); // Reserved
        }

        [Test]
        public void TestNTCP2Message2LenientValidation()
        {
            // Simulate Bob sending Message 2 with random junk in Reserved fields
            var bob = new NoiseXK(NTCP2_PROTOCOL);
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();
            bob.InitializeAsBob(bobPriv, bobPub);

            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var alice = new NoiseXK(NTCP2_PROTOCOL);
            alice.InitializeAsAlice(alicePriv, alicePub, bobPub);

            // Alice -> Bob: Message 1
            var (aliceEph, msg1Enc) = alice.CreateMessage1(new byte[16]);
            bob.ProcessMessage1(aliceEph, msg1Enc);

            // Bob -> Alice: Message 2 with junk in bytes 0-1 and 4-7
            var options2 = new byte[16]; 
            options2[0] = 0xFF; // Junk
            options2[1] = 0xEE; // Junk
            options2[2] = 0x00; // padLen hi
            options2[3] = 0x10; // padLen lo (16 bytes)
            options2[4] = 0xDD; // Junk
            
            uint tsB = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            options2[8] = (byte)(tsB >> 24);
            options2[9] = (byte)(tsB >> 16);
            options2[10] = (byte)(tsB >> 8);
            options2[11] = (byte)tsB;
            
            var (bobEph, msg2Enc) = bob.CreateMessage2(options2);
            var msg2Dec = alice.ProcessMessage2(bobEph, msg2Enc);

            Assert.IsNotNull(msg2Dec, "Alice should decrypt Message 2 even with junk in reserved fields");
            
            var reader = new BufRef(msg2Dec);
            Assert.AreEqual(0xFF, reader.Read8());
            Assert.AreEqual(0xEE, reader.Read8());
            Assert.AreEqual(16, reader.ReadFlip16()); // padLen
            
            // This test verifies that the low-level crypto works.
            // NTCP2Session was updated to treat these fields as Reserved and ignore them.
        }

        /// <summary>
        /// Test the full 3-message Noise XK handshake.
        /// Per i2pd NTCP2.cpp: InitNoiseXKState, KDF1-3, SessionRequest/Created/Confirmed
        /// </summary>
        [Test]
        public void TestNTCP2BasicHandshake()
        {
            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();

            var alice = new NoiseXK( NTCP2_PROTOCOL );
            alice.InitializeAsAlice( alicePriv, alicePub, bobPub );

            var bob = new NoiseXK( NTCP2_PROTOCOL );
            bob.InitializeAsBob( bobPriv, bobPub );

            // Message 1: Alice -> Bob
            var msg1Payload = BufUtils.RandomBytes( 16 );
            var (aliceEph, msg1Enc) = alice.CreateMessage1( msg1Payload );
            Assert.IsNotNull( aliceEph, "Ephemeral key should not be null" );
            Assert.AreEqual( 32, aliceEph.Length );

            var msg1Dec = bob.ProcessMessage1( aliceEph, msg1Enc );
            Assert.IsNotNull( msg1Dec, "Bob should decrypt Message 1" );
            Assert.IsTrue( BufUtils.Equal( msg1Payload, msg1Dec ) );

            // Message 2: Bob -> Alice
            var msg2Payload = BufUtils.RandomBytes( 16 );
            var (bobEph, msg2Enc) = bob.CreateMessage2( msg2Payload );
            Assert.IsNotNull( bobEph );

            var msg2Dec = alice.ProcessMessage2( bobEph, msg2Enc );
            Assert.IsNotNull( msg2Dec, "Alice should decrypt Message 2" );
            Assert.IsTrue( BufUtils.Equal( msg2Payload, msg2Dec ) );

            // Message 3 Part 1: encrypted Alice static key
            var msg3Part1 = alice.CreateMessage3Part1();
            Assert.IsNotNull( msg3Part1 );
            Assert.AreEqual( 48, msg3Part1.Length, "32-byte key + 16-byte AEAD tag" );

            var recoveredPub = bob.ProcessMessage3Part1( msg3Part1 );
            Assert.IsNotNull( recoveredPub, "Bob should recover Alice's static key" );
            Assert.IsTrue( BufUtils.Equal( alicePub, recoveredPub ),
                "Recovered key must match Alice's actual static key" );

            // Message 3 Part 2: encrypted payload
            var msg3Payload = BufUtils.RandomBytes( 32 );
            var msg3Part2 = alice.CreateMessage3Part2( msg3Payload );
            Assert.IsNotNull( msg3Part2 );

            var msg3Dec = bob.ProcessMessage3Part2( msg3Part2 );
            Assert.IsNotNull( msg3Dec );
            Assert.IsTrue( BufUtils.Equal( msg3Payload, msg3Dec ) );

            Logging.LogInformation( "NTCP2 Noise XK handshake test passed" );
        }

        /// <summary>
        /// Test data frame encryption after handshake (Alice -> Bob).
        /// Data frames use ChaCha20-Poly1305 with incrementing nonces per i2pd spec.
        /// </summary>
        [Test]
        public void TestNTCP2DataTransmission()
        {
            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();

            var (alice, bob) = CompleteHandshake( alicePriv, alicePub, bobPriv, bobPub );

            // Alice encrypts data for Bob
            var plaintext = BufUtils.RandomBytes( 1500 );
            var ciphertext = alice.EncryptData( plaintext );
            Assert.IsNotNull( ciphertext );
            Assert.AreEqual( plaintext.Length + 16, ciphertext.Length,
                "Ciphertext = plaintext + 16-byte AEAD tag" );

            var decrypted = bob.DecryptData( ciphertext );
            Assert.IsNotNull( decrypted, "Bob should decrypt data" );
            Assert.IsTrue( BufUtils.Equal( plaintext, decrypted ),
                "Decrypted data must match original" );
        }

        /// <summary>
        /// Test bidirectional data frames.
        /// Both Alice and Bob derive separate send/receive keys from the handshake.
        /// </summary>
        [Test]
        public void TestNTCP2BidirectionalTransmission()
        {
            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();

            var (alice, bob) = CompleteHandshake( alicePriv, alicePub, bobPriv, bobPub );

            // Alice -> Bob
            var aliceData = BufUtils.RandomBytes( 1000 );
            var aliceCt = alice.EncryptData( aliceData );
            var alicePt = bob.DecryptData( aliceCt );
            Assert.IsTrue( BufUtils.Equal( aliceData, alicePt ), "Alice->Bob data mismatch" );

            // Bob -> Alice
            var bobData = BufUtils.RandomBytes( 2000 );
            var bobCt = bob.EncryptData( bobData );
            var bobPt = alice.DecryptData( bobCt );
            Assert.IsTrue( BufUtils.Equal( bobData, bobPt ), "Bob->Alice data mismatch" );
        }

        /// <summary>
        /// Test multiple sequential messages to verify nonce incrementing.
        /// Per NTCP2 spec: each frame uses nonce++ for ChaCha20-Poly1305.
        /// Wrong nonce = decryption failure. This catches nonce management bugs.
        /// </summary>
        [Test]
        public void TestNTCP2MultipleMessages()
        {
            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();

            var (alice, bob) = CompleteHandshake( alicePriv, alicePub, bobPriv, bobPub );

            for ( int i = 0; i < 10; i++ )
            {
                var data = BufUtils.RandomBytes( 100 + i * 100 );
                var ct = alice.EncryptData( data );
                Assert.IsNotNull( ct, $"EncryptData failed for message {i}" );

                var pt = bob.DecryptData( ct );
                Assert.IsNotNull( pt, $"DecryptData failed for message {i}" );
                Assert.IsTrue( BufUtils.Equal( data, pt ), $"Data mismatch at message {i}" );
            }

            Logging.LogInformation( "NTCP2 multiple messages (10x nonce increment) test passed" );
        }

        [Test]
        public void TestNTCP2BlockTypeValues()
        {
            Assert.AreEqual(0, (byte)NTCP2BlockType.DateTime);
            Assert.AreEqual(1, (byte)NTCP2BlockType.Options);
            Assert.AreEqual(2, (byte)NTCP2BlockType.RouterInfo);
            Assert.AreEqual(3, (byte)NTCP2BlockType.I2NP);
            Assert.AreEqual(4, (byte)NTCP2BlockType.Termination);
            Assert.AreEqual(254, (byte)NTCP2BlockType.Padding);
        }

        [Test]
        public void TestNTCP2OptionsBlockSerialization()
        {
            var options = new NTCP2OptionsBlock
            {
                TMin = 0x12,
                TMax = 0x34,
                RMin = 0x56,
                RMax = 0x78,
                TDummy = 1000,
                RDummy = 2000,
                TDelay = 100,
                RDelay = 200
            };

            var serialized = options.Serialize();
            Assert.AreEqual(12, serialized.Length);

            var parsed = new NTCP2OptionsBlock();
            parsed.Parse(new BufRefLen(serialized));

            Assert.AreEqual(0x12, parsed.TMin);
            Assert.AreEqual(0x34, parsed.TMax);
            Assert.AreEqual(0x56, parsed.RMin);
            Assert.AreEqual(0x78, parsed.RMax);
            Assert.AreEqual(1000, parsed.TDummy);
            Assert.AreEqual(2000, parsed.RDummy);
            Assert.AreEqual(100, parsed.TDelay);
            Assert.AreEqual(200, parsed.RDelay);
        }

        [Test]
        public void TestNTCP2TerminationBlockSerialization()
        {
            var term = new NTCP2TerminationBlock
            {
                Reason = NTCP2TerminationReason.ClockSkew,
                ValidPacketsReceived = 12345678,
                AdditionalData = new byte[] { 1, 2, 3, 4 }
            };

            var serialized = term.Serialize();
            Assert.AreEqual(9 + 4, serialized.Length);
            Assert.AreEqual((byte)NTCP2TerminationReason.ClockSkew, serialized[8]);

            var parsed = new NTCP2TerminationBlock();
            parsed.Parse(new BufRefLen(serialized));

            Assert.AreEqual(NTCP2TerminationReason.ClockSkew, parsed.Reason);
            Assert.AreEqual(12345678, parsed.ValidPacketsReceived);
            Assert.IsNotNull(parsed.AdditionalData);
            Assert.AreEqual(4, parsed.AdditionalData.Length);
            Assert.AreEqual(1, parsed.AdditionalData[0]);
        }
    }
}
