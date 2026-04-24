using System;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using I2PCore.Utils;
using I2PCore.TransportLayer.Crypto;

namespace I2PTests
{
    /// <summary>
    /// NTCP2 cryptographic operation tests
    /// Tests the Noise XK handshake state machine components
    /// Per spec: https://geti2p.net/spec/ntcp2
    /// </summary>
    [TestFixture]
    public class NTCP2CryptoTest
    {
        /// <summary>
        /// Test NTCP2 Noise XK initialization for Alice (initiator)
        /// Per NTCP2 spec lines 260-277:
        /// h = SHA256(protocol_name)
        /// h = SHA256(h) // MixHash(null prologue)
        /// h = SHA256(h || Bob's_static_key) // MixHash(rs)
        /// </summary>
        [Test]
        public void TestNoiseXKInitializationAlice()
        {
            // Generate keys
            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var bobPriv = new byte[32];
            var bobPub = new byte[32];
            for (int i = 0; i < 32; i++) bobPub[i] = (byte)i;

            // Alice initializes knowing Bob's public key
            var aliceNoise = new NoiseXK(NoiseXK.PROTOCOL_NAME_NTCP2);
            aliceNoise.InitializeAsAlice(alicePriv, alicePub, bobPub);

            // Expected h calculation:
            // 1. h = SHA256(protocol_name) because it's > 32 bytes
            var h = new byte[32];
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                h = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(NoiseXK.PROTOCOL_NAME_NTCP2));
            }

            // 2. MixHash(empty prologue) -> h = SHA256(h)
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                h = sha256.ComputeHash(h);
            }

            // 3. MixHash(rs) -> h = SHA256(h || rs)
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var input = new byte[h.Length + bobPub.Length];
                Array.Copy(h, 0, input, 0, h.Length);
                Array.Copy(bobPub, 0, input, h.Length, bobPub.Length);
                h = sha256.ComputeHash(input);
            }

            var actualH = aliceNoise.GetHandshakeHash();
            Assert.IsTrue(BufUtils.Equal(h, actualH), 
                $"Handshake hash mismatch. Expected: {BitConverter.ToString(h)}, Actual: {BitConverter.ToString(actualH)}");
        }

        /// <summary>
        /// Test NTCP2 Noise XK initialization for Bob (responder)
        /// </summary>
        [Test]
        public void TestNoiseXKInitializationBob()
        {
            // Generate keys
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();

            // Bob initializes with his own keys
            var bobNoise = new NoiseXK(NoiseXK.PROTOCOL_NAME_NTCP2);
            bobNoise.InitializeAsBob(bobPriv, bobPub);

            // Expected h calculation:
            // 1. h = SHA256(protocol_name) because it's > 32 bytes
            var h = new byte[32];
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                h = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(NoiseXK.PROTOCOL_NAME_NTCP2));
            }

            // 2. MixHash(empty prologue) -> h = SHA256(h)
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                h = sha256.ComputeHash(h);
            }

            // 3. MixHash(rs) -> h = SHA256(h || rs)
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var input = new byte[h.Length + bobPub.Length];
                Array.Copy(h, 0, input, 0, h.Length);
                Array.Copy(bobPub, 0, input, h.Length, bobPub.Length);
                h = sha256.ComputeHash(input);
            }

            var actualH = bobNoise.GetHandshakeHash();
            Assert.IsTrue(BufUtils.Equal(h, actualH), 
                $"Handshake hash mismatch. Expected: {BitConverter.ToString(h)}, Actual: {BitConverter.ToString(actualH)}");
        }

        /// <summary>
        /// Test X25519 key pair generation
        /// Verifies keys are 32 bytes and different for each generation
        /// </summary>
        [Test]
        public void TestX25519KeyGeneration()
        {
            var (priv1, pub1) = X25519.GenerateKeyPair();
            var (priv2, pub2) = X25519.GenerateKeyPair();

            // Verify key sizes
            Assert.AreEqual(32, priv1.Length, "Private key should be 32 bytes");
            Assert.AreEqual(32, pub1.Length, "Public key should be 32 bytes");

            // Verify keys are different
            Assert.IsFalse(BufUtils.Equal(priv1, priv2), "Private keys should be unique");
            Assert.IsFalse(BufUtils.Equal(pub1, pub2), "Public keys should be unique");
        }

        /// <summary>
        /// Test X25519 Diffie-Hellman key agreement
        /// Verifies that both parties derive the same shared secret
        /// </summary>
        [Test]
        public void TestX25519DH()
        {
            var (alicePriv, alicePub) = X25519.GenerateKeyPair();
            var (bobPriv, bobPub) = X25519.GenerateKeyPair();

            // Alice computes shared secret with her private key and Bob's public key
            var aliceShared = X25519.ComputeSharedSecret(alicePriv, bobPub);

            // Bob computes shared secret with his private key and Alice's public key
            var bobShared = X25519.ComputeSharedSecret(bobPriv, alicePub);

            // Both should derive the same shared secret
            Assert.AreEqual(32, aliceShared.Length, "Shared secret should be 32 bytes");
            Assert.IsTrue(BufUtils.Equal(aliceShared, bobShared),
                "Both parties should derive the same shared secret");
        }

        /// <summary>
        /// Test NTCP2 Message 1 structure (SessionRequest)
        /// Per spec: X (32 bytes obfuscated) + options (16 bytes) + padding (0-31 bytes) + MAC (16 bytes)
        /// Total: 64-111 bytes
        /// </summary>
        [Test]
        public void TestSessionRequestStructure()
        {
            // Message 1 components
            var ephemeralKey = BufUtils.RandomBytes(32);      // Alice's ephemeral public key
            var options = BufUtils.RandomBytes(16);           // Encrypted options block
            var padding = BufUtils.RandomBytes(16);           // Random padding (0-31 bytes)
            var mac = BufUtils.RandomBytes(16);               // Poly1305 MAC

            // Construct Message 1
            var message1 = new byte[ephemeralKey.Length + options.Length + padding.Length + mac.Length];
            Array.Copy(ephemeralKey, 0, message1, 0, ephemeralKey.Length);
            Array.Copy(options, 0, message1, 32, options.Length);
            Array.Copy(padding, 0, message1, 48, padding.Length);
            Array.Copy(mac, 0, message1, 64, mac.Length);

            Assert.AreEqual(80, message1.Length, "Message 1 should be 80 bytes with 16-byte padding");
            Assert.IsTrue(message1.Length >= 64 && message1.Length <= 111,
                "Message 1 size should be 64-111 bytes");
        }

        /// <summary>
        /// Test NTCP2 Message 2 structure (SessionCreated)
        /// Per spec: Y (32 bytes obfuscated) + options (16 bytes) + padding (0-31 bytes) + MAC (16 bytes)
        /// Total: 64-111 bytes
        /// </summary>
        [Test]
        public void TestSessionCreatedStructure()
        {
            // Message 2 components (same structure as Message 1)
            var ephemeralKey = BufUtils.RandomBytes(32);      // Bob's ephemeral public key
            var options = BufUtils.RandomBytes(16);           // Encrypted options block
            var padding = BufUtils.RandomBytes(24);           // Random padding
            var mac = BufUtils.RandomBytes(16);               // Poly1305 MAC

            // Construct Message 2
            var message2 = new byte[ephemeralKey.Length + options.Length + padding.Length + mac.Length];
            Array.Copy(ephemeralKey, 0, message2, 0, ephemeralKey.Length);
            Array.Copy(options, 0, message2, 32, options.Length);
            Array.Copy(padding, 0, message2, 48, padding.Length);
            Array.Copy(mac, 0, message2, 72, mac.Length);

            Assert.AreEqual(88, message2.Length, "Message 2 should be 88 bytes with 24-byte padding");
            Assert.IsTrue(message2.Length >= 64 && message2.Length <= 111,
                "Message 2 size should be 64-111 bytes");
        }

        /// <summary>
        /// Test NTCP2 Message 3 structure (SessionConfirmed)
        /// Per spec: Part 1 (encrypted static key + MAC) + Part 2 (RouterInfo + padding + MAC)
        /// Part 1: 48 bytes fixed (32 + 16)
        /// Part 2: Variable (depends on RouterInfo size)
        /// </summary>
        [Test]
        public void TestSessionConfirmedStructure()
        {
            // Part 1: Alice's static key + MAC
            var staticKey = BufUtils.RandomBytes(32);
            var part1Mac = BufUtils.RandomBytes(16);
            var part1 = new byte[48];
            Array.Copy(staticKey, 0, part1, 0, 32);
            Array.Copy(part1Mac, 0, part1, 32, 16);

            Assert.AreEqual(48, part1.Length, "Message 3 Part 1 should be exactly 48 bytes");

            // Part 2: RouterInfo (variable) + padding + MAC
            var routerInfo = BufUtils.RandomBytes(500);       // Typical RouterInfo size
            var padding = BufUtils.RandomBytes(12);
            var part2Mac = BufUtils.RandomBytes(16);
            var part2 = new byte[routerInfo.Length + padding.Length + part2Mac.Length];
            Array.Copy(routerInfo, 0, part2, 0, routerInfo.Length);
            Array.Copy(padding, 0, part2, routerInfo.Length, padding.Length);
            Array.Copy(part2Mac, 0, part2, routerInfo.Length + padding.Length, part2Mac.Length);

            Assert.AreEqual(528, part2.Length);
            Assert.IsTrue(part2.Length >= 16, "Part 2 should be at least 16 bytes (MAC only)");

            // Total message
            var message3 = new byte[part1.Length + part2.Length];
            Array.Copy(part1, 0, message3, 0, part1.Length);
            Array.Copy(part2, 0, message3, part1.Length, part2.Length);

            Assert.AreEqual(576, message3.Length);
        }

        /// <summary>
        /// Test NTCP2 data phase frame structure
        /// Per spec: Length (2 bytes obfuscated) + Payload (variable) + MAC (16 bytes)
        /// </summary>
        [Test]
        public void TestDataFrameStructure()
        {
            var payloadSize = 1000;
            var payload = BufUtils.RandomBytes(payloadSize);
            var mac = BufUtils.RandomBytes(16);

            // In actual NTCP2, length is obfuscated with SipHash-2-4
            var lengthObfuscated = BufUtils.RandomBytes(2);

            // Construct data frame
            var frame = new byte[2 + payload.Length + mac.Length];
            Array.Copy(lengthObfuscated, 0, frame, 0, 2);
            Array.Copy(payload, 0, frame, 2, payload.Length);
            Array.Copy(mac, 0, frame, 2 + payload.Length, mac.Length);

            Assert.AreEqual(1018, frame.Length, "Frame should be 2 + payload + 16");
            Assert.IsTrue(frame.Length >= 18, "Minimum frame size is 18 bytes (empty payload)");
        }

        /// <summary>
        /// Test SHA256 hashing (used in Noise MixHash operations)
        /// </summary>
        [Test]
        public void TestSHA256()
        {
            var data = BufUtils.RandomBytes(100);
            var hash1 = System.Security.Cryptography.SHA256.HashData(data);
            var hash2 = System.Security.Cryptography.SHA256.HashData(data);

            Assert.AreEqual(32, hash1.Length, "SHA256 hash should be 32 bytes");
            Assert.IsTrue(BufUtils.Equal(hash1, hash2), "Same input should produce same hash");

            // Different input should produce different hash
            data[0] ^= 0xFF;
            var hash3 = System.Security.Cryptography.SHA256.HashData(data);
            Assert.IsFalse(BufUtils.Equal(hash1, hash3), "Different input should produce different hash");
        }

        /// <summary>
        /// Test nonce increment for data phase encryption
        /// ChaCha20-Poly1305 nonce must increment for each message
        /// </summary>
        [Test]
        public void TestNonceIncrement()
        {
            ulong nonce = 0;
            var nonce1 = ChaCha20Poly1305.CreateNonce(nonce++);
            var nonce2 = ChaCha20Poly1305.CreateNonce(nonce++);
            var nonce3 = ChaCha20Poly1305.CreateNonce(nonce++);

            Assert.AreEqual(12, nonce1.Length, "Nonce should be 12 bytes");
            Assert.IsFalse(BufUtils.Equal(nonce1, nonce2), "Nonces should be unique");
            Assert.IsFalse(BufUtils.Equal(nonce2, nonce3), "Nonces should be unique");

            // Verify nonce structure (4 zero bytes + 8-byte counter)
            Assert.AreEqual(0, nonce1[0]);
            Assert.AreEqual(0, nonce1[1]);
            Assert.AreEqual(0, nonce1[2]);
            Assert.AreEqual(0, nonce1[3]);

            // Verify counter is little-endian
            Assert.AreEqual(0, nonce1[4]);  // Counter 0
            Assert.AreEqual(1, nonce2[4]);  // Counter 1
            Assert.AreEqual(2, nonce3[4]);  // Counter 2
        }
    }
}
