using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using I2PCore.Data;
using I2PCore.Utils;
using System;

namespace I2PTests
{
    [TestFixture]
    public class BlindingTest
    {
        /// <summary>
        /// Test that blinding an Ed25519 public key produces a valid 32-byte blinded key
        /// and that the same inputs always produce the same output (deterministic).
        /// </summary>
        [Test]
        public void TestBlindedKeyDeterministic()
        {
            var cert = new I2PCertificate( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );
            var keys = I2PPrivateKey.GetNewKeyPair();
            var privskey = new I2PSigningPrivateKey( cert );

            var dest = new I2PDestination(
                keys.PublicKey,
                new I2PSigningPublicKey( privskey ) );

            var blinded = new BlindedPublicKey( dest );

            Assert.IsTrue( blinded.IsValid, "BlindedPublicKey should be valid for EdDSA" );
            Assert.AreEqual(
                I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519,
                blinded.SigType );
            Assert.AreEqual(
                I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519,
                blinded.BlindedSigType,
                "EdDSA should blind to RedDSA" );

            var date = "20260410";
            var key1 = blinded.GetBlindedKey( date );
            var key2 = blinded.GetBlindedKey( date );

            Assert.IsNotNull( key1, "Blinded key should not be null" );
            Assert.AreEqual( 32, key1.Length, "Ed25519 blinded key should be 32 bytes" );
            Assert.IsTrue( BufUtils.Equal( key1, key2 ),
                "Same date should produce same blinded key (deterministic)" );
        }

        /// <summary>
        /// Test that different dates produce different blinded keys.
        /// </summary>
        [Test]
        public void TestBlindedKeyVariesByDate()
        {
            var cert = new I2PCertificate( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );
            var keys = I2PPrivateKey.GetNewKeyPair();
            var privskey = new I2PSigningPrivateKey( cert );

            var dest = new I2PDestination(
                keys.PublicKey,
                new I2PSigningPublicKey( privskey ) );

            var blinded = new BlindedPublicKey( dest );

            var key1 = blinded.GetBlindedKey( "20260410" );
            var key2 = blinded.GetBlindedKey( "20260411" );

            Assert.IsNotNull( key1 );
            Assert.IsNotNull( key2 );
            Assert.IsFalse( BufUtils.Equal( key1, key2 ),
                "Different dates should produce different blinded keys" );
        }

        /// <summary>
        /// Test subcredential derivation: credential and subcredential should be 32 bytes each.
        /// </summary>
        [Test]
        public void TestSubcredentialDerivation()
        {
            var cert = new I2PCertificate( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );
            var keys = I2PPrivateKey.GetNewKeyPair();
            var privskey = new I2PSigningPrivateKey( cert );

            var dest = new I2PDestination(
                keys.PublicKey,
                new I2PSigningPublicKey( privskey ) );

            var blinded = new BlindedPublicKey( dest );
            var date = "20260410";
            var blindedKey = blinded.GetBlindedKey( date );

            var subcred = blinded.GetSubcredential( blindedKey );

            Assert.IsNotNull( subcred, "Subcredential should not be null" );
            Assert.AreEqual( 32, subcred.Length, "Subcredential should be 32 bytes (SHA-256)" );

            // Same inputs should give same subcredential
            var subcred2 = blinded.GetSubcredential( blindedKey );
            Assert.IsTrue( BufUtils.Equal( subcred, subcred2 ),
                "Subcredential should be deterministic" );
        }

        /// <summary>
        /// Test store hash computation. The store hash is used to look up
        /// encrypted LS2 entries in the NetDb.
        /// </summary>
        [Test]
        public void TestStoreHash()
        {
            var cert = new I2PCertificate( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );
            var keys = I2PPrivateKey.GetNewKeyPair();
            var privskey = new I2PSigningPrivateKey( cert );

            var dest = new I2PDestination(
                keys.PublicKey,
                new I2PSigningPublicKey( privskey ) );

            var blinded = new BlindedPublicKey( dest );

            var hash1 = blinded.GetStoreHash( "20260410" );
            var hash2 = blinded.GetStoreHash( "20260410" );
            var hash3 = blinded.GetStoreHash( "20260411" );

            Assert.IsNotNull( hash1 );
            Assert.IsFalse( hash1.Equals( I2PIdentHash.Zero ), "Store hash should not be zero" );
            Assert.IsTrue( hash1.Equals( hash2 ), "Same date should give same store hash" );
            Assert.IsFalse( hash1.Equals( hash3 ), "Different dates should give different store hashes" );
        }

        /// <summary>
        /// Test b33 encoding and decoding round-trip.
        /// </summary>
        [Test]
        public void TestB33RoundTrip()
        {
            var cert = new I2PCertificate( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );
            var keys = I2PPrivateKey.GetNewKeyPair();
            var privskey = new I2PSigningPrivateKey( cert );

            var dest = new I2PDestination(
                keys.PublicKey,
                new I2PSigningPublicKey( privskey ) );

            var original = new BlindedPublicKey( dest );
            var b33 = original.ToB33();

            Assert.IsNotNull( b33, "b33 string should not be null" );
            Assert.IsTrue( b33.Length > 0, "b33 string should not be empty" );

            var decoded = new BlindedPublicKey( b33 );

            Assert.IsTrue( decoded.IsValid, "Decoded BlindedPublicKey should be valid" );
            Assert.AreEqual( original.SigType, decoded.SigType, "SigType should match" );
            Assert.AreEqual( original.BlindedSigType, decoded.BlindedSigType, "BlindedSigType should match" );

            // Both should produce the same blinded key for the same date
            var date = "20260410";
            var key1 = original.GetBlindedKey( date );
            var key2 = decoded.GetBlindedKey( date );
            Assert.IsTrue( BufUtils.Equal( key1, key2 ),
                "Original and decoded should produce same blinded key" );
        }

        /// <summary>
        /// Test private key blinding: blinded private key should produce the
        /// same blinded public key as public key blinding.
        /// </summary>
        [Test]
        public void TestPrivateKeyBlindingConsistency()
        {
            var cert = new I2PCertificate( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );
            var keys = I2PPrivateKey.GetNewKeyPair();
            var privskey = new I2PSigningPrivateKey( cert );
            var pubskey = new I2PSigningPublicKey( privskey );

            var dest = new I2PDestination( keys.PublicKey, pubskey );

            var blinding = new BlindedPublicKey( dest );
            var date = "20260410";

            // Blind the public key
            var blindedPub = blinding.GetBlindedKey( date );

            // Blind the private key
            var (blindedPriv, blindedPubFromPriv) = blinding.BlindPrivateKey(
                privskey.Key.ToByteArray(), date );

            Assert.IsNotNull( blindedPriv, "Blinded private key should not be null" );
            Assert.IsNotNull( blindedPubFromPriv, "Blinded public key from private should not be null" );
            Assert.AreEqual( 32, blindedPriv.Length, "Blinded private key should be 32 bytes" );
            Assert.AreEqual( 32, blindedPubFromPriv.Length, "Blinded public key should be 32 bytes" );

            // The blinded public key from private key blinding should match
            // the blinded public key from public key blinding
            Assert.IsTrue( BufUtils.Equal( blindedPub, blindedPubFromPriv ),
                "Public key blinding and private key blinding must produce matching public keys" );
        }

        /// <summary>
        /// Test that ECDSA P-256 blinding works (produces valid output).
        /// </summary>
        [Test]
        public void TestEcdsaP256Blinding()
        {
            var cert = new I2PCertificate( I2PSigningKey.SigningKeyTypes.EcdsaSha256P256 );
            var keys = I2PPrivateKey.GetNewKeyPair();
            var privskey = new I2PSigningPrivateKey( cert );

            var dest = new I2PDestination(
                keys.PublicKey,
                new I2PSigningPublicKey( privskey ) );

            var blinded = new BlindedPublicKey( dest );

            Assert.IsTrue( blinded.IsValid );
            Assert.AreEqual(
                I2PSigningKey.SigningKeyTypes.EcdsaSha256P256,
                blinded.BlindedSigType,
                "ECDSA should keep same blinded type" );

            var key = blinded.GetBlindedKey( "20260410" );
            Assert.IsNotNull( key, "ECDSA blinded key should not be null" );
            // P-256 public key is 65 bytes (uncompressed x,y)
            Assert.AreEqual( 65, key.Length, "P-256 blinded key should be 65 bytes" );
        }
    }
}
