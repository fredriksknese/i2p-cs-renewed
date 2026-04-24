using System;
using System.Linq;
using System.Text;
using I2PCore.Crypto;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;
using I2PCore.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PTests
{
    [TestFixture]
    public class CryptoExtensionsTest
    {
        /// <summary>
        /// Test HKDF key derivation produces correct length output and is deterministic.
        /// </summary>
        [Test]
        public void TestHKDFDeterministic()
        {
            var salt = BufUtils.RandomBytes( 32 );
            var ikm = BufUtils.RandomBytes( 64 );
            var info = Encoding.ASCII.GetBytes( "test-info" );

            var output1 = HKDF.DeriveKey( salt, ikm, info, 44 );
            var output2 = HKDF.DeriveKey( salt, ikm, info, 44 );

            Assert.IsNotNull( output1 );
            Assert.AreEqual( 44, output1.Length, "Output length should match requested" );
            Assert.IsTrue( BufUtils.Equal( output1, output2 ),
                "Same inputs should produce same output" );
        }

        /// <summary>
        /// Test HKDF with null salt uses zero salt (per RFC 5869).
        /// </summary>
        [Test]
        public void TestHKDFNullSalt()
        {
            var ikm = BufUtils.RandomBytes( 32 );
            var info = Encoding.ASCII.GetBytes( "test" );

            var output = HKDF.DeriveKey( null, ikm, info, 32 );

            Assert.IsNotNull( output );
            Assert.AreEqual( 32, output.Length );
        }

        /// <summary>
        /// Test HKDF DeriveChainAndKey produces two independent 32-byte keys.
        /// </summary>
        [Test]
        public void TestHKDFDeriveChainAndKey()
        {
            var chainingKey = BufUtils.RandomBytes( 32 );
            var ikm = BufUtils.RandomBytes( 32 );

            var (chainKey, encryptionKey) = HKDF.DeriveChainAndKey( chainingKey, ikm );

            Assert.IsNotNull( chainKey );
            Assert.IsNotNull( encryptionKey );
            Assert.AreEqual( 32, chainKey.Length );
            Assert.AreEqual( 32, encryptionKey.Length );
            Assert.IsFalse( BufUtils.Equal( chainKey, encryptionKey ),
                "Chain key and encryption key should differ" );
        }

        /// <summary>
        /// Test HKDF with the specific i2pd blinding parameters.
        /// HKDF(salt, datestring, "i2pblinding1", 64) should produce 64 bytes.
        /// </summary>
        [Test]
        public void TestHKDFBlindingParameters()
        {
            var salt = BufUtils.RandomBytes( 32 );
            var dateBytes = Encoding.ASCII.GetBytes( "20260410" );
            var info = Encoding.ASCII.GetBytes( "i2pblinding1" );

            var output = HKDF.DeriveKey( salt, dateBytes, info, 64 );

            Assert.IsNotNull( output );
            Assert.AreEqual( 64, output.Length, "Blinding HKDF should produce 64 bytes" );
        }

        /// <summary>
        /// Test HKDF with ELS2 parameters used in encrypted LeaseSet decryption.
        /// </summary>
        [Test]
        public void TestHKDFELS2Parameters()
        {
            var outerSalt = BufUtils.RandomBytes( 32 );
            var outerInput = BufUtils.RandomBytes( 36 ); // subcredential(32) + timestamp(4)
            var info = Encoding.ASCII.GetBytes( "ELS2_L1K" );

            var keys = HKDF.DeriveKey( outerSalt, outerInput, info, 44 );

            Assert.IsNotNull( keys );
            Assert.AreEqual( 44, keys.Length, "ELS2 L1K should produce 44 bytes (32 key + 12 IV)" );

            // Verify key and IV can be extracted
            var key = new byte[32];
            var iv = new byte[12];
            Array.Copy( keys, 0, key, 0, 32 );
            Array.Copy( keys, 32, iv, 0, 12 );

            Assert.AreEqual( 32, key.Length );
            Assert.AreEqual( 12, iv.Length );
        }

        /// <summary>
        /// Test ChaCha20 stream cipher (without AEAD) used by encrypted LS2.
        /// Encrypt then decrypt should give back plaintext.
        /// </summary>
        [Test]
        public void TestChaCha20StreamCipherRoundTrip()
        {
            var key = BufUtils.RandomBytes( 32 );
            var iv = BufUtils.RandomBytes( 12 );
            var plaintext = BufUtils.RandomBytes( 256 );

            // Encrypt
            var engine = new ChaCha7539Engine();
            engine.Init( true, new ParametersWithIV( new KeyParameter( key ), iv ) );
            var ciphertext = new byte[plaintext.Length];
            engine.ProcessBytes( plaintext, 0, plaintext.Length, ciphertext, 0 );

            Assert.IsFalse( BufUtils.Equal( plaintext, ciphertext ),
                "Ciphertext should differ from plaintext" );

            // Decrypt
            engine.Init( false, new ParametersWithIV( new KeyParameter( key ), iv ) );
            var decrypted = new byte[ciphertext.Length];
            engine.ProcessBytes( ciphertext, 0, ciphertext.Length, decrypted, 0 );

            Assert.IsTrue( BufUtils.Equal( plaintext, decrypted ),
                "Decrypted should match original plaintext" );
        }

        /// <summary>
        /// Test GOST R 34.10-2012 (256-bit) key sizes match i2pd spec.
        /// </summary>
        [Test]
        public void TestGostKeySizes()
        {
            Assert.AreEqual( 64,
                I2PSigningKey.SigningPublicKeyLength( I2PSigningKey.SigningKeyTypes.GostR34102012_256 ),
                "GOST-256 public key should be 64 bytes" );
            Assert.AreEqual( 32,
                I2PSigningKey.SigningPrivateKeyLength( I2PSigningKey.SigningKeyTypes.GostR34102012_256 ),
                "GOST-256 private key should be 32 bytes" );
            Assert.AreEqual( 64,
                I2PSigningKey.SignatureLength( I2PSigningKey.SigningKeyTypes.GostR34102012_256 ),
                "GOST-256 signature should be 64 bytes" );

            Assert.AreEqual( 128,
                I2PSigningKey.SigningPublicKeyLength( I2PSigningKey.SigningKeyTypes.GostR34102012_512 ),
                "GOST-512 public key should be 128 bytes" );
            Assert.AreEqual( 64,
                I2PSigningKey.SigningPrivateKeyLength( I2PSigningKey.SigningKeyTypes.GostR34102012_512 ),
                "GOST-512 private key should be 64 bytes" );
            Assert.AreEqual( 128,
                I2PSigningKey.SignatureLength( I2PSigningKey.SigningKeyTypes.GostR34102012_512 ),
                "GOST-512 signature should be 128 bytes" );
        }

        /// <summary>
        /// Test bandwidth class parsing matches i2pd values.
        /// </summary>
        [Test]
        public void TestBandwidthClassParsing()
        {
            Assert.AreEqual(
                I2PCore.SessionLayer.RouterContext.BandwidthClass.L,
                I2PCore.SessionLayer.RouterContext.ParseBandwidthClass( "L" ) );
            Assert.AreEqual(
                I2PCore.SessionLayer.RouterContext.BandwidthClass.O,
                I2PCore.SessionLayer.RouterContext.ParseBandwidthClass( "O" ) );
            Assert.AreEqual(
                I2PCore.SessionLayer.RouterContext.BandwidthClass.P,
                I2PCore.SessionLayer.RouterContext.ParseBandwidthClass( "P" ) );
            Assert.AreEqual(
                I2PCore.SessionLayer.RouterContext.BandwidthClass.X,
                I2PCore.SessionLayer.RouterContext.ParseBandwidthClass( "X" ) );
            Assert.AreEqual(
                I2PCore.SessionLayer.RouterContext.BandwidthClass.O,
                I2PCore.SessionLayer.RouterContext.ParseBandwidthClass( "invalid" ),
                "Invalid class should default to O" );
        }

        /// <summary>
        /// Test that different bandwidth classes produce correct limit values.
        /// </summary>
        [Test]
        public void TestBandwidthClassValues()
        {
            // Verify enum values match i2pd: L=32, M=64, N=128, O=256, P=2048, X=0
            Assert.AreEqual( 32, (int)I2PCore.SessionLayer.RouterContext.BandwidthClass.L );
            Assert.AreEqual( 64, (int)I2PCore.SessionLayer.RouterContext.BandwidthClass.M );
            Assert.AreEqual( 128, (int)I2PCore.SessionLayer.RouterContext.BandwidthClass.N );
            Assert.AreEqual( 256, (int)I2PCore.SessionLayer.RouterContext.BandwidthClass.O );
            Assert.AreEqual( 2048, (int)I2PCore.SessionLayer.RouterContext.BandwidthClass.P );
            Assert.AreEqual( 0, (int)I2PCore.SessionLayer.RouterContext.BandwidthClass.X );
        }
    }
}
