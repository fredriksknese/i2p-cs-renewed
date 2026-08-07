using System;
using System.Linq;
using System.Security.Cryptography;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 1-4 (docs/PRODUCTION-PLAN.md). The RNG seam.
///     <para>
///         Randomness used to enter I2PCore through four independent doors, so nothing that
///         consumed it could be made reproducible. Phases 4 and 5 need to diff protocol bytes
///         against i2pd captures; that is impossible while every run produces different ephemeral
///         keys and padding. Routing everything through <c>BufUtils.RandomSource</c> makes a whole
///         handshake replayable from a seed.
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class RngSeamTest
{
    [TearDown]
    public void RestoreRealCsprng()
    {
        BufUtils.RandomSource = null;
    }

    private const string NTCP2_PROTOCOL = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

    /// <summary>
    ///     The gate for this batch: a seeded source produces byte-identical NTCP2 message 1 across
    ///     runs. Message 1 is Alice's ephemeral X25519 public key plus the ChaCha20-Poly1305
    ///     options block, so this covers BouncyCastle key generation (via
    ///     <c>BufUtils.BcRandom</c>) and the AEAD together.
    /// </summary>
    [Test]
    public void SeededSourceGivesIdenticalNtcp2Message1()
    {
        var aliceStatic = WithSeed( 0xa11ce, X25519.GenerateKeyPair );
        var bobStatic = WithSeed( 0x5eed, X25519.GenerateKeyPair );

        var first = WithSeed( 42, () => BuildMessage1( aliceStatic, bobStatic.publicKey ) );
        var second = WithSeed( 42, () => BuildMessage1( aliceStatic, bobStatic.publicKey ) );

        CollectionAssert.AreEqual( first.ephemeral, second.ephemeral,
            "the same seed must produce the same ephemeral key" );
        CollectionAssert.AreEqual( first.encrypted, second.encrypted,
            "the same seed must produce byte-identical NTCP2 message 1" );
    }

    /// <summary>
    ///     Guards the obvious way for this to pass vacuously — if the ephemeral key were somehow
    ///     constant, the test above would also pass.
    /// </summary>
    [Test]
    public void DifferentSeedsGiveDifferentNtcp2Message1()
    {
        var aliceStatic = WithSeed( 0xa11ce, X25519.GenerateKeyPair );
        var bobStatic = WithSeed( 0x5eed, X25519.GenerateKeyPair );

        var first = WithSeed( 42, () => BuildMessage1( aliceStatic, bobStatic.publicKey ) );
        var second = WithSeed( 43, () => BuildMessage1( aliceStatic, bobStatic.publicKey ) );

        CollectionAssert.AreNotEqual( first.ephemeral, second.ephemeral );
        CollectionAssert.AreNotEqual( first.encrypted, second.encrypted );
    }

    /// <summary>
    ///     X25519 generates keys through BouncyCastle, which had its own SecureRandom. If that
    ///     door were still open this would fail while the BufUtils helpers below still passed.
    /// </summary>
    [Test]
    public void BouncyCastleKeyGenerationDrawsFromTheSeam()
    {
        var first = WithSeed( 7, X25519.GenerateKeyPair );
        var second = WithSeed( 7, X25519.GenerateKeyPair );

        CollectionAssert.AreEqual( first.privateKey, second.privateKey );
        CollectionAssert.AreEqual( first.publicKey, second.publicKey );
    }

    [Test]
    public void BufUtilsHelpersDrawFromTheSeam()
    {
        var first = WithSeed( 99, () => (
            Bytes: BufUtils.RandomBytes( 64 ),
            Int: BufUtils.RandomInt( 1000 ),
            Uint: BufUtils.RandomUint()) );

        var second = WithSeed( 99, () => (
            Bytes: BufUtils.RandomBytes( 64 ),
            Int: BufUtils.RandomInt( 1000 ),
            Uint: BufUtils.RandomUint()) );

        CollectionAssert.AreEqual( first.Bytes, second.Bytes );
        ClassicAssert.AreEqual( first.Int, second.Int );
        ClassicAssert.AreEqual( first.Uint, second.Uint );
    }

    /// <summary>
    ///     The seam must never be left engaged. Clearing it has to restore a real CSPRNG, not
    ///     leave the last test's deterministic stream generating this router's keys.
    /// </summary>
    [Test]
    public void ClearingTheSeamRestoresARealCsprng()
    {
        BufUtils.RandomSource = new SeededRandomSource( 1 );
        BufUtils.RandomSource = null;

        var a = BufUtils.RandomBytes( 32 );
        var b = BufUtils.RandomBytes( 32 );

        CollectionAssert.AreNotEqual( a, b );
        ClassicAssert.IsFalse( a.All( x => x == 0 ) );
    }

    /// <summary>
    ///     Elligator2 used static RandomNumberGenerator.Fill, bypassing the seam entirely.
    /// </summary>
    [Test]
    public void Elligator2DrawsFromTheSeam()
    {
        var first = WithSeed( 11, Elligator2.GenerateRandomRepresentative );
        var second = WithSeed( 11, Elligator2.GenerateRandomRepresentative );

        CollectionAssert.AreEqual( first, second );
    }

    private static (byte[] ephemeral, byte[] encrypted) BuildMessage1(
        (byte[] privateKey, byte[] publicKey) aliceStatic,
        byte[] bobStaticPublic )
    {
        var alice = new NoiseXK( NTCP2_PROTOCOL );
        alice.InitializeAsAlice( aliceStatic.privateKey, aliceStatic.publicKey, bobStaticPublic );

        return alice.CreateMessage1( new byte[16] );
    }

    private static T WithSeed<T>( int seed, Func<T> body )
    {
        BufUtils.RandomSource = new SeededRandomSource( seed );

        try
        {
            return body();
        }
        finally
        {
            BufUtils.RandomSource = null;
        }
    }

    /// <summary>
    ///     A reproducible byte stream shaped like a CSPRNG: SHA-256 in counter mode over the seed.
    ///     Deliberately lives in the test assembly — I2PCore must not ship a class that can
    ///     silently make a real router's keys predictable.
    /// </summary>
    private sealed class SeededRandomSource : RandomNumberGenerator
    {
        private readonly object _lock = new();
        private readonly byte[] _seed;
        private ulong _counter;

        public SeededRandomSource( int seed )
        {
            _seed = BitConverter.GetBytes( seed );
        }

        public override void GetBytes( byte[] data )
        {
            GetBytes( data.AsSpan() );
        }

        public override void GetBytes( byte[] data, int offset, int count )
        {
            GetBytes( data.AsSpan( offset, count ) );
        }

        public override void GetBytes( Span<byte> data )
        {
            lock ( _lock )
            {
                while ( data.Length > 0 )
                {
                    var block = NextBlock();
                    var take = Math.Min( block.Length, data.Length );

                    block.AsSpan( 0, take ).CopyTo( data );
                    data = data[take..];
                }
            }
        }

        public override void GetNonZeroBytes( byte[] data )
        {
            GetNonZeroBytes( data.AsSpan() );
        }

        public override void GetNonZeroBytes( Span<byte> data )
        {
            Span<byte> one = stackalloc byte[1];

            for ( var i = 0; i < data.Length; i++ )
            {
                do
                {
                    GetBytes( one );
                } while ( one[0] == 0 );

                data[i] = one[0];
            }
        }

        private byte[] NextBlock()
        {
            var input = new byte[_seed.Length + 8];

            _seed.CopyTo( input, 0 );
            BitConverter.GetBytes( _counter++ ).CopyTo( input, _seed.Length );

            return SHA256.HashData( input );
        }
    }
}
