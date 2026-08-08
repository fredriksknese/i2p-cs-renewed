using I2PCore.Data;
using NUnit.Framework;

namespace I2PTests;

/// <summary>
///     Derived public keys must be exactly the fixed width their type declares.
///
///     Unplanned batch after 3-4 (docs/PRODUCTION-PLAN.md). `GarlicTest.TestEncodeDecodeLoop`
///     failed in CI with <c>ArgumentException: y value does not appear to be in correct group</c>
///     — the failure session 1 saw once, could not reproduce in fourteen further runs, and
///     recorded as possibly a flaky test.
///
///     <para>
///         It was not flaky. <c>I2PPublicKey</c> derived ElGamal keys with
///         <c>BigInteger.ToByteArrayUnsigned()</c>, which drops leading zero bytes, so a key
///         whose most significant byte happened to be zero came out 255 bytes instead of 256.
///         I2P public keys are fixed width, so a short key shifts every field after it in the
///         serialised Destination and the reader recovers a corrupt group element. About one key
///         in 256 — frequent enough to hit CI now and then, rare enough to look like flakiness.
///         <c>I2PSigningPublicKey</c> had the same defect for DSA.
///     </para>
///     <para>
///         These tests generate enough keys that a regression is near-certain to be caught: at
///         one in 256, the chance of <see cref="Samples" /> keys all being full length by luck
///         is <c>(255/256)^2000</c>, about 4 in 10000. That is why this is a population test
///         rather than one more run of the test that flaked — a single run catches the defect
///         0.4% of the time, which is exactly how it stayed hidden for two sessions.
///     </para>
/// </summary>
[TestFixture]
public class KeyLengthTest
{
    /// <summary>
    ///     Large enough that a reintroduced one-in-256 defect essentially cannot pass (see the
    ///     probability on the fixture), small enough to keep the cost bounded — ElGamal key
    ///     generation dominates, at roughly 12 ms each.
    /// </summary>
    private const int Samples = 2000;

    [Test]
    public void DerivedElGamalPublicKeysAreAlwaysFullLength()
    {
        var expected = I2PKeyType.PublicKeyLength(I2PKeyType.KeyTypes.ElGamal2048);
        var shortest = expected;
        var shortCount = 0;

        for (var i = 0; i < Samples; i++)
        {
            var priv = new I2PPrivateKey(new I2PCertificate(I2PKeyType.KeyTypes.ElGamal2048));
            var pub = new I2PPublicKey(priv);

            if (pub.Key.Length == expected) continue;

            shortCount++;
            if (pub.Key.Length < shortest) shortest = pub.Key.Length;
        }

        Assert.That(shortCount, Is.Zero,
            $"{shortCount} of {Samples} ElGamal public keys were not {expected} bytes " +
            $"(shortest {shortest}). Leading zero bytes are being dropped.");
    }

    [Test]
    public void DerivedDsaSigningPublicKeysAreAlwaysFullLength()
    {
        var expected = I2PSigningKey.SigningPublicKeyLength(I2PSigningKey.SigningKeyTypes.DsaSha1);
        var shortest = expected;
        var shortCount = 0;

        for (var i = 0; i < Samples; i++)
        {
            var priv = new I2PSigningPrivateKey(new I2PCertificate(I2PSigningKey.SigningKeyTypes.DsaSha1));
            var pub = new I2PSigningPublicKey(priv);

            if (pub.Key.Length == expected) continue;

            shortCount++;
            if (pub.Key.Length < shortest) shortest = pub.Key.Length;
        }

        Assert.That(shortCount, Is.Zero,
            $"{shortCount} of {Samples} DSA signing public keys were not {expected} bytes " +
            $"(shortest {shortest}). Leading zero bytes are being dropped.");
    }
}
