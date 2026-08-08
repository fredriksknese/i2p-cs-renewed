using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using NUnit.Framework;

namespace I2PTests.Loopback;

/// <summary>
///     Pairs the SSU2-only "WithHeader" NoiseXK entry points directly, with no SSU2Session and no
///     channel. Batch 3-3 (docs/PRODUCTION-PLAN.md).
///
///     These four methods — CreateMessage1WithHeader(AndCurrentKeys) and
///     ProcessMessage1WithHeader, and their message-2 counterparts — are reachable only from
///     SSU2Session. NTCP2 uses the header-less variants, which NTCP2HandshakeTest covers. So
///     before batch 3-3 nothing exercised this path at all, in any test or in any default
///     configuration (SSU2 is off by default since batch 0-4).
/// </summary>
[TestFixture]
public class NoiseXkWithHeaderTest
{
    private const string Ssu2Protocol = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

    /// <summary>
    ///     The Noise layer itself, given the identical header on both sides. If this passes, the
    ///     handshake failure the loopback fixture shows is in SSU2Session's header handling, not
    ///     in NoiseXK.
    /// </summary>
    [Test]
    public void Message1RoundTripsWhenBothSidesMixTheSameHeader()
    {
        var (bobPriv, bobPub) = X25519.GenerateKeyPair();
        var (alicePriv, alicePub) = X25519.GenerateKeyPair();

        var header = new byte[32];
        for (var i = 0; i < header.Length; i++) header[i] = (byte)(i * 7);

        var payload = new byte[] { 1, 2, 3, 4, 5 };

        var alice = new NoiseXK(Ssu2Protocol);
        alice.InitializeAsAlice(alicePriv, alicePub, bobPub);
        var (ephemeral, ciphertext) = alice.CreateMessage1WithHeader(header, payload);

        var bob = new NoiseXK(Ssu2Protocol);
        bob.InitializeAsBob(bobPriv, bobPub);
        var recovered = bob.ProcessMessage1WithHeader(header, ephemeral, ciphertext);

        Assert.That(recovered, Is.EqualTo(payload));
    }

    /// <summary>
    ///     The same exchange, but Bob mixes a header differing in one byte — which is what
    ///     happens if the header Alice hashes is not byte-identical to the one Bob recovers.
    ///     Establishes that a header mismatch presents exactly as the "AEAD authentication
    ///     failed" the loopback fixture reports, so the two are not confused later.
    /// </summary>
    [Test]
    public void Message1FailsWhenTheHeadersDiffer()
    {
        var (bobPriv, bobPub) = X25519.GenerateKeyPair();
        var (alicePriv, alicePub) = X25519.GenerateKeyPair();

        var aliceHeader = new byte[32];
        var bobHeader = new byte[32];
        bobHeader[7] = 1;

        var alice = new NoiseXK(Ssu2Protocol);
        alice.InitializeAsAlice(alicePriv, alicePub, bobPub);
        var (ephemeral, ciphertext) = alice.CreateMessage1WithHeader(aliceHeader, new byte[] { 9 });

        var bob = new NoiseXK(Ssu2Protocol);
        bob.InitializeAsBob(bobPriv, bobPub);

        var ex = Assert.Throws<System.Exception>(
            () => bob.ProcessMessage1WithHeader(bobHeader, ephemeral, ciphertext));
        Assert.That(ex.Message, Does.Contain("AEAD authentication failed"));
    }
}
