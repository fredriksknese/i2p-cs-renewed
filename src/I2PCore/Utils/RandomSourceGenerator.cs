using System;
using Org.BouncyCastle.Crypto.Prng;

namespace I2PCore.Utils;

/// <summary>
///     Batch 1-4 (docs/PRODUCTION-PLAN.md). Bridges BouncyCastle's <see cref="IRandomGenerator" />
///     onto <see cref="BufUtils.RandomSource" />, so key generation performed by BouncyCastle
///     (X25519, ML-KEM, signatures, ElGamal) draws from the same seam as everything else.
///     <para>
///         Every call reads <c>BufUtils.RandomSource</c> rather than capturing it, so a test that
///         swaps the source affects the shared <c>BufUtils.BcRandom</c> instance immediately.
///     </para>
///     <para>
///         Seed material is discarded. The underlying source is either the platform CSPRNG, which
///         needs no seeding, or a test stream whose whole purpose is to be reproducible — mixing
///         in BouncyCastle's own entropy would defeat it.
///     </para>
/// </summary>
internal sealed class RandomSourceGenerator : IRandomGenerator
{
    public void AddSeedMaterial( byte[] seed )
    {
    }

    public void AddSeedMaterial( ReadOnlySpan<byte> seed )
    {
    }

    public void AddSeedMaterial( long seed )
    {
    }

    public void NextBytes( byte[] bytes )
    {
        BufUtils.RandomSource.GetBytes( bytes );
    }

    public void NextBytes( byte[] bytes, int start, int len )
    {
        BufUtils.RandomSource.GetBytes( bytes, start, len );
    }

    public void NextBytes( Span<byte> bytes )
    {
        BufUtils.RandomSource.GetBytes( bytes );
    }
}
