using I2PCore.SessionLayer;
using I2PCore.TransportLayer.SSU2;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Guards the Gate 0 invariant that a default router advertises nothing it cannot actually
///     do. Each default below is off because the feature behind it is known broken or
///     unverified; turning one back on is a deliberate act that should fail here first and be
///     justified in the PR that does it.
/// </summary>
[TestFixture]
public class SafeDefaultsTest
{
    /// <summary>
    ///     SSU2 has no ACK/retransmit path wired up (SSU2AckManager is never instantiated by
    ///     production code) and no Retry/token handling. Phase 4 owns turning this back on.
    /// </summary>
    [Test]
    public void Ssu2IsDisabledByDefault()
    {
        var ctx = new RouterContext();

        ClassicAssert.IsFalse( ctx.EnableSSU2,
            "SSU2 must be opt-in until Phase 4; advertising a broken transport wastes peers' connect attempts" );
    }

    /// <summary>
    ///     The ML-KEM hybrid destination encryption leads with a handshake whose own tests are
    ///     quarantined. ECIES-X25519 is the interoperable default.
    /// </summary>
    [Test]
    public void ProxyEncryptionDefaultsToEcies()
    {
        var ctx = new RouterContext();

        ClassicAssert.AreEqual( RouterContext.HttpProxyEncryptionType.Ecies, ctx.ProxyEncryption,
            "destinations must default to the encryption type peers can actually negotiate" );
    }

    /// <summary>
    ///     NTCP2Host publishes addr.Options["pq"] only when this is set. There is no "pq=0" —
    ///     omitting the option is how a peer knows not to attempt the hybrid handshake.
    /// </summary>
    [Test]
    public void PqTransportIsDisabledByDefault()
    {
        var ctx = new RouterContext();

        ClassicAssert.IsFalse( ctx.EnablePqTransport,
            "the published RouterInfo must not advertise pq while NTCP2PQHandshakeTest is quarantined" );
    }

    /// <summary>
    ///     SSU2Host advertises 'm' in its caps when this is set, but SendPathResponse only logs
    ///     — there is no path validation response on the wire. Batch 4-3 implements it and
    ///     restores this.
    /// </summary>
    [Test]
    public void ConnectionMigrationIsNotAdvertised()
    {
        ClassicAssert.IsFalse( SSU2Host.ConnectionMigrationSupported,
            "do not advertise connection migration while SendPathResponse is a stub" );
    }
}
