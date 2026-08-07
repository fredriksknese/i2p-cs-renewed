using System.Net;
using I2PCore.Client;
using I2PCore.Data;
using I2PCore.SessionLayer.Streaming;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 2-5 (docs/PRODUCTION-PLAN.md). Session lifetime in <see cref="I2PUDPServerTunnel" />.
///     <para>
///         <c>ObtainSession</c>'s fast path tested the dictionary for the requested key and then
///         returned <c>_lastSession</c> — whichever port pair that happened to belong to. With two
///         or more active remotes it forwarded one peer's datagrams over another peer's session and
///         socket. It also had no interlock with <c>ExpireStale</c>, which disposes sessions
///         without clearing the cache, so it could return a session whose socket was already gone.
///     </para>
/// </summary>
[TestFixture]
public class UdpTunnelSessionTest
{
    [SetUp]
    public void CreateTunnel()
    {
        var info = new I2PDestinationInfo( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );

        _datagrams = new DatagramDestination(
            info.Destination,
            info.PrivateSigningKey,
            ( _, _ ) => { } );

        _tunnel = new I2PUDPServerTunnel(
            "test",
            _datagrams,
            new IPEndPoint( IPAddress.Loopback, 29094 ),
            0 );
    }

    [TearDown]
    public void DisposeTunnel()
    {
        _tunnel?.Dispose();
        _datagrams?.Dispose();
    }

    private I2PUDPServerTunnel _tunnel;
    private DatagramDestination _datagrams;

    private static readonly I2PIdentHash PeerA = new( true );
    private static readonly I2PIdentHash PeerB = new( true );

    /// <summary>
    ///     The defect. Two remotes on different port pairs must get their own sessions; the old
    ///     fast path returned the cached one for both, so B's datagrams went out over A's socket.
    /// </summary>
    [Test]
    public void SessionsAreNotSharedBetweenDifferentPortPairs()
    {
        var a = _tunnel.ObtainSession( PeerA, 1000, 2000 );
        var b = _tunnel.ObtainSession( PeerB, 1001, 2001 );

        ClassicAssert.AreNotSame( a, b,
            "a different (fromPort, toPort) pair must get its own session, not the cached one" );

        ClassicAssert.AreEqual( 1000, a.RemotePort );
        ClassicAssert.AreEqual( 2000, a.LocalPort );
        ClassicAssert.AreEqual( 1001, b.RemotePort );
        ClassicAssert.AreEqual( 2001, b.LocalPort );

        ClassicAssert.AreEqual( 2, _tunnel.SessionCount );
    }

    /// <summary>
    ///     Interleaving is what makes the bug bite in practice: the cache is refreshed by whichever
    ///     remote spoke last, so the next lookup for a different pair returned the wrong session.
    /// </summary>
    [Test]
    public void RepeatedLookupsStayOnTheirOwnSession()
    {
        var a1 = _tunnel.ObtainSession( PeerA, 1000, 2000 );
        var b1 = _tunnel.ObtainSession( PeerB, 1001, 2001 );
        var a2 = _tunnel.ObtainSession( PeerA, 1000, 2000 );
        var b2 = _tunnel.ObtainSession( PeerB, 1001, 2001 );

        ClassicAssert.AreSame( a1, a2, "the same port pair must resolve to the same session" );
        ClassicAssert.AreSame( b1, b2 );
        ClassicAssert.AreNotSame( a2, b2 );
    }

    /// <summary>
    ///     The disposal half. ExpireStale disposes the session it removes; if the cache still
    ///     pointed at it, the next lookup handed back an object whose UdpClient was disposed and
    ///     the forward threw ObjectDisposedException.
    /// </summary>
    [Test]
    public void ExpiredSessionsAreDisposedAndNotHandedOutAgain()
    {
        var first = _tunnel.ObtainSession( PeerA, 1000, 2000 );

        ClassicAssert.AreEqual( 1, _tunnel.SessionCount );

        // Age the session past the timeout instead of waiting two minutes for it.
        first.LastActivity -= UDPTunnelConstants.SESSION_TIMEOUT_MS + 1000;

        _tunnel.ExpireStale();

        ClassicAssert.AreEqual( 0, _tunnel.SessionCount, "the stale session should have been removed" );

        var second = _tunnel.ObtainSession( PeerA, 1000, 2000 );

        ClassicAssert.AreNotSame( first, second,
            "the expired session was disposed; handing it back would use a disposed socket" );
    }

    [Test]
    public void StopDisposesEverySession()
    {
        _tunnel.ObtainSession( PeerA, 1000, 2000 );
        _tunnel.ObtainSession( PeerB, 1001, 2001 );

        ClassicAssert.AreEqual( 2, _tunnel.SessionCount );

        _tunnel.Start();
        _tunnel.Stop();

        ClassicAssert.AreEqual( 0, _tunnel.SessionCount );
    }

    /// <summary>
    ///     Stop() early-returns when the tunnel was never started, so Dispose() used to leave the
    ///     CancellationTokenSource from the field initialiser undisposed.
    /// </summary>
    [Test]
    public void DisposingAnUnstartedTunnelIsClean()
    {
        var info = new I2PDestinationInfo( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );

        using var datagrams = new DatagramDestination(
            info.Destination, info.PrivateSigningKey, ( _, _ ) => { } );

        var tunnel = new I2PUDPServerTunnel(
            "unstarted", datagrams, new IPEndPoint( IPAddress.Loopback, 29095 ), 0 );

        Assert.DoesNotThrow( () => tunnel.Dispose() );
        Assert.DoesNotThrow( () => tunnel.Dispose(), "Dispose must be idempotent" );
    }
}
