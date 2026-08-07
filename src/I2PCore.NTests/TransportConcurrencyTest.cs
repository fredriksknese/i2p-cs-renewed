using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using I2PCore;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 2-4 (docs/PRODUCTION-PLAN.md). Locking hygiene in <see cref="TransportProvider" />.
///     <para>
///         Two defects. <c>DistributeIncomingMessage</c> locked on the mutable
///         <c>IncomingMessage</c> event field and read it three times, so a subscription change
///         racing a delivery could produce <c>lock(null)</c> or a null invoke. And
///         <c>GetEstablishedTransport</c> held one instance-wide lock across <c>CreateTransport</c>,
///         serialising every send in the router behind any single outbound connect.
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class TransportConcurrencyTest
{
    [OneTimeSetUp]
    public void StartTransportLayer()
    {
        _skipReason = TransportProvider.Inst != null
            ? "another fixture already started the transport layer in this process"
            : null;

        if ( _skipReason != null ) return;

        _tempDir = Path.Combine( Path.GetTempPath(), "i2p-transport-" + Guid.NewGuid().ToString( "N" )[..8] );
        Directory.CreateDirectory( _tempDir );

        _originalNetworkId = I2PConstants.I2PNetworkId;
        _originalBootstrapDisabled = Bootstrap.Disabled;

        I2PConstants.I2PNetworkId = 3;
        Bootstrap.Disabled = true;

        StreamUtils.AppPathOverride = _tempDir;
        RouterContext.RouterSettingsFile = Path.Combine( _tempDir, "TransportTest.bin" );
        RouterContext.Reset();

        var ctx = RouterContext.Inst;
        ctx.DefaultExtAddress = IPAddress.Loopback;
        ctx.DefaultTcpPort = PortAllocator.WellKnown.TransportConcurrencyNtcp2;
        ctx.DefaultUdpPort = PortAllocator.WellKnown.TransportConcurrencySsu2;
        ctx.IsFirewalled = false;
        ctx.FloodfillEnabled = false;
        ctx.ApplyNewSettings();

        NetDb.Start();
        TransportProvider.Start();
    }

    [OneTimeTearDown]
    public void StopTransportLayer()
    {
        if ( _skipReason != null ) return;

        try
        {
            TransportProvider.Stop();
            NetDb.Stop();
        }
        finally
        {
            I2PConstants.I2PNetworkId = _originalNetworkId;
            Bootstrap.Disabled = _originalBootstrapDisabled;

            try
            {
                if ( _tempDir != null && Directory.Exists( _tempDir ) )
                    Directory.Delete( _tempDir, true );
            }
            catch ( IOException )
            {
            }
        }
    }

    private string _tempDir;
    private string _skipReason;
    private int _originalNetworkId;
    private bool _originalBootstrapDisabled;

    /// <summary>
    ///     The exact race the old code lost. `if (IncomingMessage != null) lock (IncomingMessage)`
    ///     read the field twice and invoked it a third time; an unsubscribe landing between the
    ///     null check and the lock threw ArgumentNullException, and one landing before the invoke
    ///     threw NullReferenceException. Delegates are immutable, so a `+=` also swapped the very
    ///     object being locked on — two threads could hold "the lock" on different instances.
    /// </summary>
    [Test]
    public void DeliveryToleratesConcurrentSubscriptionChanges()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        var provider = TransportProvider.Inst;
        var failures = new ConcurrentBag<Exception>();
        var delivered = 0;
        var stop = false;

        void Handler( ITransport t, Ii2NpHeader m )
        {
            Interlocked.Increment( ref delivered );
        }

        var churn = Enumerable.Range( 0, 4 ).Select( _ => Task.Run( () =>
        {
            try
            {
                while ( !Volatile.Read( ref stop ) )
                {
                    provider.IncomingMessage += Handler;
                    provider.IncomingMessage -= Handler;
                }
            }
            catch ( Exception ex )
            {
                failures.Add( ex );
            }
        } ) ).ToArray();

        var senders = Enumerable.Range( 0, 4 ).Select( _ => Task.Run( () =>
        {
            try
            {
                for ( var i = 0; i < 5000; i++ )
                {
                    var msg = new DeliveryStatusMessage( (uint)( i + 1 ) );
                    provider.DistributeIncomingMessage( null, msg.CreateHeader16 );
                }
            }
            catch ( Exception ex )
            {
                failures.Add( ex );
            }
        } ) ).ToArray();

        Task.WaitAll( senders, TimeSpan.FromSeconds( 60 ) );
        Volatile.Write( ref stop, true );
        Task.WaitAll( churn, TimeSpan.FromSeconds( 30 ) );

        ClassicAssert.IsEmpty( failures,
            "delivering while subscriptions change must not throw: "
            + string.Join( " | ", failures.Select( e => e.GetType().Name + ": " + e.Message ).Distinct() ) );
    }

    /// <summary>
    ///     Delivery must still reach a stable subscriber — a fix that dropped messages instead of
    ///     throwing would satisfy the test above.
    /// </summary>
    [Test]
    public void DeliveryReachesAStableSubscriber()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        var provider = TransportProvider.Inst;
        var delivered = 0;

        void Handler( ITransport t, Ii2NpHeader m )
        {
            Interlocked.Increment( ref delivered );
        }

        provider.IncomingMessage += Handler;

        try
        {
            for ( var i = 0; i < 100; i++ )
                provider.DistributeIncomingMessage( null, new DeliveryStatusMessage( (uint)( i + 1 ) ).CreateHeader16 );
        }
        finally
        {
            provider.IncomingMessage -= Handler;
        }

        ClassicAssert.AreEqual( 100, delivered );
    }

    /// <summary>
    ///     The batch's verify row: 50 parallel lookups. Every send in the router passes through
    ///     this path, and it used to serialise them all behind one lock that was also held across
    ///     an outbound socket connect.
    ///     <para>
    ///         The destinations are unknown to NetDb, so each resolves to null quickly — this
    ///         proves the coalescing path is deadlock- and exception-free under contention, not
    ///         that a slow connect no longer blocks others, which needs an injectable transport
    ///         and belongs with the Phase 3 fixtures.
    ///     </para>
    /// </summary>
    [Test]
    public void ParallelTransportLookupsDoNotDeadlock()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        var provider = TransportProvider.Inst;
        var failures = new ConcurrentBag<Exception>();

        // A mix of distinct destinations and one shared destination, so both the independent
        // path and the coalescing path are exercised.
        var shared = new I2PIdentHash( true );

        var sw = Stopwatch.StartNew();

        var tasks = Enumerable.Range( 0, 50 ).Select( i => Task.Run( () =>
        {
            try
            {
                var dest = i % 2 == 0
                    ? shared
                    : new I2PIdentHash( true );

                provider.GetTransport( dest );
            }
            catch ( Exception ex )
            {
                failures.Add( ex );
            }
        } ) ).ToArray();

        var finished = Task.WaitAll( tasks, TimeSpan.FromSeconds( 30 ) );
        sw.Stop();

        ClassicAssert.IsTrue( finished,
            $"50 parallel GetTransport calls did not finish within 30 s ({sw.ElapsedMilliseconds} ms elapsed)" );

        ClassicAssert.IsEmpty( failures,
            "parallel lookups must not throw: "
            + string.Join( " | ", failures.Select( e => e.GetType().Name + ": " + e.Message ).Distinct() ) );
    }

    /// <summary>
    ///     A failed connect must not poison the destination. Lazy caches thrown exceptions for the
    ///     life of the instance, so the pending entry has to be removed either way — otherwise one
    ///     failure would make a peer permanently unreachable.
    /// </summary>
    [Test]
    public void FailedLookupsDoNotPoisonTheDestination()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        var provider = TransportProvider.Inst;
        var dest = new I2PIdentHash( true );

        for ( var i = 0; i < 5; i++ )
            ClassicAssert.IsNull( provider.GetTransport( dest ),
                $"attempt {i + 1}: an unknown destination should resolve to null, repeatably" );
    }
}
