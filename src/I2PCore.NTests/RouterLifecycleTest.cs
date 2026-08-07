using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using I2PCore;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 2-1 (docs/PRODUCTION-PLAN.md). Start/Stop must be idempotent.
///     <para>
///         <see cref="Router" /> is static, so anything it attaches or caches outlives a Stop().
///         Two things did: <c>TunnelProvider.I2NpMessageReceived</c> was subscribed in Run() and
///         never unsubscribed, growing the invocation list by one per cycle; and the ECIES router
///         processor was cached forever despite <c>RouterContext.Reset()</c> giving the router a
///         new identity on every restart.
///     </para>
///     <para>
///         This runs a real router — on netid 3 with reseed disabled and loopback ports, so it
///         never touches the live network. Batch 2-6 extends it to the full Gate 2 check (10
///         cycles, thread count stable).
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class RouterLifecycleTest
{
    [OneTimeSetUp]
    public void ConfigureIsolatedRouter()
    {
        _skipReason = Router.Started
            ? "another fixture already started the router in this process"
            : null;

        if ( _skipReason != null ) return;

        _tempDir = Path.Combine( Path.GetTempPath(), "i2p-lifecycle-" + Guid.NewGuid().ToString( "N" )[..8] );
        Directory.CreateDirectory( _tempDir );

        _originalBootstrapDisabled = Bootstrap.Disabled;
        _originalNetworkId = I2PConstants.I2PNetworkId;
        _originalDrain = Router.GracefulShutdownTimeout;

        // Safety rule in CLAUDE.md: never netid 2 before Gate 6.
        I2PConstants.I2PNetworkId = 3;
        Bootstrap.Disabled = true;

        // Nothing is transiting, so the drain loop exits on its first check anyway; zero keeps
        // five cycles fast even if a tunnel lingers.
        Router.GracefulShutdownTimeout = TimeSpan.Zero;

        StreamUtils.AppPathOverride = _tempDir;
        RouterContext.RouterSettingsFile = Path.Combine( _tempDir, "LifecycleTest.bin" );
        RouterContext.Reset();

        var ctx = RouterContext.Inst;
        ctx.DefaultExtAddress = IPAddress.Loopback;
        ctx.DefaultTcpPort = PortAllocator.WellKnown.LifecycleNtcp2;
        ctx.DefaultUdpPort = PortAllocator.WellKnown.LifecycleSsu2;
        ctx.IsFirewalled = false;
        ctx.IsHidden = false;
        ctx.FloodfillEnabled = false;
        ctx.ApplyNewSettings();
    }

    [OneTimeTearDown]
    public void RestoreProcessState()
    {
        if ( _skipReason != null ) return;

        try
        {
            if ( Router.Started ) Router.Stop();
        }
        finally
        {
            Bootstrap.Disabled = _originalBootstrapDisabled;
            I2PConstants.I2PNetworkId = _originalNetworkId;
            Router.GracefulShutdownTimeout = _originalDrain;

            try
            {
                if ( _tempDir != null && Directory.Exists( _tempDir ) )
                    Directory.Delete( _tempDir, true );
            }
            catch ( IOException )
            {
                // A background thread may still hold a file open; the temp dir is disposable.
            }
        }
    }

    private const int Cycles = 5;

    private string _tempDir;
    private string _skipReason;
    private bool _originalBootstrapDisabled;
    private int _originalNetworkId;
    private TimeSpan _originalDrain;

    /// <summary>
    ///     The defect this batch fixes. Before it, the count was the number of Start() calls, so
    ///     after five cycles every inbound I2NP message was dispatched to five handlers — four of
    ///     them bound to router contexts that had already been reset.
    /// </summary>
    [Test]
    public void HandlersDoNotAccumulateAcrossStartStopCycles()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        ClassicAssert.AreEqual( 0, TunnelProvider.I2NpMessageReceivedHandlerCount,
            "the router is stopped, so nothing should be attached yet" );

        // NetDb.Stop() nulls NetDb.Inst, so each cycle gets a fresh IdentResolver whose events
        // start empty. Router is not its only subscriber -- UnknownRouterQueue attaches from
        // TransportProvider's constructor -- so the invariant worth asserting is that the counts
        // do not grow, not that they equal one. Baselined from cycle 1 rather than hardcoded, so
        // this keeps working if another legitimate subscriber appears.
        var baselineLeaseSet = 0;
        var baselineFailure = 0;

        for ( var i = 1; i <= Cycles; i++ )
        {
            Router.Start();

            ClassicAssert.IsTrue( Router.Started, $"cycle {i}: Router.Start() did not start" );

            // This one is the defect: TunnelProvider.I2NpMessageReceived is static, so a handler
            // left attached here really does survive Stop() and accumulate.
            ClassicAssert.AreEqual( 1, TunnelProvider.I2NpMessageReceivedHandlerCount,
                $"cycle {i}: exactly one I2NpMessageReceived handler must be attached while running" );

            var lookup = NetDb.Inst.IdentHashLookup;

            if ( i == 1 )
            {
                baselineLeaseSet = lookup.LeaseSetReceivedHandlerCount;
                baselineFailure = lookup.LookupFailureHandlerCount;

                ClassicAssert.GreaterOrEqual( baselineLeaseSet, 1,
                    "Router must attach its LeaseSetReceived handler to the current resolver" );
                ClassicAssert.GreaterOrEqual( baselineFailure, 1,
                    "Router must attach its LookupFailure handler to the current resolver" );
            }
            else
            {
                ClassicAssert.AreEqual( baselineLeaseSet, lookup.LeaseSetReceivedHandlerCount,
                    $"cycle {i}: LeaseSetReceived handler count grew" );
                ClassicAssert.AreEqual( baselineFailure, lookup.LookupFailureHandlerCount,
                    $"cycle {i}: LookupFailure handler count grew" );
            }

            Router.Stop();

            ClassicAssert.IsFalse( Router.Started, $"cycle {i}: Router.Stop() did not stop" );

            ClassicAssert.AreEqual( 0, TunnelProvider.I2NpMessageReceivedHandlerCount,
                $"cycle {i}: Stop() must detach the I2NpMessageReceived handler it attached" );
        }
    }

    /// <summary>
    ///     Stop() calls RouterContext.Reset(), and the cached ECIES processor used to survive it
    ///     still holding the previous identity's ident hash and X25519 keys. It would then fail to
    ///     decrypt every router-level garlic message addressed to the running router, reporting
    ///     nothing wrong — the processor builds lazily and, once non-null, is never rebuilt.
    ///     <para>
    ///         The restart has to be given a different settings file to be a real test. Reset()
    ///         reloads the same persisted keys, so with one settings file the identity is stable
    ///         across restarts and a stale processor is indistinguishable from a fresh one.
    ///     </para>
    /// </summary>
    [Test]
    public void EciesProcessorFollowsTheCurrentRouterContext()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        I2PIdentHash firstIdentity;

        Router.Start();

        try
        {
            var processor = Router.EciesRouterProcessor;

            ClassicAssert.IsNotNull( processor, "ECIES processor should build from a started router" );

            firstIdentity = RouterContext.Inst.MyRouterIdentity.IdentHash;

            ClassicAssert.AreEqual( firstIdentity, processor.LocalRouterHash,
                "the processor must be bound to the identity the router is currently running as" );
        }
        finally
        {
            Router.Stop();
        }

        // Give the router a genuinely new identity, as a fresh install or a rotated key would.
        RouterContext.RouterSettingsFile = Path.Combine( _tempDir, "LifecycleTest-restart.bin" );
        RouterContext.Reset();
        RouterContext.Inst.ApplyNewSettings();

        Router.Start();

        try
        {
            var secondIdentity = RouterContext.Inst.MyRouterIdentity.IdentHash;

            ClassicAssert.AreNotEqual( firstIdentity, secondIdentity,
                "test setup: the restart must actually change identity, or this proves nothing" );

            ClassicAssert.AreEqual( secondIdentity, Router.EciesRouterProcessor.LocalRouterHash,
                "after a restart the processor must be rebuilt against the current RouterContext, "
                + "not left bound to the identity it was first built for" );
        }
        finally
        {
            Router.Stop();

            // Leave the fixture on the settings file the other tests were configured with.
            RouterContext.RouterSettingsFile = Path.Combine( _tempDir, "LifecycleTest.bin" );
            RouterContext.Reset();
        }
    }

    /// <summary>
    ///     <b>Gate 2</b> (batch 2-6): 10 Start/Stop cycles in one process — no handler growth, no
    ///     thread growth, clean exit.
    ///     <para>
    ///         Thread count is compared against a baseline taken after the first cycle, not before
    ///         it: the first Start() creates the layer worker threads and warms the thread pool,
    ///         so measuring from a cold process would report that one-time cost as a leak. The
    ///         tolerance is for thread-pool breathing, which is not under the router's control;
    ///         an actual per-cycle leak would be ten threads, far outside it.
    ///     </para>
    /// </summary>
    [Test]
    public void TenStartStopCyclesLeakNothing()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        Router.Start();
        Router.Stop();

        var baselineThreads = ThreadCount();

        for ( var i = 1; i <= 10; i++ )
        {
            Router.Start();

            ClassicAssert.AreEqual( 1, TunnelProvider.I2NpMessageReceivedHandlerCount,
                $"cycle {i}: I2NpMessageReceived handler count" );

            Router.Stop();

            ClassicAssert.AreEqual( 0, TunnelProvider.I2NpMessageReceivedHandlerCount,
                $"cycle {i}: handlers must be detached while stopped" );

            ClassicAssert.IsFalse( I2PPrivateKey.PrecalculationRunning,
                $"cycle {i}: Stop() must leave no DH key generator running (batch 2-2)" );
        }

        var finalThreads = ThreadCount();

        ClassicAssert.LessOrEqual( finalThreads, baselineThreads + 5,
            $"thread count grew from {baselineThreads} to {finalThreads} over 10 Start/Stop cycles" );
    }

    private static int ThreadCount()
    {
        using var p = Process.GetCurrentProcess();
        p.Refresh();
        return p.Threads.Count;
    }

    /// <summary>
    ///     Start() and Stop() are documented as no-ops when already in the target state. If a
    ///     redundant Start() subscribed a second time, the guard in the first test would only
    ///     catch it by luck.
    /// </summary>
    [Test]
    public void RedundantStartAndStopAreNoOps()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        Router.Stop();
        Router.Stop();

        ClassicAssert.AreEqual( 0, TunnelProvider.I2NpMessageReceivedHandlerCount );

        Router.Start();
        Router.Start();

        try
        {
            ClassicAssert.AreEqual( 1, TunnelProvider.I2NpMessageReceivedHandlerCount,
                "a second Start() while running must not subscribe again" );
        }
        finally
        {
            Router.Stop();
        }
    }
}
