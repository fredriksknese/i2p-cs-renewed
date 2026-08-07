using System;
using System.IO;
using I2PCore;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 2-7 (docs/PRODUCTION-PLAN.md). NetDb shutdown must not be able to kill the process.
///     <para>
///         <c>RoutersStatistics.GetStore()</c> read <c>NetDb.Inst.GetFullPath(...)</c>, and
///         <c>NetDb.Stop()</c> sets <c>Inst = null</c>. <c>Load()</c> runs on the NetDb worker
///         thread, so a Stop arriving mid-load dereferenced null there — and
///         <c>NetDb.Run()</c>'s <c>try</c> had a <c>finally</c> but no <c>catch</c> around
///         <c>Load()</c>, so the exception reached the top of a background thread and took the
///         whole process with it.
///     </para>
///     <para>
///         This surfaced as an intermittently aborted CI run ("Test host process crashed") once
///         the Phase 2 lifecycle fixtures started cycling NetDb quickly. A crashed host reports a
///         partial summary and a non-zero exit, which is a far worse failure mode than a red
///         test: the tests that never ran are simply absent from the count.
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class NetDbLifecycleTest
{
    [OneTimeSetUp]
    public void IsolateStorage()
    {
        _skipReason = NetDb.Inst != null
            ? "another fixture already started NetDb in this process"
            : null;

        if ( _skipReason != null ) return;

        _tempDir = Path.Combine( Path.GetTempPath(), "i2p-netdb-" + Guid.NewGuid().ToString( "N" )[..8] );
        Directory.CreateDirectory( _tempDir );

        _originalNetworkId = I2PConstants.I2PNetworkId;
        _originalBootstrapDisabled = Bootstrap.Disabled;

        I2PConstants.I2PNetworkId = 3;
        Bootstrap.Disabled = true;

        StreamUtils.AppPathOverride = _tempDir;
        RouterContext.RouterSettingsFile = Path.Combine( _tempDir, "NetDbTest.bin" );
        RouterContext.Reset();
    }

    [OneTimeTearDown]
    public void RestoreProcessState()
    {
        if ( _skipReason != null ) return;

        try
        {
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
    ///     The precise regression test for this batch: loading statistics must not require the
    ///     NetDb singleton. <c>GetStore()</c> used to call <c>NetDb.Inst.GetFullPath(...)</c>,
    ///     which throws once <c>Stop()</c> has nulled <c>Inst</c> — and it is reached from the
    ///     worker thread, where the throw is fatal to the process.
    ///     <para>
    ///         Confirmed to fail against the unfixed code with a NullReferenceException. The
    ///         cycling tests below do <b>not</b> reproduce the original CI race; they guard
    ///         restartability, not the crash.
    ///     </para>
    /// </summary>
    [Test]
    public void StatisticsLoadDoesNotDependOnTheNetDbSingleton()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        NetDb.Stop();

        ClassicAssert.IsNull( NetDb.Inst,
            "test setup: the singleton must be absent for this to mean anything" );

        var stats = new RoutersStatistics();
        var storePath = Path.Combine( _tempDir, "statistics-standalone.sto" );

        Assert.DoesNotThrow(
            () => stats.Load( storePath ),
            "RoutersStatistics.Load must work from its own path, not NetDb.Inst" );

        Assert.DoesNotThrow( () => stats.Save( storePath ) );
    }

    /// <summary>
    ///     Restartability under fast cycling. This does not reproduce the CI crash — the window
    ///     needs Stop()'s 5 s join to time out, which an empty temp NetDb never causes — but a
    ///     Start/Stop cycle that left the singleton or its worker in a bad state would show here.
    /// </summary>
    [Test]
    public void RapidStartStopCyclesAreClean()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        for ( var i = 1; i <= 25; i++ )
        {
            NetDb.Start();

            // No delay: the point is to land Stop() inside the worker's Load().
            NetDb.Stop();

            ClassicAssert.IsNull( NetDb.Inst, $"cycle {i}: Stop() must clear the instance" );
        }
    }

    /// <summary>
    ///     Same, with varied delays so Stop() lands at different points in the worker's startup.
    /// </summary>
    [Test]
    public void StartStopAtVariedPointsIsClean()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        foreach ( var delayMs in new[] { 0, 1, 5, 20, 50 } )
            for ( var i = 0; i < 3; i++ )
            {
                NetDb.Start();

                if ( delayMs > 0 ) System.Threading.Thread.Sleep( delayMs );

                NetDb.Stop();

                ClassicAssert.IsNull( NetDb.Inst );
            }
    }

    /// <summary>
    ///     NetDb must come back after a Stop, or the first restart would leave the router with no
    ///     network database at all.
    /// </summary>
    [Test]
    public void NetDbRestartsAfterStop()
    {
        if ( _skipReason != null ) Assert.Ignore( _skipReason );

        NetDb.Start();
        ClassicAssert.IsNotNull( NetDb.Inst );

        NetDb.Stop();
        ClassicAssert.IsNull( NetDb.Inst );

        NetDb.Start();
        ClassicAssert.IsNotNull( NetDb.Inst, "NetDb must be restartable" );
        ClassicAssert.IsNotNull( NetDb.Inst.IdentHashLookup );

        NetDb.Stop();
    }
}
