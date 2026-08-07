using System.Diagnostics;
using System.Threading;
using I2PCore.Data;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 2-2 (docs/PRODUCTION-PLAN.md). The DH key pair precalculation thread.
///     <para>
///         <c>Run()</c> was <c>while (true)</c> with no cancellation, so once started the thread
///         lived until process exit — waking every 5 s and refilling the pool — and a host
///         embedding I2PCore had no way to get the thread back from <c>Router.Stop()</c>.
///     </para>
/// </summary>
[TestFixture]
[NonParallelizable]
public class KeyPrecalculationTest
{
    [TearDown]
    public void StopGenerator()
    {
        I2PPrivateKey.StopPrecalculation();
    }

    private const int Cycles = 10;

    /// <summary>
    ///     The defect. Before this batch there was no code path that could make this false again
    ///     once <see cref="I2PPrivateKey.GetNewKeyPair" /> had been called.
    /// </summary>
    [Test]
    public void StopPrecalculationEndsTheThread()
    {
        I2PPrivateKey.GetNewKeyPair();

        ClassicAssert.IsTrue( I2PPrivateKey.PrecalculationRunning,
            "requesting a key pair should start the generator" );

        I2PPrivateKey.StopPrecalculation();

        ClassicAssert.IsFalse( I2PPrivateKey.PrecalculationRunning,
            "StopPrecalculation() must join the generator thread before returning" );
    }

    /// <summary>
    ///     Once the pool is full the generator parks in a 5 s wait. Cancelling the token is not
    ///     enough on its own — nothing re-checks it until the wait returns — so Stop() has to
    ///     signal the event too. Ten cycles of sitting through that wait would add nearly a
    ///     minute to shutdown.
    ///     <para>
    ///         The parked state is the whole point: an earlier version of this test slept a fixed
    ///         100 ms, caught the generator still refilling, and passed with the wake-up removed,
    ///         because the refill loop re-checks the token on every iteration.
    ///     </para>
    /// </summary>
    [Test]
    public void StopPrecalculationIsPrompt()
    {
        I2PPrivateKey.GetNewKeyPair();

        WaitForFullPool();

        // Give the generator a moment to come back round to WaitOne after the last key.
        Thread.Sleep( 200 );

        var sw = Stopwatch.StartNew();
        I2PPrivateKey.StopPrecalculation();
        sw.Stop();

        ClassicAssert.Less( sw.ElapsedMilliseconds, 2000,
            "cancellation must wake the parked 5 s wait, not sit through it" );
    }

    private static void WaitForFullPool()
    {
        var waited = 0;

        while ( I2PPrivateKey.PooledKeyCount() < I2PPrivateKey.PoolTargetForTests && waited < 30000 )
        {
            Thread.Sleep( 50 );
            waited += 50;
        }

        ClassicAssert.GreaterOrEqual( I2PPrivateKey.PooledKeyCount(), I2PPrivateKey.PoolTargetForTests,
            "test setup: the pool never filled, so the generator was never parked" );
    }

    /// <summary>
    ///     The batch's verify row: thread count stable across cycles. Restarting has to produce
    ///     exactly one live generator, never a second one alongside a stranded first.
    /// </summary>
    [Test]
    public void RestartingDoesNotAccumulateThreads()
    {
        var baseline = ThreadCount();

        for ( var i = 1; i <= Cycles; i++ )
        {
            I2PPrivateKey.GetNewKeyPair();

            ClassicAssert.IsTrue( I2PPrivateKey.PrecalculationRunning,
                $"cycle {i}: generator should be running" );

            I2PPrivateKey.StopPrecalculation();

            ClassicAssert.IsFalse( I2PPrivateKey.PrecalculationRunning,
                $"cycle {i}: generator should be stopped" );
        }

        // Process thread count is noisy — the pool grows and trims on its own — so this is a
        // leak check, not an equality check. Ten stranded generators would blow well past it.
        ClassicAssert.LessOrEqual( ThreadCount(), baseline + 5,
            $"thread count grew from {baseline} to {ThreadCount()} over {Cycles} cycles" );
    }

    /// <summary>
    ///     A stopped generator must be restartable, or the first Router.Stop() would permanently
    ///     disable precalculation for the process.
    /// </summary>
    [Test]
    public void GeneratorRestartsAfterStop()
    {
        I2PPrivateKey.GetNewKeyPair();
        I2PPrivateKey.StopPrecalculation();

        var keys = I2PPrivateKey.GetNewKeyPair();

        ClassicAssert.IsNotNull( keys.PrivateKey );
        ClassicAssert.IsNotNull( keys.PublicKey );
        ClassicAssert.IsTrue( I2PPrivateKey.PrecalculationRunning,
            "a key pair request after a stop must start a fresh generator" );
    }

    [Test]
    public void StopIsSafeWhenNothingIsRunning()
    {
        I2PPrivateKey.StopPrecalculation();
        I2PPrivateKey.StopPrecalculation();

        ClassicAssert.IsFalse( I2PPrivateKey.PrecalculationRunning );
    }

    private static int ThreadCount()
    {
        using var p = Process.GetCurrentProcess();
        p.Refresh();
        return p.Threads.Count;
    }
}
