using System;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Batch 2-3 (docs/PRODUCTION-PLAN.md). <see cref="DaemonHelper" /> shipped fully implemented
///     and with no caller: nothing handled SIGINT, so the runtime terminated the CLI outright and
///     Router.Stop() never ran. The host apps now block on <see cref="DaemonHelper.WaitForShutdown()" />,
///     so these are the guarantees they depend on.
///     <para>
///         Signal delivery itself is not testable in-process — raising SIGINT would take the test
///         runner down with it — so it is verified by running the CLI under
///         <c>timeout -s INT</c>, recorded in the batch's PR.
///     </para>
/// </summary>
[TestFixture]
public class DaemonHelperTest
{
    [Test]
    public void WaitForShutdownBlocksUntilRequested()
    {
        using var daemon = new DaemonHelper();

        ClassicAssert.IsFalse( daemon.WaitForShutdown( TimeSpan.FromMilliseconds( 100 ) ),
            "WaitForShutdown must block while no shutdown has been requested" );

        var released = Task.Run( () =>
        {
            daemon.WaitForShutdown();
            return true;
        } );

        daemon.RequestShutdown();

        ClassicAssert.IsTrue( released.Wait( TimeSpan.FromSeconds( 5 ) ),
            "RequestShutdown must release a thread already blocked in WaitForShutdown" );
    }

    [Test]
    public void RequestShutdownSetsTheFlagAndCancelsTheToken()
    {
        using var daemon = new DaemonHelper();

        ClassicAssert.IsFalse( daemon.IsShuttingDown );
        ClassicAssert.IsFalse( daemon.ShutdownToken.IsCancellationRequested );

        daemon.RequestShutdown();

        ClassicAssert.IsTrue( daemon.IsShuttingDown,
            "the sample main loops poll IsShuttingDown to leave their while loop" );
        ClassicAssert.IsTrue( daemon.ShutdownToken.IsCancellationRequested );
    }

    /// <summary>
    ///     The CLI can be signalled more than once — Ctrl+C followed by SIGTERM, or SIGINT
    ///     followed by ProcessExit, which DaemonHelper also hooks. A second request must not
    ///     throw or start a second shutdown.
    /// </summary>
    [Test]
    public void RepeatedShutdownRequestsAreHarmless()
    {
        using var daemon = new DaemonHelper();

        daemon.RequestShutdown();
        daemon.RequestShutdown();
        daemon.RequestShutdown();

        ClassicAssert.IsTrue( daemon.IsShuttingDown );
        ClassicAssert.IsTrue( daemon.WaitForShutdown( TimeSpan.FromMilliseconds( 100 ) ) );
    }

    [Test]
    public void ShutdownAfterRequestReturnsImmediately()
    {
        using var daemon = new DaemonHelper();

        daemon.RequestShutdown();

        // Already-signalled state must not re-block; the CLI calls WaitForShutdown after
        // handlers are registered, which may be after the signal has already arrived.
        ClassicAssert.IsTrue( daemon.WaitForShutdown( TimeSpan.Zero ) );
    }

    [Test]
    public void ReloadCallbackFiresOnlyWhenInvoked()
    {
        using var daemon = new DaemonHelper();

        var reloads = 0;
        daemon.OnReload( () => Interlocked.Increment( ref reloads ) );

        daemon.RequestShutdown();

        ClassicAssert.AreEqual( 0, reloads,
            "a shutdown must not be mistaken for a config reload" );
    }
}
