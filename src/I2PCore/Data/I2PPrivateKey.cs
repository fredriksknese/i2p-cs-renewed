using System;
using System.Collections.Generic;
using System.Threading;
using I2PCore.Crypto.MLKEM;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PPrivateKey : I2PKeyType
{
    public I2PPrivateKey(I2PCertificate cert) : base(cert)
    {
        switch (Certificate.PublicKeyType)
        {
            case KeyTypes.X25519:
            case KeyTypes.MLKEM512_X25519:
            case KeyTypes.MLKEM768_X25519:
            case KeyTypes.MLKEM1024_X25519:
                // X25519 key clamping per RFC 7748
                Key = new I2PByteBlock(BufUtils.RandomBytes(32));
                Key[0] &= 248;
                Key[Key.Length - 1] &= 127;
                Key[Key.Length - 1] |= 64;
                break;

            default:
                Key = new I2PByteBlock(BufUtils.RandomBytes(KeySizeBytes));

                // ElGamal / EC keys: ensure high bit set and odd
                Key[0] |= 0x80;
                Key[Key.Length - 1] |= 0x01;
                break;
        }
    }

    public I2PPrivateKey(I2PBufferCursor reader, I2PCertificate cert) : base(reader, cert)
    {
    }

    public override int KeySizeBytes => Certificate.PrivateKeyLength;

    #region Precalculated keys

    // Batch 2-2 (docs/PRODUCTION-PLAN.md). This pool hides the cost of generating ElGamal-2048
    // keypairs (DefaultAsymetricKeyCert is a Null cert, which resolves to ElGamal2048).
    //
    // It had no shutdown path at all: Run() was `while (true)`, so once started the thread ran for
    // the life of the process, waking every 5 s and refilling the pool. IsBackground kept it from
    // blocking process exit, but a host embedding I2PCore and calling Router.Stop() had no way to
    // get its threads back. StopPrecalculation() is now called from Router.Stop().
    //
    // Two races were fixed on the way. The lazy start tested `Worker == null` unsynchronised while
    // also assigning _precalculatedKeys, so two callers could start two threads and leave one of
    // them appending to a list nobody reads. And Run()'s `_precalculatedKeys.Count < 10` was read
    // outside the lock that every mutation takes.
    //
    // Note: nothing in the library calls GetNewKeyPair() today -- only tests do -- so in a stock
    // router this thread never starts. That does not make the shutdown path optional; it makes it
    // the thing that has to be right before anything starts relying on the pool.
    private static readonly object WorkerLock = new();
    private static readonly LinkedList<I2PdhKeyPair> _precalculatedKeys = new();
    private static readonly AutoResetEvent _keyConsumed = new(true);

    protected static Thread Worker;
    private static CancellationTokenSource _workerCancellation;

    private const int PoolTarget = 10;

    /// <summary>
    ///     True while the precalculation thread is alive. Test seam for the Gate 2 checks.
    /// </summary>
    internal static bool PrecalculationRunning
    {
        get
        {
            lock (WorkerLock)
            {
                return Worker is { IsAlive: true };
            }
        }
    }

    public static I2PdhKeyPair GetNewKeyPair()
    {
        EnsurePrecalculationRunning();

        I2PdhKeyPair result;

        lock (_precalculatedKeys)
        {
            if (_precalculatedKeys.Count > 0)
            {
                result = _precalculatedKeys.Last.Value;
                _precalculatedKeys.RemoveLast();
                _keyConsumed.Set();
                return result;
            }
        }

        result.PrivateKey = new I2PPrivateKey(DefaultAsymetricKeyCert);
        result.PublicKey = new I2PPublicKey(result.PrivateKey);
        return result;
    }

    private static void EnsurePrecalculationRunning()
    {
        lock (WorkerLock)
        {
            if (Worker is { IsAlive: true }) return;

            _workerCancellation = new CancellationTokenSource();
            var token = _workerCancellation.Token;

            Worker = new Thread(() => Run(token))
            {
                Name = "DH Key pair generator",
                Priority = ThreadPriority.Lowest,
                IsBackground = true
            };
            Worker.Start();
        }
    }

    /// <summary>
    ///     Stop the precalculation thread and discard the pooled keys. Called by Router.Stop().
    ///     Safe to call when nothing is running, and safe to call twice.
    /// </summary>
    public static void StopPrecalculation()
    {
        Thread worker;
        CancellationTokenSource cancellation;

        lock (WorkerLock)
        {
            worker = Worker;
            cancellation = _workerCancellation;

            Worker = null;
            _workerCancellation = null;
        }

        if (worker != null)
        {
            cancellation?.Cancel();

            // The generator spends most of its life in a 5 s wait; wake it so Stop() is prompt.
            _keyConsumed.Set();

            if (!worker.Join(5000))
                Logging.LogWarning(
                    "I2PPrivateKey: DH key pair generator did not stop within 5 s.");
        }

        cancellation?.Dispose();

        // Unused private key material should not sit in memory across a restart.
        lock (_precalculatedKeys)
        {
            _precalculatedKeys.Clear();
        }
    }

    private static void Run(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                _keyConsumed.WaitOne(5000);

                while (!token.IsCancellationRequested && PooledKeyCount() < PoolTarget)
                {
                    I2PdhKeyPair keys;
                    keys.PrivateKey = new I2PPrivateKey(DefaultAsymetricKeyCert);
                    keys.PublicKey = new I2PPublicKey(keys.PrivateKey);

                    lock (_precalculatedKeys)
                    {
                        _precalculatedKeys.AddFirst(keys);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logging.Log(ex);
        }
        finally
        {
            // Only clear the field if it still refers to this thread: StopPrecalculation() may
            // already have replaced it, and clearing someone else's Worker would strand it.
            lock (WorkerLock)
            {
                if (Worker == Thread.CurrentThread) Worker = null;
            }
        }
    }

    /// <summary>
    ///     Number of keys currently pooled. Test seam: a test that wants the generator parked in
    ///     its wait rather than mid-refill has to be able to see the pool reach its target.
    /// </summary>
    internal static int PooledKeyCount()
    {
        lock (_precalculatedKeys)
        {
            return _precalculatedKeys.Count;
        }
    }

    internal static int PoolTargetForTests => PoolTarget;

    #endregion
}

public struct I2PdhKeyPair
{
    public I2PPrivateKey PrivateKey;
    public I2PPublicKey PublicKey;
}