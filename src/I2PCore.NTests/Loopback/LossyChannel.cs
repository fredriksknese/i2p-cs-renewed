using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace I2PTests.Loopback;

/// <summary>
///     An in-memory datagram network between endpoints registered on it, with the impairments a
///     UDP transport has to survive: loss, reordering, delay and an MTU.
///
///     Batch 3-3 (docs/PRODUCTION-PLAN.md).
///
///     Two properties are deliberate and worth preserving:
///
///     <list type="number">
///         <item>
///             <b>No threads and no sockets.</b> <see cref="Send" /> only enqueues;
///             <see cref="Pump" /> delivers. A test therefore controls exactly when the peer
///             sees traffic, and a failure is reproducible rather than a race. This is the
///             whole reason for preferring it over a real socket pair on 127.0.0.1 — loopback
///             UDP essentially never drops, so it cannot exercise the retransmit path at all.
///         </item>
///         <item>
///             <b>Deterministic.</b> Impairments are driven by a seeded <see cref="Random" />,
///             so "fails at 5% loss" means the same 5% on every run. A flaky protocol test is
///             worse than no protocol test: it trains people to re-run it.
///         </item>
///     </list>
///
///     Uses <see cref="Random" /> rather than the CSPRNG on purpose — it models a network, not a
///     key. (<c>CsprngGuardTest</c> only scans <c>src/I2PCore</c>, so this does not trip it.)
/// </summary>
public sealed class LossyChannel
{
    private readonly Dictionary<IPEndPoint, Action<IPEndPoint, byte[]>> _endpoints = new();
    private readonly List<Pending> _inFlight = new();
    private readonly Random _rng;

    /// <param name="seed">Fixes the impairment sequence. Same seed ⇒ same run.</param>
    public LossyChannel(int seed = 1)
    {
        _rng = new Random(seed);
    }

    /// <summary>Fraction of datagrams to drop, 0.0 to 1.0.</summary>
    public double DropProbability { get; set; }

    /// <summary>
    ///     Probability that a datagram is held back one extra pump, which delivers it after a
    ///     datagram sent later. Models reordering without needing a clock.
    /// </summary>
    public double ReorderProbability { get; set; }

    /// <summary>Pumps a datagram waits before it can be delivered. 0 ⇒ delivered by the next Pump.</summary>
    public int DelayPumps { get; set; }

    /// <summary>
    ///     Datagrams larger than this are dropped rather than fragmented, which is what a real
    ///     path with no PMTU discovery does. 0 disables the limit.
    /// </summary>
    public int Mtu { get; set; }

    public int SentCount { get; private set; }
    public int DeliveredCount { get; private set; }
    public int DroppedByLossCount { get; private set; }
    public int DroppedByMtuCount { get; private set; }
    public int ReorderedCount { get; private set; }

    /// <summary>Datagrams accepted but not yet delivered.</summary>
    public int InFlightCount => _inFlight.Count;

    /// <summary>
    ///     Called as (from, to, datagram) for every datagram offered, before loss or MTU is
    ///     applied. Lets a test inspect what a peer actually put on the wire.
    /// </summary>
    public Action<IPEndPoint, IPEndPoint, byte[]> Tap { get; set; }

    /// <summary>Attach an endpoint. <paramref name="deliver" /> is called as (source, datagram).</summary>
    public void Register(IPEndPoint endpoint, Action<IPEndPoint, byte[]> deliver)
    {
        _endpoints[endpoint] = deliver;
    }

    /// <summary>
    ///     Offer a datagram. Applies MTU and loss immediately — a dropped datagram was never
    ///     really "in flight" — and queues whatever survives for <see cref="Pump" />.
    /// </summary>
    public void Send(IPEndPoint from, IPEndPoint to, byte[] data)
    {
        SentCount++;
        Tap?.Invoke(from, to, (byte[])data.Clone());

        if (Mtu > 0 && data.Length > Mtu)
        {
            DroppedByMtuCount++;
            return;
        }

        if (DropProbability > 0 && _rng.NextDouble() < DropProbability)
        {
            DroppedByLossCount++;
            return;
        }

        var wait = DelayPumps;

        if (ReorderProbability > 0 && _rng.NextDouble() < ReorderProbability)
        {
            wait++;
            ReorderedCount++;
        }

        // Copy: the caller may reuse its buffer, and a channel that aliased the sender's array
        // would hide exactly the kind of buffer-reuse bug it should expose.
        _inFlight.Add(new Pending(from, to, (byte[])data.Clone(), wait));
    }

    /// <summary>
    ///     Deliver every datagram whose wait has elapsed, and age the rest. Delivery can enqueue
    ///     more datagrams (a reply); those wait for the following pump, so one Pump is one
    ///     network hop rather than an unbounded cascade.
    /// </summary>
    /// <returns>How many datagrams were delivered.</returns>
    public int Pump()
    {
        var due = _inFlight.Where(p => p.PumpsRemaining <= 0).ToList();
        var rest = _inFlight.Where(p => p.PumpsRemaining > 0).ToList();

        _inFlight.Clear();
        foreach (var p in rest) _inFlight.Add(p with { PumpsRemaining = p.PumpsRemaining - 1 });

        foreach (var p in due)
        {
            if (!_endpoints.TryGetValue(p.To, out var deliver))
                continue; // Nothing listening there — indistinguishable from a black hole.

            DeliveredCount++;
            deliver(p.From, p.Data);
        }

        return due.Count;
    }

    /// <summary>
    ///     Pump until nothing is left in flight or <paramref name="maxPumps" /> is reached.
    ///     Returns true if the channel drained. False means traffic is still being generated —
    ///     for a handshake that will not converge, that is the symptom.
    /// </summary>
    public bool PumpUntilIdle(int maxPumps = 200)
    {
        for (var i = 0; i < maxPumps; i++)
        {
            if (_inFlight.Count == 0) return true;
            Pump();
        }

        return _inFlight.Count == 0;
    }

    public override string ToString()
    {
        return $"LossyChannel sent={SentCount} delivered={DeliveredCount} " +
               $"lost={DroppedByLossCount} overMtu={DroppedByMtuCount} " +
               $"reordered={ReorderedCount} inFlight={InFlightCount}";
    }

    private sealed record Pending(IPEndPoint From, IPEndPoint To, byte[] Data, int PumpsRemaining);
}
