using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer;

public class TunnelTester
{
    public delegate void TestRunFinishedEventHandler(bool success, TunnelTestResult result, TestRun run);

    public const int RunsPerTest = 5;
    public static readonly TickSpan MaxTestRunTime = TickSpan.Minutes(5);
    public static readonly TickSpan TimeBetweenTests = TickSpan.Minutes(2);
    public static readonly TickSpan PassTestTimePerHop = TickSpan.Milliseconds(5000);

    public static TunnelTester Inst = new();
    protected static Thread Worker;

    private readonly object ExternalEventSync = new();
    private readonly ConcurrentQueue<InboundTunnel> InboundTunnels = new();

    private readonly ConcurrentQueue<OutboundTunnel> OutboundTunnels = new();

    private readonly TimeWindowDictionary<uint, TestProbe> OutstandingProbeIds = new(MaxTestRunTime);

    private readonly TimeWindowDictionary<Tunnel, TestRun> OutstandingTests = new(MaxTestRunTime);
    private readonly bool Terminated = false;

    private readonly TimeWindowDictionary<Tunnel, TunnelTestResult> TestResults = new(TickSpan.Minutes(10));

    private readonly AutoResetEvent TunnelAdded = new(false);

    public TunnelTester()
    {
        Router.DeliveryStatusReceived += Router_DeliveryStatusReceived;

        Worker = new Thread(Run)
        {
            Name = "TunnelTester",
            IsBackground = true
        };
        Worker.Start();
    }

    public event TestRunFinishedEventHandler TestRunFinished;

    private void Run()
    {
        while (!Terminated)
            try
            {
                TunnelAdded.WaitOne(TimeBetweenTests.ToMilliseconds /
                                    (20 * (InboundTunnels.Count + OutboundTunnels.Count + 1)));

                lock (ExternalEventSync)
                {
                    if (InboundTunnels.Count > 0) TestOneInboundTunnel();
                    if (OutboundTunnels.Count > 0) TestOneOutboundTunnel();

                    TestProbe[] timeout = null;

                    timeout = OutstandingProbeIds
                        .Where(p => p.Value.Created.DeltaToNow / p.Value.TotalHops > PassTestTimePerHop)
                        .Select(p => p.Value).ToArray();
                    foreach (var one in timeout) DeliveryStatusTimeOut(one);
                }
            }
            catch (Exception ex)
            {
                Logging.Log(ex);
            }
    }

    private void TestOneInboundTunnel()
    {
        if (InboundTunnels.IsEmpty) return;

        if (!InboundTunnels.TryDequeue(out var intunnel)) return;
        if (!intunnel.Active || intunnel.Metrics.PassedTunnelTest) return;

        InboundTunnels.Enqueue(intunnel);

        var run = OutstandingTests.Get(intunnel);
        if (run != null)
        {
            // Run has finished?
            if (run.TestedPartners.Count >= RunsPerTest)
            {
                if (run.LastRun.DeltaToNow < TimeBetweenTests) return;
                run.OutstandingProbes.Clear();
                run.SuccessPartners.Clear();
                run.TestedPartners.Clear();
            }
        }
        else
        {
            run = new TestRun(intunnel);
            OutstandingTests[intunnel] = run;
        }

        var test = TestResults.Get(intunnel, () => new TunnelTestResult(intunnel));

        if (TunnelProvider.Inst == null) return;

        var outtunnels = BufUtils.Shuffle(TunnelProvider.Inst.GetOutboundTunnels()
                .Where(t => t.Active
                            && !run.FailurePartners.Contains(t)
                            && !run.SuccessPartners.Contains(t)
                            && !run.TestedPartners.Contains(t)))
            .Take(RunsPerTest)
            .ToArray();
        ;

        if (!outtunnels.Any())
            //Logging.LogDebug( "TunnelTester: Failed to get a established outbound tunnel." );
            return;

        run.LastRun.SetNow();

        var tunneldbginfo = "";

        foreach (var outtunnel in outtunnels)
        {
            run.TestedPartners.Add(outtunnel);
            var probe = new TestProbe(intunnel, outtunnel);

            tunneldbginfo += $"({outtunnel.TunnelDebugTrace}:{probe.MessageId})";

            run.OutstandingProbes.Add(probe);
            OutstandingProbeIds[probe.MessageId] = probe;
            outtunnel.Send(new TunnelMessageTunnel(new DeliveryStatusMessage(probe.MessageId), intunnel));
        }

        if (tunneldbginfo.Length > 0)
            Logging.LogDebug(
                $"TunnelTester: Starting inbound tunnel {intunnel.TunnelDebugTrace} test with tunnels: {tunneldbginfo}");
    }

    private void TestOneOutboundTunnel()
    {
        if (OutboundTunnels.IsEmpty) return;

        if (!OutboundTunnels.TryDequeue(out var outtunnel)) return;
        if (!outtunnel.Active || outtunnel.Metrics.PassedTunnelTest) return;
        OutboundTunnels.Enqueue(outtunnel);

        var run = OutstandingTests.Get(outtunnel);
        if (run != null)
        {
            // Run has finished?
            if (run.TestedPartners.Count >= RunsPerTest)
            {
                if (run.LastRun.DeltaToNow < TimeBetweenTests) return;
                run.OutstandingProbes.Clear();
                run.SuccessPartners.Clear();
                run.TestedPartners.Clear();
            }
        }
        else
        {
            run = new TestRun(outtunnel);
            OutstandingTests[outtunnel] = run;
        }

        var test = TestResults.Get(outtunnel, () => new TunnelTestResult(outtunnel));

        if (TunnelProvider.Inst == null) return;

        var intunnels = BufUtils.Shuffle(TunnelProvider.Inst.GetInboundTunnels()
                .Where(t => t.Active
                            && !run.FailurePartners.Contains(t)
                            && !run.SuccessPartners.Contains(t)
                            && !run.TestedPartners.Contains(t)))
            .Take(RunsPerTest * 2)
            .ToArray();

        if (!intunnels.Any())
            //Logging.LogDebug( "TunnelTester: Failed to get a established inbound tunnel." );
            return;

        run.LastRun.SetNow();

        var tunneldbginfo = "";

        foreach (var intunnel in intunnels)
        {
            run.TestedPartners.Add(intunnel);
            var probe = new TestProbe(outtunnel, intunnel);

            tunneldbginfo += $"({intunnel.TunnelDebugTrace}:{probe.MessageId})";

            run.OutstandingProbes.Add(probe);
            OutstandingProbeIds[probe.MessageId] = probe;
            outtunnel.Send(new TunnelMessageTunnel(new DeliveryStatusMessage(probe.MessageId), intunnel));
        }

        if (tunneldbginfo.Length > 0)
            Logging.LogDebug(
                $"TunnelTester: Starting outbound tunnel {outtunnel.TunnelDebugTrace} test with tunnels: {tunneldbginfo}");
    }

    private void Router_DeliveryStatusReceived(DeliveryStatusMessage dstatus, InboundTunnel from)
    {
        var probe = OutstandingProbeIds[dstatus.StatusMessageId];
        if (probe == null) return;

        var run = OutstandingTests[probe.Tunnel];
        if (run == null) return;

        var testms = (DateTime.UtcNow - (DateTime)dstatus.Timestamp).TotalMilliseconds;

        var limit = PassTestTimePerHop.ToMilliseconds * probe.TotalHops;
        var pass = testms < limit;

        Logging.LogDebugData(string.Format(
            "TunnelTester: DeliveryStatus received. Test with {0} and {1}: {2}. {3:0} vs {4} ms",
            run.TunnelUnderTest.TunnelDebugTrace, probe.Partner.TunnelDebugTrace,
            pass ? "Success" : "Fail",
            testms, limit));

        var delta = TickSpan.Milliseconds((int)testms);

        probe.Tunnel.Metrics.UpdateMinLatency(delta);
        probe.Partner.Metrics.UpdateMinLatency(delta);

        lock (ExternalEventSync)
        {
            if (pass)
                run.SuccessPartners.Add(probe.Partner);
            else
                run.FailurePartners.Add(probe.Partner);
            run.OutstandingProbes.Remove(probe);
            OutstandingProbeIds.Remove(probe.MessageId);

            HandleTunnelTestResult(run);
        }
    }

    private void DeliveryStatusTimeOut(TestProbe probe)
    {
        OutstandingProbeIds.Remove(probe.MessageId);

        var run = OutstandingTests[probe.Tunnel];
        if (run == null) return;

        Logging.LogDebug($"TunnelTester: Test with {run.TunnelUnderTest.TunnelDebugTrace}" +
                         $" and {probe.Partner.TunnelDebugTrace} timeout.");

        run.OutstandingProbes.Remove(probe);
        run.FailurePartners.Add(probe.Partner);

        lock (ExternalEventSync)
        {
            HandleTunnelTestResult(run);
        }
    }

    private void HandleTunnelTestResult(TestRun run)
    {
        if (run.OutstandingProbes.Count > 0) return;

        var testresult = TestResults.Get(run.TunnelUnderTest, () => new TunnelTestResult(run.TunnelUnderTest));

        var resultcount = run.SuccessPartners.Count + run.FailurePartners.Count + testresult.Pass + testresult.Fail;

        // Test run finished?
        if (resultcount < RunsPerTest) return;

        testresult.Pass += run.SuccessPartners.Count;
        testresult.Fail += run.FailurePartners.Count;

        // Collect statistics for the partner tunnel
        foreach (var onepartner in run.SuccessPartners)
        {
            foreach (var onehop in onepartner.TunnelMembers)
                NetDb.Inst.Statistics.SuccessfulTunnelTest(onehop.IdentHash);

            var partnertestresult = TestResults.Get(onepartner, () => new TunnelTestResult(onepartner));
            ++partnertestresult.Pass;
        }

        foreach (var onepartner in run.FailurePartners)
        {
            foreach (var onehop in onepartner.TunnelMembers) NetDb.Inst.Statistics.FailedTunnelTest(onehop.IdentHash);

            var partnertestresult = TestResults.Get(onepartner, () => new TunnelTestResult(onepartner));
            ++partnertestresult.Fail;
        }

        // Success
        if (testresult.Pass > 0 && testresult.Pass * 2 >= testresult.Fail)
        {
            Logging.LogDebug($"TunnelTester: Run result: Tunnel {run.TunnelUnderTest} passed tests. " +
                             $"Successes: {testresult.Pass}, Failures {testresult.Fail}.");

            run.TunnelUnderTest.Metrics.PassedTunnelTest = true;
            Interlocked.Exchange(ref run.TunnelUnderTest.TestFailures, 0);

            foreach (var onehop in run.TunnelUnderTest.TunnelMembers)
                NetDb.Inst.Statistics.SuccessfulTunnelTest(onehop.IdentHash);

            if (TestRunFinished != null) ThreadPool.QueueUserWorkItem(a => TestRunFinished(true, testresult, run));

            return;
        }

        // Fail and remove
        foreach (var onehop in run.TunnelUnderTest.TunnelMembers)
            NetDb.Inst.Statistics.FailedTunnelTest(onehop.IdentHash);

        Logging.LogDebug($"TunnelTester: Run result: Tunnel {run.TunnelUnderTest} failed tests and is removed. " +
                         $"Successes: {testresult.Pass}, Failures {testresult.Fail}.");

        if (TunnelProvider.Inst != null)
            TunnelProvider.Inst.TunnelTestFailed(run.TunnelUnderTest);

        if (TestRunFinished != null) ThreadPool.QueueUserWorkItem(a => TestRunFinished(false, testresult, run));
    }

    public void Test(OutboundTunnel tunnel)
    {
        if (tunnel == null) return;

        var test = TestResults.Get(tunnel);
        if (test != null && test.Pass > 0) return;
        if (OutstandingTests.Get(tunnel) != null) return;

        OutboundTunnels.Enqueue(tunnel);

        TunnelAdded.Set();
    }

    public void Test(InboundTunnel tunnel)
    {
        if (tunnel == null) return;

        var test = TestResults.Get(tunnel);
        if (test != null && test.Pass > 0) return;
        if (OutstandingTests.Get(tunnel) != null) return;

        InboundTunnels.Enqueue(tunnel);

        TunnelAdded.Set();
    }

    public class TunnelTestResult
    {
        public readonly TickCounter Created = TickCounter.Now;
        public readonly Tunnel TestedTunnel;
        public int Fail;
        public int Pass;

        internal TunnelTestResult(Tunnel tunnel)
        {
            TestedTunnel = tunnel;
        }
    }

    public class TestProbe
    {
        public readonly TickCounter Created = TickCounter.Now;
        public readonly uint MessageId;
        public readonly Tunnel Partner;
        public readonly int TotalHops;
        public readonly Tunnel Tunnel;

        public TestProbe(Tunnel tunnel, Tunnel partner)
        {
            Tunnel = tunnel;
            Partner = partner;
            MessageId = I2NpMessage.GenerateMessageId();
            TotalHops = Tunnel.Config.Info.Hops.Count + Partner.Config.Info.Hops.Count;
        }
    }

    public class TestRun
    {
        public readonly HashSet<Tunnel> FailurePartners = new();

        public readonly List<TestProbe> OutstandingProbes = new();
        public readonly HashSet<Tunnel> SuccessPartners = new();
        public readonly HashSet<Tunnel> TestedPartners = new();

        public readonly Tunnel TunnelUnderTest;
        public TickCounter Created = TickCounter.Now;
        public TickCounter LastRun = TickCounter.MaxDelta;

        internal TestRun(Tunnel testtunnel)
        {
            TunnelUnderTest = testtunnel;
        }
    }
}