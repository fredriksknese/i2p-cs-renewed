using System.Diagnostics;
using I2PCore;
using I2PCore.Data;
using I2PCore.Utils;
using I2PRouterWeb.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class NetDbLookupModel : PageModel
{
    private readonly RouterService _routerService;

    public NetDbLookupModel(RouterService routerService)
    {
        _routerService = routerService;
    }

    [BindProperty] public string B32Address { get; set; } = string.Empty;

    [BindProperty] public int ParallelQueries { get; set; } = 6;

    [BindProperty] public bool DirectLookup { get; set; } = false;

    public bool IsLookupInProgress { get; set; }
    public string? ErrorMessage { get; set; }
    public LeaseSetResult? Result { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrWhiteSpace(B32Address))
        {
            ErrorMessage = "Please enter a b32 address.";
            return Page();
        }

        var addr = B32Address.Trim().ToLowerInvariant();
        if (!addr.EndsWith(".b32.i2p"))
        {
            if (!addr.Contains("."))
                addr += ".b32.i2p";
            else if (addr.EndsWith(".b32"))
                addr += ".i2p";
        }

        B32Address = addr;

        if (!_routerService.IsRunning)
        {
            ErrorMessage = "Router is not running.";
            return Page();
        }

        try
        {
            var sw = Stopwatch.StartNew();
            var identHash = new I2PIdentHash(addr);

            // Check cache first
            var cachedLs = NetDb.Inst?.FindLeaseSet(identHash);
            if (cachedLs != null && cachedLs.Expire > DateTime.UtcNow)
            {
                sw.Stop();
                Result = BuildResult(cachedLs, sw.ElapsedMilliseconds, identHash, null);
                _routerService.LogActivity("NetDbLookup", $"Cache hit for {identHash.Id64}");
                return Page();
            }

            // Start async lookup via floodfills through IdentResolver
            var tcs = new TaskCompletionSource<(ILeaseSet? ls, IdentResolver.IdentUpdateRequestInfo? info)>();

            // Subscribe to the LeaseSet event temporarily
            IdentResolver.IdentResolverResultLeaseSetEx successHandler = null;
            IdentResolver.IdentResolverResultFailEx failHandler = null;

            successHandler = (ls, info) =>
            {
                if (ls?.Destination?.IdentHash == identHash)
                {
                    NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx -= successHandler;
                    NetDb.Inst.IdentHashLookup.LookupFailureEx -= failHandler;
                    tcs.TrySetResult((ls, info));
                }
            };

            failHandler = (key, info) =>
            {
                if (key == identHash)
                {
                    NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx -= successHandler;
                    NetDb.Inst.IdentHashLookup.LookupFailureEx -= failHandler;
                    tcs.TrySetResult((null, info));
                }
            };

            NetDb.Inst.IdentHashLookup.LeaseSetReceivedEx += successHandler;
            NetDb.Inst.IdentHashLookup.LookupFailureEx += failHandler;
            NetDb.Inst.IdentHashLookup.LookupLeaseSet(identHash, null, ParallelQueries, DirectLookup);

            // Wait up to 30 seconds
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                var (ls, info) = await tcs.Task.WaitAsync(cts.Token);
                sw.Stop();

                if (ls != null && ls.Expire > DateTime.UtcNow)
                {
                    Result = BuildResult(ls, sw.ElapsedMilliseconds, identHash, info);
                    _routerService.LogActivity("NetDbLookup",
                        $"Found LeaseSet for {identHash.Id64} in {sw.ElapsedMilliseconds}ms");
                }
                else
                {
                    Result = BuildResult(null, sw.ElapsedMilliseconds, identHash, info);
                    ErrorMessage =
                        $"LeaseSet lookup returned no valid result for {identHash.Id64} after {sw.ElapsedMilliseconds}ms.";
                }
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                var info = NetDb.Inst.IdentHashLookup.GetQueryInfo(identHash);
                Result = BuildResult(null, sw.ElapsedMilliseconds, identHash, info);

                // Check if lookup failed due to no tunnels being available
                var noTunnels = false;
                if (info?.Attempts != null)
                    lock (info.Attempts)
                    {
                        noTunnels = info.Attempts.Any(a =>
                            a.Details != null && a.Details.Contains("no tunnels available"));
                    }

                if (noTunnels)
                    ErrorMessage = $"No exploratory tunnels available for LeaseSet lookup of {identHash.Id64}. " +
                                   "The router needs active inbound and outbound tunnels to query floodfill routers. " +
                                   "Check the Tunnels page to verify tunnel status.";
                else
                    ErrorMessage = $"LeaseSet lookup timed out after 30 seconds for {identHash.Id64}. " +
                                   "The destination may be offline or unreachable.";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
            _routerService.LogActivity("Error", $"NetDB lookup error: {ex.Message}");
        }

        return Page();
    }

    private static LeaseSetResult BuildResult(ILeaseSet? ls, long lookupMs, I2PIdentHash hash,
        IdentResolver.IdentUpdateRequestInfo? info)
    {
        var result = new LeaseSetResult
        {
            DestinationHash = BufUtils.ToBase32String(hash.Hash) + ".b32.i2p",
            LeaseSetType = ls?.GetType().Name ?? "None",
            Expiration = ls?.Expire.ToString("yyyy-MM-dd HH:mm:ss UTC") ?? "N/A",
            LookupTimeMs = lookupMs,
            Leases = new List<LeaseInfo>()
        };

        if (ls?.Leases != null)
            foreach (var lease in ls.Leases)
                result.Leases.Add(new LeaseInfo
                {
                    GatewayHash = lease.TunnelGw?.Id64Short ?? "unknown",
                    TunnelId = lease.TunnelId?.ToString() ?? "?",
                    EndDate = lease.Expire.ToString("yyyy-MM-dd HH:mm:ss UTC")
                });

        if (ls?.PublicKeys != null)
            foreach (var key in ls.PublicKeys)
                result.EncryptionKeys.Add(new EncryptionKeyInfo
                {
                    KeyType = key.Certificate.PublicKeyType.ToString(),
                    KeySizeBytes = key.KeySizeBytes
                });

        if (info != null)
        {
            List<IdentResolver.LookupAttempt> attempts;
            lock (info.Attempts)
            {
                attempts = info.Attempts.ToList();
            }

            foreach (var attempt in attempts)
            {
                var attInfo = new LookupAttemptInfo
                {
                    StartMs = TickCounter.TimeDelta(attempt.Start, info.Start).ToMilliseconds,
                    OutboundTunnel = attempt.OutboundTunnelGateway != null
                        ?
                        $"{attempt.OutboundTunnelGateway.Id64Short} (ID: {attempt.OutboundTunnelId})"
                        : attempt.Details != null
                            ? "None"
                            : "Direct",
                    InboundTunnel = attempt.InboundTunnelGateway != null
                        ? $"{attempt.InboundTunnelGateway.Id64Short} (ID: {attempt.InboundTunnelId})"
                        : "None",
                    Details = attempt.Details
                };

                foreach (var ff in attempt.FloodfillResponses)
                    attInfo.Floodfills.Add(new FloodfillStatusInfo
                    {
                        Floodfill = ff.Key.Id64Short,
                        Response = ff.Value.Response.ToString(),
                        Details = ff.Value.Details
                    });
                result.History.Add(attInfo);
            }
        }

        return result;
    }
}

public class LeaseSetResult
{
    public string DestinationHash { get; set; } = string.Empty;
    public string LeaseSetType { get; set; } = string.Empty;
    public string Expiration { get; set; } = string.Empty;
    public long LookupTimeMs { get; set; }
    public List<LeaseInfo> Leases { get; set; } = new();
    public List<EncryptionKeyInfo> EncryptionKeys { get; set; } = new();
    public List<LookupAttemptInfo> History { get; set; } = new();
}

public class LookupAttemptInfo
{
    public long StartMs { get; set; }
    public string OutboundTunnel { get; set; } = string.Empty;
    public string InboundTunnel { get; set; } = string.Empty;
    public string? Details { get; set; }
    public List<FloodfillStatusInfo> Floodfills { get; set; } = new();
}

public class FloodfillStatusInfo
{
    public string Floodfill { get; set; } = string.Empty;
    public string Response { get; set; } = string.Empty;
    public string? Details { get; set; }
}

public class EncryptionKeyInfo
{
    public string KeyType { get; set; } = string.Empty;
    public int KeySizeBytes { get; set; }
}

public class LeaseInfo
{
    public string GatewayHash { get; set; } = string.Empty;
    public string TunnelId { get; set; } = string.Empty;
    public string EndDate { get; set; } = string.Empty;
}