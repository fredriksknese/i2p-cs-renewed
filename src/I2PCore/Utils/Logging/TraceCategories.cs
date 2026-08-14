using System;
using System.Collections.Generic;
using System.Linq;

namespace I2PCore.Utils;

/// <summary>
///     The very high volume tracing categories, one bit each.
/// </summary>
/// <remarks>
///     Batch 6-1 (docs/PRODUCTION-PLAN.md). <b>These were compile-time switches, which is the
///     scheme batch 0-1 removed everywhere else and for the same reason.</b>
///     <para>
///     <c>I2PCore.csproj</c> defined <c>NOLOG_ALL_TUNNEL_TRANSFER</c> and five siblings as inert
///     placeholders; the code was guarded by <c>#if LOG_ALL_TUNNEL_TRANSFER</c>, so switching a
///     category on meant editing the project file and rebuilding. In a fixture that takes half
///     an hour per run, and on a router in the field, that is the same defect 0-1 described:
///     the output you need to diagnose a fault is unreachable in the build you have.
///     </para>
///     <para>
///     A seventh category, <c>LOG_ALL_UPNP</c>, was guarding five call sites and was not in the
///     project file at all — no build of this repository could ever emit it.
///     </para>
///     <para>
///     Selection is now a runtime flags field, <see cref="Logging.EnabledTraces" />, set by the
///     CLI's <c>--log-trace</c>. Emission still costs nothing when a category is off: the call
///     sites bind to an <c>[InterpolatedStringHandler]</c> that tests the bit before the
///     interpolation runs, exactly as batch 0-6 did for <c>LogDebug</c>.
///     </para>
/// </remarks>
[Flags]
public enum TraceCategories
{
    None = 0,

    /// <summary>Was <c>LOG_ALL_TUNNEL_TRANSFER</c>. Per-message tunnel traffic, both directions.</summary>
    TunnelTransfer = 1 << 0,

    /// <summary>Was <c>LOG_ALL_LEASE_MGMT</c>. Garlic decryption, cloves, session tags, leases.</summary>
    LeaseMgmt = 1 << 1,

    /// <summary>Was <c>LOG_ALL_IDENT_LOOKUPS</c>. NetDb lookups started and coalesced.</summary>
    IdentLookups = 1 << 2,

    /// <summary>Was <c>LOG_MUCH_TRANSPORT</c>. Full transport exception detail with stack traces.</summary>
    Transport = 1 << 3,

    /// <summary>Was <c>LOG_TUNNEL_SELECTION</c>. Which tunnel was picked out of which candidates.</summary>
    TunnelSelection = 1 << 4,

    // There is no router-selection category. LOG_ROUTER_SELECTION_HISTORY guarded two fields in
    // NetDb.Query.cs that nothing in the repository read, so switching it on could never have
    // produced a line; batch 6-1 deleted them rather than carry the name forward.

    /// <summary>Was <c>LOG_ALL_UPNP</c>, which no build defined. Full UPnP request/response bodies.</summary>
    Upnp = 1 << 6,

    All = TunnelTransfer | LeaseMgmt | IdentLookups | Transport | TunnelSelection | Upnp
}

/// <summary>
///     Names for <see cref="TraceCategories" /> as they are written on a command line.
/// </summary>
public static class TraceCategoryNames
{
    private static readonly (string Name, TraceCategories Category)[] Table =
    {
        ( "tunnel-transfer", TraceCategories.TunnelTransfer ),
        ( "lease-mgmt", TraceCategories.LeaseMgmt ),
        ( "ident-lookups", TraceCategories.IdentLookups ),
        ( "transport", TraceCategories.Transport ),
        ( "tunnel-selection", TraceCategories.TunnelSelection ),
        ( "upnp", TraceCategories.Upnp ),
        ( "all", TraceCategories.All ),
        ( "none", TraceCategories.None )
    };

    /// <summary>Every name accepted by <see cref="TryParse" />, in the order they are documented.</summary>
    public static IEnumerable<string> All => Table.Select( t => t.Name );

    /// <summary>
    ///     Parse a comma separated list of category names. Returns false and names the first
    ///     unrecognised element rather than silently enabling nothing — a misspelt category that
    ///     quietly produces no output is the failure mode this whole batch exists to remove.
    /// </summary>
    public static bool TryParse( string text, out TraceCategories result, out string unknown )
    {
        result = TraceCategories.None;
        unknown = null;

        if ( string.IsNullOrWhiteSpace( text ) ) return true;

        foreach ( var element in text.Split( ',', StringSplitOptions.RemoveEmptyEntries ) )
        {
            var name = element.Trim().ToLowerInvariant();
            var hit = Table.FirstOrDefault( t => t.Name == name );

            if ( hit.Name is null )
            {
                // Nothing survives a rejected list. Leaving the categories parsed so far in
                // `result` would hand a caller that ignores the return value a half-applied
                // selection, which is a worse outcome than either extreme.
                result = TraceCategories.None;
                unknown = element.Trim();
                return false;
            }

            result |= hit.Category;
        }

        return true;
    }

    /// <summary>The names of the categories set in <paramref name="categories" />, comma separated.</summary>
    public static string Format( TraceCategories categories )
    {
        if ( categories == TraceCategories.None ) return "none";
        if ( categories == TraceCategories.All ) return "all";

        return string.Join( ",", Table
            .Where( t => t.Category != TraceCategories.None
                         && t.Category != TraceCategories.All
                         && ( categories & t.Category ) != 0 )
            .Select( t => t.Name ) );
    }
}
