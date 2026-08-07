namespace I2PTests;

/// <summary>
///     Category names used with [Category(...)]. They exist as constants so the strings in the
///     test sources and the strings in CI --filter expressions cannot drift apart.
///
///     The unit suite — what CI gates on — is everything EXCEPT these:
///
///         dotnet test src/I2PCore.NTests -c Release --filter \
///           "TestCategory!=Integration&amp;TestCategory!=ScaledNetwork&amp;\
///            TestCategory!=MultiHop&amp;TestCategory!=Experimental"
/// </summary>
public static class TestCategories
{
    /// <summary>Needs a real i2pd process. Self-skips when none is found (see I2PD_PATH).</summary>
    public const string Integration = "Integration";

    /// <summary>Spins up many routers; slow and resource hungry.</summary>
    public const string ScaledNetwork = "ScaledNetwork";

    /// <summary>Multi-hop tunnel tests; slow, and gated on Phase 6.</summary>
    public const string MultiHop = "MultiHop";

    /// <summary>
    ///     Known-failing tests for features that are not expected to work yet. Quarantined
    ///     rather than deleted: the test is the specification of the repair, and the batch
    ///     that fixes the feature un-quarantines it. A test only belongs here with a
    ///     comment naming the batch that owns it.
    /// </summary>
    public const string Experimental = "Experimental";
}
