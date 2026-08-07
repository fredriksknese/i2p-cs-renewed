using I2PCore.Data;

namespace I2PCore.TunnelLayer;

// Batch 2-6 (docs/PRODUCTION-PLAN.md). DEFAULT_QUANTITY, DEFAULT_OB_EXPL_LENGTH and
// DEFAULT_IB_EXPL_LENGTH used to be mutable public statics. The CLI assigned them at startup and
// nothing ever restored them, so they were process-global configuration that survived
// Router.Stop() and leaked between tests: a fixture that set a 1-hop exploratory length changed
// the tunnels every later fixture built, with the damage depending on execution order.
//
// They are now const -- the compiled-in defaults -- and the configurable values live on
// RouterContext, which is per-router and is discarded by RouterContext.Reset(). Callers that want
// non-default pools pass them in explicitly rather than mutating global state.
public class TunnelPoolSettings
{
    public const int DEFAULT_QUANTITY = 3;
    public const int DEFAULT_OB_EXPL_LENGTH = 2;
    public const int DEFAULT_IB_EXPL_LENGTH = 2;

    /// <summary>
    ///     Hops in a client (non-exploratory) tunnel. Exploratory tunnels are shorter because
    ///     they carry no client traffic.
    /// </summary>
    public const int DEFAULT_CLIENT_LENGTH = 3;

    /// <summary>
    ///     Exploratory pool settings.
    /// </summary>
    /// <param name="isInbound">Direction of the pool.</param>
    /// <param name="quantity">Tunnels to keep in the pool. Defaults to <see cref="DEFAULT_QUANTITY" />.</param>
    /// <param name="length">
    ///     Hops per tunnel. Defaults to <see cref="DEFAULT_IB_EXPL_LENGTH" /> or
    ///     <see cref="DEFAULT_OB_EXPL_LENGTH" /> for the given direction.
    /// </param>
    public TunnelPoolSettings(bool isInbound, int? quantity = null, int? length = null)
    {
        IsInbound = isInbound;
        IsExploratory = true;
        Quantity = quantity ?? DEFAULT_QUANTITY;
        Length = length ?? (isInbound ? DEFAULT_IB_EXPL_LENGTH : DEFAULT_OB_EXPL_LENGTH);
    }

    /// <summary>
    ///     Client pool settings when <paramref name="dest" /> is set, exploratory when it is null.
    /// </summary>
    public TunnelPoolSettings(I2PIdentHash dest, bool isInbound, int? quantity = null, int? length = null)
    {
        IsInbound = isInbound;
        IsExploratory = dest == null;
        Quantity = quantity ?? DEFAULT_QUANTITY;

        if (length.HasValue)
            Length = length.Value;
        else if (IsExploratory)
            Length = isInbound ? DEFAULT_IB_EXPL_LENGTH : DEFAULT_OB_EXPL_LENGTH;
        else
            Length = DEFAULT_CLIENT_LENGTH;
    }

    public int Quantity { get; set; } = DEFAULT_QUANTITY;
    public int BackupQuantity { get; set; } = 0;
    public int Length { get; set; } = DEFAULT_CLIENT_LENGTH;
    public int LengthVariance { get; set; } = 0;
    public bool IsInbound { get; private set; }
    public bool IsExploratory { get; }
    public bool AllowZeroHop { get; set; } = false;
}
