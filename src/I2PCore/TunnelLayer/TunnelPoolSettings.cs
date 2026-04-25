using I2PCore.Data;

namespace I2PCore.TunnelLayer;

public class TunnelPoolSettings
{
    public const int DEFAULT_QUANTITY = 3;
    public const int DEFAULT_OB_EXPL_LENGTH = 2;
    public const int DEFAULT_IB_EXPL_LENGTH = 2;

    public TunnelPoolSettings(bool isInbound)
    {
        IsInbound = isInbound;
        IsExploratory = true;
        Quantity = DEFAULT_QUANTITY;
        Length = isInbound ? DEFAULT_IB_EXPL_LENGTH : DEFAULT_OB_EXPL_LENGTH;
    }

    public TunnelPoolSettings(I2PIdentHash dest, bool isInbound)
    {
        IsInbound = isInbound;
        IsExploratory = dest == null;
        Quantity = DEFAULT_QUANTITY;
        if (IsExploratory)
            Length = isInbound ? DEFAULT_IB_EXPL_LENGTH : DEFAULT_OB_EXPL_LENGTH;
        else
            Length = 3;
    }

    public int Quantity { get; set; } = 3;
    public int BackupQuantity { get; set; } = 0;
    public int Length { get; set; } = 3;
    public int LengthVariance { get; set; } = 0;
    public bool IsInbound { get; private set; }
    public bool IsExploratory { get; }
    public bool AllowZeroHop { get; set; } = false;
}