using System.Threading;

namespace I2PCore.Utils;

public class SuccessRatio
{
    private long FailureCountField;
    private long SuccessCountField;

    public long SuccessCount => Interlocked.Read(ref SuccessCountField);
    public long FailureCount => Interlocked.Read(ref FailureCountField);

    public double Ratio => (double)SuccessCountField / FailureCountField;
    public double Percent => 100.0 * SuccessCountField / (SuccessCountField + FailureCountField);

    public long Success(bool succ)
    {
        return succ ? Success() : Failure();
    }

    public long Success()
    {
        return Interlocked.Increment(ref SuccessCountField);
    }

    public long Failure()
    {
        return Interlocked.Increment(ref FailureCountField);
    }

    public override string ToString()
    {
        return $"Succ: {SuccessCountField}, Fail: {FailureCountField}, Ratio: {Ratio:F2}, {Percent:F2}%";
    }
}