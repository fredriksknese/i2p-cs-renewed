using I2P.I2CP.Messages;
using I2PCore;
using I2PCore.Utils;

namespace I2P.I2CP.States;

public abstract class I2CpState
{
    public static readonly TickSpan InactivityTimeout = TickSpan.Minutes(20);
    public static readonly TickSpan HandshakeTimeout = TickSpan.Seconds(30);
    public static readonly TickSpan EstablishedDestinationTimeout = TickSpan.Seconds(150);

    public TickCounter Created = TickCounter.Now;
    public TickCounter LastAction = TickCounter.Now;
    public int Retries = 0;

    protected I2CpSession Session;

    protected I2CpState(I2CpSession sess)
    {
        Session = sess;
    }

    protected bool Timeout(TickSpan timeout)
    {
        return LastAction.DeltaToNow > timeout;
    }

    protected void DataSent()
    {
        LastAction.SetNow();
    }

    internal virtual I2CpState Run()
    {
        if (Timeout(HandshakeTimeout))
            throw new FailedToConnectException($"{this} WaitProtVer {Session.DebugId} Failed to connect. Timeout.");

        return this;
    }

    internal abstract I2CpState MessageReceived(I2CpMessage msg);

    public override string ToString()
    {
        return $"{Session} {GetType().Name}";
    }
}