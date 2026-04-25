using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.TunnelLayer;

public class TransitTunnel : InboundTunnel
{
    protected I2PIdentHash NextHop;
    public override I2PIdentHash Destination => NextHop;

    /// <summary>
    ///     The previous hop in the tunnel (who sends data to us).
    ///     Set from the transport-level sender of the build request.
    /// </summary>
    public I2PIdentHash ReceiveFrom { get; internal set; }

    internal I2PTunnelId SendTunnelId;

    private readonly I2PByteBlock IvKey;
    private readonly I2PByteBlock LayerKey;

    public override bool Established
    {
        get => true;
        set => base.Established = value;
    }

    internal BandwidthLimiter Limiter;

    public TransitTunnel(ITunnelOwner owner, TunnelConfig config, BuildRequestRecord brrec)
        : base(owner, config, 1)
    {
        Limiter = new BandwidthLimiter(Bandwidth.SendBandwidth, TunnelSettings.TransitTunnelBitrateLimit);

        ReceiveTunnelId = new I2PTunnelId(brrec.ReceiveTunnel);
        NextHop = new I2PIdentHash(new I2PBufferCursor(brrec.NextIdent.Hash.Clone()));
        SendTunnelId = new I2PTunnelId(brrec.NextTunnel);

        IvKey = brrec.IvKey.Clone();
        LayerKey = brrec.LayerKey.Clone();
    }

    public override IEnumerable<I2PRouterIdentity> TunnelMembers => Enumerable.Empty<I2PRouterIdentity>();

    public override bool Exectue()
    {
        return HandleReceiveQueue();
    }

#if LOG_ALL_TUNNEL_TRANSFER
        ItemFilterWindow<HashedItemGroup> FilterMessageTypes =
 new ItemFilterWindow<HashedItemGroup>( TickSpan.Seconds( 30 ), 2 );
#endif

    private bool HandleReceiveQueue()
    {
        var tdmsgs = new List<TunnelDataMessage>();

        if (ReceiveQueue.IsEmpty) return true;

        while (ReceiveQueue.TryDequeue(out var message))
            if (message.MessageType == I2NpMessage.MessageTypes.TunnelData)
                // Just drop the non-TunnelData
                tdmsgs.Add((TunnelDataMessage)message);

        if (tdmsgs.Any()) return HandleTunnelData(tdmsgs);

        return true;
    }

#if LOG_ALL_TUNNEL_TRANSFER
        PeriodicLogger LogDataSent = new PeriodicLogger( 15 );
#endif

    private bool HandleTunnelData(IEnumerable<TunnelDataMessage> msgs)
    {
        EncryptTunnelMessages(msgs);

#if LOG_ALL_TUNNEL_TRANSFER
            LogDataSent.Log( () => "TransitTunnel " + Destination.Id32Short + " TunnelData sent." );
#endif
        var dropped = 0;
        foreach (var one in msgs)
        {
            if (Limiter.DropMessage())
            {
                ++dropped;
                continue;
            }

            // Check global transit bandwidth limit
            if (RouterContext.Inst.ShouldDropTransit())
            {
                ++dropped;
                continue;
            }

            one.TunnelId = SendTunnelId;
            Bandwidth.DataSent(one.Payload.Length);
            RouterContext.Inst.RecordTransitBytes(one.Payload.Length);
            TransportProvider.Send(Destination, one);
        }

#if LOG_ALL_TUNNEL_TRANSFER
            if ( dropped > 0 )
            {
                Logging.LogDebug( () => string.Format( "{0} bandwidth limit. {1} dropped messages. {2}", this, dropped, Bandwidth ) );
            }
#endif

        return true;
    }

    private void EncryptTunnelMessages(IEnumerable<TunnelDataMessage> msgs)
    {
        var cipher = new CbcBlockCipher(new AesEngine());

        foreach (var msg in msgs)
        {
            msg.Iv.AesEcbEncrypt(IvKey.ToByteArray());

            cipher.Init(true, LayerKey.ToParametersWithIv(msg.Iv));
            cipher.ProcessBytes(msg.EncryptedWindow);

            msg.Iv.AesEcbEncrypt(IvKey.ToByteArray());
        }
    }
}