using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.TunnelLayer;

public class EndpointTunnel : InboundTunnel
{
    protected I2PIdentHash NextHop;
    public override I2PIdentHash Destination => NextHop;

    /// <summary>
    ///     The previous hop in the tunnel (who sends data to us).
    ///     Set from the transport-level sender of the build request.
    /// </summary>
    public I2PIdentHash ReceiveFrom { get; internal set; }

    public override bool Established
    {
        get => true;
        set => base.Established = value;
    }

    internal I2PTunnelId ResponseTunnelId;
    internal uint ResponseMessageId;

    private readonly I2PByteBlock IvKey;
    private readonly I2PByteBlock LayerKey;

    internal BandwidthLimiter Limiter;

    public EndpointTunnel(ITunnelOwner owner, TunnelConfig config, BuildRequestRecord brrec)
        : base(owner, config, 1)
    {
        Limiter = new BandwidthLimiter(Bandwidth.SendBandwidth, TunnelSettings.EndpointTunnelBitrateLimit);

        ReceiveTunnelId = new I2PTunnelId(brrec.ReceiveTunnel);
        ResponseTunnelId = new I2PTunnelId(brrec.NextTunnel);
        ResponseMessageId = brrec.SendMessageId;

        NextHop = new I2PIdentHash(new I2PBufferCursor(brrec.NextIdent.Hash.Clone()));
        IvKey = brrec.IvKey.Clone();
        LayerKey = brrec.LayerKey.Clone();
    }

    public override IEnumerable<I2PRouterIdentity> TunnelMembers => Enumerable.Empty<I2PRouterIdentity>();

#if LOG_ALL_TUNNEL_TRANSFER
        ItemFilterWindow<HashedItemGroup> FilterMessageTypes =
 new ItemFilterWindow<HashedItemGroup>( TickSpan.Seconds( 30 ), 2 );
#endif

    private readonly PeriodicAction FragBufferReport = new(TickSpan.Seconds(60));

    public override bool Exectue()
    {
        FragBufferReport.Do(delegate
        {
            var fbsize = Reassembler.BufferedFragmentCount;
            Logging.Log("EndpointTunnel: " + Destination.Id32Short + " Fragment buffer size: " + fbsize);
            if (fbsize > 2000) throw new Exception("BufferedFragmentCount > 2000 !"); // Trying to fill my memory?
        });

        return HandleReceiveQueue();
    }


    private readonly TunnelDataFragmentReassembly Reassembler = new();

    protected override void HandleTunnelData(List<TunnelDataMessage> msgs)
    {
        EncryptTunnelMessages(msgs);

        var newmsgs = Reassembler.Process(msgs, out var failed);

        if (failed)
        {
            Logging.LogWarning($"{this}: Reassembler failure. Dropping tunnel.");
            Shutdown();
        }

        var dropped = 0;
        foreach (var one in newmsgs)
        {
            if (Limiter.DropMessage())
            {
                ++dropped;
                continue;
            }

            try
            {
                one.Distribute(this);
            }
            catch (Exception ex)
            {
                Logging.Log("EndpointTunnel", ex);
                throw; // Kill tunnel is strange things happen
            }
        }

#if LOG_ALL_TUNNEL_TRANSFER
            if ( dropped > 0 )
            {
                Logging.LogDebug( () => string.Format( "{0} bandwidth limit. {1} dropped messages. {2}", this, dropped, Bandwidth ) );
            }
#endif

        return;
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

            // The 0 should be visible now
            msg.UpdateFirstDeliveryInstructionPosition();
        }
    }
}