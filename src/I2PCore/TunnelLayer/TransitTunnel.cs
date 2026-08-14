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

    /// <summary>
    ///     One line per tunnel message as it crosses this hop, before and after our layer crypto.
    /// </summary>
    /// <remarks>
    ///     Batch 6-1 (docs/PRODUCTION-PLAN.md). This is the tracing the batch exists for, and the
    ///     shape is chosen to answer one question the session-6 log could not:
    ///     <b>a hop that preserves length and destroys content</b> — every byte of a 5 MB
    ///     transfer arriving, none of it matching what was sent.
    ///     <para>
    ///     A transit hop cannot see plaintext, so digesting our input against our output proves
    ///     nothing on its own: they are <i>supposed</i> to differ, that is what the layer crypto
    ///     does. What is diagnostic is that the digest we log on the way out is the digest the
    ///     <i>next</i> hop logs on the way in. That makes one message followable across two
    ///     routers' logs, and it localises a corruption to a hop rather than to a transfer. The
    ///     IV is digested too because it is transformed either side of the window
    ///     (<see cref="EncryptTunnelMessages" />) and a wrong IV is indistinguishable from a
    ///     wrong key by content alone.
    ///     </para>
    ///     <para>
    ///     <see cref="BufUtils.ComputeHash(System.ReadOnlySpan{byte})" /> is FNV-1a, not a
    ///     cryptographic digest. It is a correlation handle, and cheap enough to sit in this
    ///     path — which it only ever does with the category switched on.
    ///     </para>
    /// </remarks>
    private void TraceTunnelData(string stage, I2PTunnelId tunnelid, List<TunnelDataMessage> msgs)
    {
        if (!Logging.IsTraceEnabled(TraceCategories.TunnelTransfer)) return;

        foreach (var one in msgs)
            Logging.LogTrace(TraceCategories.TunnelTransfer,
                $"TransitTunnel {TunnelDebugTrace} {stage}: tunnel {tunnelid} {one.Payload.Length}B iv {one.Iv.Span.ComputeHash():X8} window {one.EncryptedWindow.Span.ComputeHash():X8}");
    }

    protected override void HandleTunnelData(List<TunnelDataMessage> msgs)
    {
        // Both sides of the layer crypto, so the pair identifies this hop's transformation.
        TraceTunnelData($"recv from {ReceiveFrom?.Id32Short ?? "[unknown]"}", ReceiveTunnelId, msgs);
        EncryptTunnelMessages(msgs);
        TraceTunnelData($"send to {Destination.Id32Short}", SendTunnelId, msgs);

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

        if (dropped > 0)
            Logging.LogTrace(TraceCategories.TunnelTransfer,
                $"{this} bandwidth limit. {dropped} dropped messages. {Bandwidth}");

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
        }
    }
}