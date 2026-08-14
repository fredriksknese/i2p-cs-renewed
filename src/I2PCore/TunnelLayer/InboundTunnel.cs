using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.TunnelLayer;

public class InboundTunnel : Tunnel
{
    private readonly PeriodicAction FragBufferReport = new(TickSpan.Seconds(60));
    public readonly int OutTunnelHops;

    private readonly TunnelDataFragmentReassembly Reassembler = new();
    private readonly I2PIdentHash RemoteGateway;

    public readonly uint TunnelBuildReplyMessageId = I2NpMessage.GenerateMessageId();

    internal I2PTunnelId GatewayTunnelId;

    public InboundTunnel(ITunnelOwner owner, TunnelConfig config, int outtunnelhops)
        : base(owner, config)
    {
        OutTunnelHops = outtunnelhops;

        var gw = config.Info.Hops[0];
        RemoteGateway = gw.Peer.IdentHash;
        GatewayTunnelId = gw.TunnelId;

        ReceiveTunnelId = config.Info.Hops.Last().TunnelId;

        Logging.LogTrace( TraceCategories.TunnelTransfer, $"InboundTunnel: Tunnel {Destination?.Id32Short} created." );
    }

    // Fake 0-hop
    protected InboundTunnel(ITunnelOwner owner, TunnelConfig config, I2PIdentHash remotegateway)
        : base(owner, config)
    {
        Established = true;

        ReceiveTunnelId = config.Info.Hops.Any() ? config.Info.Hops.Last().TunnelId : new I2PTunnelId();
        RemoteGateway = remotegateway;
        GatewayTunnelId = ReceiveTunnelId;

        Logging.LogDebug($"{this}: 0-hop tunnel {Destination?.Id32Short} created.");
    }

    public override I2PIdentHash Destination => RemoteGateway;
    public override I2PIdentHash FarEnd => RemoteGateway;

    public override IEnumerable<I2PRouterIdentity> TunnelMembers
    {
        get
        {
            if (Config?.Info is null) return null;
            return Config.Info.Hops.Select(h => (I2PRouterIdentity)h.Peer);
        }
    }

    // Java I2P: flat 5-10s REQUEST_TIMEOUT regardless of hop count or pool type.
    // No per-hop multiplication, no exploratory multiplier.
    public override TickSpan TunnelEstablishmentTimeout => TunnelBuildTimeout;

    public event Action<GarlicMessage> GarlicMessageReceived;

    public override bool Exectue()
    {
        if (Terminated || RemoteGateway == null) return false;

        FragBufferReport.Do(delegate
        {
            var fbsize = Reassembler.BufferedFragmentCount;
            if (fbsize > 0)
            {
                Logging.Log($"{this}: {Destination.Id32Short} Fragment buffer size: {fbsize}");
                if (fbsize > 2000) throw new Exception("BufferedFragmentCount > 2000 !"); // Trying to fill my memory?
            }
        });

        return HandleReceiveQueue() && HandleSendQueue();
    }

    protected virtual bool HandleReceiveQueue()
    {
        List<TunnelDataMessage> tdmsgs = null;

        while (!ReceiveQueue.IsEmpty)
        {
            if (!ReceiveQueue.TryDequeue(out var msg)) continue;

            if (msg.MessageType != I2NpMessage.MessageTypes.TunnelData)
            {
                HandleTunnelMessage(msg);
            }
            else
            {
                if (tdmsgs is null) tdmsgs = new List<TunnelDataMessage>();
                tdmsgs.Add((TunnelDataMessage)msg);
            }
        }

        if (tdmsgs != null) HandleTunnelData(tdmsgs);

        return true;
    }

    protected virtual bool HandleTunnelMessage(I2NpMessage msg)
    {
        Logging.LogTrace( TraceCategories.TunnelTransfer, $"{this} HandleReceiveQueue: {msg.MessageType}" );

        switch (msg.MessageType)
        {
            case I2NpMessage.MessageTypes.TunnelData:
                throw new NotImplementedException($"Should not happen {TunnelDebugTrace}");

            case I2NpMessage.MessageTypes.Garlic:
                var garlic = (GarlicMessage)msg;

                var handler = GarlicMessageReceived;
                if (handler != null)
                {
                    ThreadPool.QueueUserWorkItem(cb => handler(garlic));
                }
                else
                {
                    // No subscriber (e.g. zero-hop tunnel) - route to Router for handling
                    Logging.LogDebug($"{this}: Garlic routed to Router (no subscriber)");
                    Router.HandleI2NpMessageReceived(msg.CreateHeader16, this);
                }

                break;

            default:
                Logging.LogTrace( TraceCategories.TunnelTransfer, $"{this}: HandleReceiveQueue: not handled {msg?.MessageType}" );

                Router.HandleI2NpMessageReceived(msg.CreateHeader16, this);
                break;
        }

        return true;
    }

    protected virtual void HandleTunnelData(List<TunnelDataMessage> msgs)
    {
        DecryptTunnelMessages(msgs);

        var newmsgs = Reassembler.Process(msgs, out var failed);

        if (failed)
        {
            Logging.LogWarning($"{this}: Reassembler failure. Dropping tunnel.");
            Shutdown();
        }

        foreach (var one in newmsgs) one.Distribute(this);
    }

    protected void DecryptTunnelMessages(List<TunnelDataMessage> msgs)
    {
        var cipher = new CbcBlockCipher(new AesEngine());
        List<TunnelDataMessage> failed = null;

        foreach (var msg in msgs)
            try
            {
                for (var i = Config.Info.Hops.Count - 2; i >= 0; --i)
                {
                    var hop = Config.Info.Hops[i];

                    msg.Iv.AesEcbDecrypt(hop.IvKey.Key.ToByteArray());
                    cipher.Decrypt(hop.LayerKey.Key, msg.Iv, msg.EncryptedWindow);
                    msg.Iv.AesEcbDecrypt(hop.IvKey.Key.ToByteArray());
                }

                // The 0 should be visible now
                msg.UpdateFirstDeliveryInstructionPosition();
            }
            catch (Exception ex)
            {
                Logging.Log("DecryptTunnelMessages", ex);

                // Be resiliant to faulty data. Just drop it.
                if (failed == null) failed = new List<TunnelDataMessage>();
                failed.Add(msg);
            }

        if (failed != null)
            foreach (var one in failed)
                while (msgs.Remove(one))
                    ;
    }

    private bool HandleSendQueue()
    {
        return true;
    }

    public I2NpMessage CreateBuildRequest(InboundTunnel replytunnel)
    {
        var vtb = VariableTunnelBuildMessage.BuildInboundTunnel(Config.Info,
            replytunnel.Destination, replytunnel.GatewayTunnelId,
            TunnelBuildReplyMessageId);

        return vtb;
    }

    public override string ToString()
    {
        return $"{base.ToString()} {Destination.Id32Short} {GatewayTunnelId}";
    }
}