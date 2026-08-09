using System;
using System.Collections.Generic;
using System.Net;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TransportLayer.SSU2;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace I2PTests.Loopback;

/// <summary>
///     One end of an SSU2 conversation: a <see cref="SSU2Host" /> with its own identity and its
///     own static keys, wired to a <see cref="LossyChannel" /> instead of a UDP socket.
///
///     Batch 3-3 (docs/PRODUCTION-PLAN.md).
///
///     Two peers can exist in one process because the host is built through the internal test
///     constructor, which takes a <see cref="RouterContext" /> and a keypair per instance. Built
///     the normal way, every host reads <c>RouterContext.Inst</c> and the one SSU2 keypair in the
///     process-wide key store, so both ends would be the same router and no handshake is
///     possible. Removing that assumption generally is Phase 8; this is the narrow version.
///
///     Outbound datagrams are diverted by overriding <see cref="SSU2Host.SendPacket" />. Inbound
///     ones go through <see cref="SSU2Host.DispatchPacket" /> — the same entry point the socket
///     receive loop uses — so inbound session creation and trial header decryption are exercised
///     rather than simulated.
/// </summary>
public sealed class LoopbackSSU2Peer
{
    private readonly LoopbackSSU2Host _host;

    private LoopbackSSU2Peer(string name, RouterContext routerContext, IPEndPoint endpoint,
        LossyChannel channel, byte[] priv, byte[] pub, byte[] introKey)
    {
        Name = name;
        RouterContext = routerContext;
        Endpoint = endpoint;

        IntroKey = introKey;
        _host = new LoopbackSSU2Host(routerContext, priv, pub, introKey, endpoint, channel);
        _host.ConnectionCreated += (transport, hash) =>
        {
            Established.Add(transport);
            if (transport is SSU2Session s) Sessions.Add(s);
        };

        channel.Register(endpoint, (from, data) => _host.DispatchPacket(from, data));
    }

    /// <summary>This peer's SSU2 intro key — the header key a remote uses to reach it.</summary>
    public byte[] IntroKey { get; private set; }

    public string Name { get; }
    public RouterContext RouterContext { get; }
    public IPEndPoint Endpoint { get; }
    public I2PRouterInfo MyRouterInfo => RouterContext.MyRouterInfo;

    /// <summary>Sessions this peer has completed a handshake on, in completion order.</summary>
    public List<SSU2Session> Sessions { get; } = new();

    public List<ITransport> Established { get; } = new();

    /// <summary>I2NP messages that reached this peer's data phase.</summary>
    public List<Ii2NpHeader> Received { get; } = new();

    /// <summary>
    ///     Build a peer whose published SSU2 address is <c>127.0.0.1:port</c>.
    ///     The identity is generated in memory — <see cref="RouterContext()" /> calls
    ///     NewIdentity and touches no files, so nothing is persisted and no test needs cleanup.
    /// </summary>
    public static LoopbackSSU2Peer Create(string name, int port, LossyChannel channel)
    {
        var routerContext = new RouterContext
        {
            DefaultUdpPort = port,
            DefaultTcpPort = port,
            DefaultExtAddress = IPAddress.Loopback,
            // Last: the setter calls ApplyNewSettings, which republishes addresses, so the
            // port and external address have to be in place before it runs. Not firewalled,
            // because a firewalled context publishes introducers instead of a directly
            // reachable address and AddSession would then find no "host" option to dial.
            IsFirewalled = false
        };

        var (priv, pub) = GenerateX25519KeyPair();
        var introKey = BufUtils.RandomBytes(32);

        return new LoopbackSSU2Peer(name, routerContext, new IPEndPoint(IPAddress.Loopback, port),
            channel, priv, pub, introKey);
    }

    /// <summary>
    ///     Start an outbound session to <paramref name="remote" /> and hook its data-phase
    ///     events. Registers with the host exactly as TransportProvider would, so replies
    ///     dispatch back to this session by endpoint.
    /// </summary>
    public SSU2Session ConnectTo(LoopbackSSU2Peer remote)
    {
        var session = (SSU2Session)_host.AddSession(remote.MyRouterInfo);
        Assert(session != null, $"{Name}: AddSession returned null — no dialable SSU2 address");

        Observe(session);
        session.Connect();
        return session;
    }

    /// <summary>
    ///     Record data-phase deliveries and establishment on a session. Applied to outbound
    ///     sessions here and to inbound ones as they are created, so both directions are counted.
    ///
    ///     <para>
    ///         <b>Batch 4-0h: establishment is watched per session, not only on the host.</b>
    ///         <c>SSU2Session</c> calls <c>Host.FireConnectionCreated</c> for <em>incoming</em>
    ///         connections only — an outbound session announces itself by raising
    ///         <see cref="SSU2Session.ConnectionEstablished" /> on itself, which is what
    ///         <c>TransportProvider</c> subscribes to. Listening only to the host therefore left
    ///         <see cref="Established" /> permanently empty for the dialling peer, so
    ///         <c>HandshakeCompletesOnACleanChannel</c> asserted something the fixture could not
    ///         observe even once the handshake worked. **A fixture that cannot see success is not
    ///         measuring failure.**
    ///     </para>
    /// </summary>
    public void Observe(SSU2Session session)
    {
        session.DataBlockReceived += (_, header) => Received.Add(header);
        session.ConnectionEstablished += (transport, _) =>
        {
            if (Established.Contains(transport)) return;

            Established.Add(transport);
            if (transport is SSU2Session s && !Sessions.Contains(s)) Sessions.Add(s);
        };
    }

    /// <summary>Attach <see cref="Observe" /> to every session that has appeared so far.</summary>
    public void ObserveNewSessions()
    {
        foreach (var s in Sessions)
        {
            if (_observed.Contains(s)) continue;
            _observed.Add(s);
            Observe(s);
        }
    }

    private readonly HashSet<SSU2Session> _observed = new();

    private static (byte[] priv, byte[] pub) GenerateX25519KeyPair()
    {
        var gen = new X25519KeyPairGenerator();
        gen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var pair = gen.GenerateKeyPair();

        return (((X25519PrivateKeyParameters)pair.Private).GetEncoded(),
            ((X25519PublicKeyParameters)pair.Public).GetEncoded());
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    /// <summary>
    ///     Socket-free <see cref="SSU2Host" />: sends into the channel, and reports its own
    ///     endpoint as the datagram source so the far side attributes traffic correctly.
    /// </summary>
    private sealed class LoopbackSSU2Host : SSU2Host
    {
        private readonly LossyChannel _channel;
        private readonly IPEndPoint _myEndpoint;

        public LoopbackSSU2Host(RouterContext routerContext, byte[] priv, byte[] pub,
            byte[] introKey, IPEndPoint myEndpoint, LossyChannel channel)
            : base(routerContext, priv, pub, introKey)
        {
            _myEndpoint = myEndpoint;
            _channel = channel;
        }

        public override void SendPacket(IPEndPoint destination, byte[] data)
        {
            _channel.Send(_myEndpoint, destination, data);
        }
    }
}
