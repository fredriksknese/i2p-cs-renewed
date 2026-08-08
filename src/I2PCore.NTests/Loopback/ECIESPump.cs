using System;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.SessionLayer.ECIES;

namespace I2PTests.Loopback;

/// <summary>
///     Two <see cref="ECIESSessionKeyManager" /> instances wired directly to each other — the
///     bytes one produces are handed straight to the other, with no garlic, no tunnels, no
///     NetDb, no router and no clock.
///
///     Batch 3-4 (docs/PRODUCTION-PLAN.md).
///
///     <para>
///         <b>The handshake is driven the way production drives it.</b> A responder does not
///         answer a New Session inside <c>ProcessMessage</c> — that call only decrypts the
///         payload and records a pending handshake. The reply is a separate, explicit
///         <c>CreateHandshakeReply(remoteHash, originalNewSessionBytes, replyPayload)</c>, which
///         <c>Session.cs</c> makes when it next has something to send. A fixture that skipped
///         that step would find no session tags were ever created and would blame the wrong
///         thing, so <see cref="Handshake" /> reproduces the real three-step exchange.
///     </para>
///     <para>
///         <b>Identity hashes are not symmetric here, deliberately.</b> The initiator addresses
///         the responder by its real <see cref="I2PIdentHash" />, but the responder identifies
///         the initiator by <c>SHA256(static key)</c>, because a New Session carries a static key
///         and not a destination. Production reconciles that later via
///         <c>ConfirmRemoteHash</c>. The pump keeps both names and uses whichever the local side
///         knows, rather than papering over the asymmetry.
///     </para>
/// </summary>
public sealed class ECIESPump
{
    private ECIESPump(Peer alice, Peer bob)
    {
        Alice = alice;
        Bob = bob;
    }

    public Peer Alice { get; }
    public Peer Bob { get; }

    /// <summary>New Session bytes, kept because the responder needs them again to reply.</summary>
    private byte[] _newSessionBytes;

    /// <summary>How Bob refers to Alice: SHA256 of her static key, not her real ident hash.</summary>
    public I2PIdentHash AliceHashAtBob { get; private set; }

    public static ECIESPump Create()
    {
        return new ECIESPump(Peer.Create("Alice"), Peer.Create("Bob"));
    }

    /// <summary>
    ///     Run the full New Session / New Session Reply exchange. Both payloads are carried and
    ///     returned so a test can assert the handshake moves data, not just state.
    /// </summary>
    public (byte[] atBob, byte[] atAlice) Handshake(byte[] requestPayload, byte[] replyPayload)
    {
        _newSessionBytes = Alice.Keys.CreateNewSession(
            Bob.Destination.IdentHash, Bob.PublicKey, requestPayload);

        var atBob = Bob.Keys.ProcessMessage(_newSessionBytes);
        if (!atBob.Success)
            throw new InvalidOperationException($"Responder rejected the New Session: {atBob.Error}");

        AliceHashAtBob = atBob.RemoteDestination;

        var nsr = Bob.Keys.CreateHandshakeReply(AliceHashAtBob, _newSessionBytes, replyPayload);

        var atAlice = Alice.Keys.ProcessMessage(nsr);
        if (!atAlice.Success)
            throw new InvalidOperationException($"Initiator rejected the New Session Reply: {atAlice.Error}");

        return (atBob.Payload, atAlice.Payload);
    }

    /// <summary>
    ///     Send one Existing Session message from <paramref name="from" /> to
    ///     <paramref name="to" /> and return the payload the far side recovered.
    /// </summary>
    public byte[] Send(Peer from, Peer to, byte[] payload)
    {
        var remoteHash = ReferenceEquals(from, Alice) ? Bob.Destination.IdentHash : AliceHashAtBob;

        var message = from.Keys.CreateExistingSession(remoteHash, payload);
        var received = to.Keys.ProcessMessage(message.ToByteArray());

        if (!received.Success)
            throw new InvalidOperationException($"Existing Session message rejected: {received.Error}");

        return received.Payload;
    }

    /// <summary>
    ///     Push <paramref name="count" /> messages one way, stopping at the first that does not
    ///     make it. Returns how many arrived intact and why it stopped, so a test can report the
    ///     boundary rather than just "it threw".
    /// </summary>
    public (int delivered, string stoppedBecause) SendMany(Peer from, Peer to, int count)
    {
        for (var i = 0; i < count; i++)
            try
            {
                var payload = BitConverter.GetBytes(i);
                var received = Send(from, to, payload);

                if (received == null || received.Length != payload.Length)
                    return (i, $"message {i} came back as {received?.Length.ToString() ?? "null"} bytes");

                for (var b = 0; b < payload.Length; b++)
                    if (received[b] != payload[b])
                        return (i, $"message {i} came back corrupted");
            }
            catch (Exception ex)
            {
                return (i, $"{ex.GetType().Name}: {ex.Message}");
            }

        return (count, null);
    }

    /// <summary>One end: a destination, its X25519 static keypair, and its key manager.</summary>
    public sealed class Peer
    {
        private Peer(string name, I2PDestinationInfo info, I2PPublicKey publicKey, ECIESSessionKeyManager keys)
        {
            Name = name;
            Info = info;
            PublicKey = publicKey;
            Keys = keys;
        }

        public string Name { get; }
        public I2PDestinationInfo Info { get; }
        public I2PPublicKey PublicKey { get; }
        public ECIESSessionKeyManager Keys { get; }
        public I2PDestination Destination => Info.Destination;

        /// <summary>
        ///     Built exactly as <c>SessionManager.GenerateTemporaryKeys</c> builds it: one
        ///     X25519 keypair, the public half handed to the manager alongside the destination.
        /// </summary>
        public static Peer Create(string name)
        {
            var info = new I2PDestinationInfo(
                I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519,
                I2PKeyType.KeyTypes.X25519);

            var publicKey = new I2PPublicKey(info.PrivateKey);

            var keys = new ECIESSessionKeyManager(
                info.Destination,
                info.PrivateKey.ToByteArray(),
                publicKey.ToByteArray());

            return new Peer(name, info, publicKey, keys);
        }
    }
}
