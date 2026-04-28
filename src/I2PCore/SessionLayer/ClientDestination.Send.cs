using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.SessionLayer;

public partial class ClientDestination : IClient
{


    private SendPreconditionState CheckSendPreconditions(I2PIdentHash dest)
    {
        var isLocal = Router.GetClientDestination(dest) != null;

        if (isLocal)
        {
            var ls = MySessions.GetLeaseSet(dest);
            if (ls != null)
            {
                return new SendPreconditionState
                {
                    ClientState = ClientStates.Established,
                    RemoteLeaseSet = ls
                };
            }

            return new SendPreconditionState { ClientState = ClientStates.NoLeases };
        }

        if (InboundEstablishedPool.IsEmpty)
        {
            Logging.LogDebug($"{this}: Inbound established pool is empty.");
            return new SendPreconditionState { ClientState = ClientStates.NoTunnels };
        }

        var outtunnel = SelectOutboundTunnel();

        if (outtunnel is null)
        {
            Logging.LogDebug($"{this}: No established outbound tunnels.");
            return new SendPreconditionState { ClientState = ClientStates.NoTunnels };
        }

        var leaseset = MySessions.GetLeaseSet(dest);

        if (leaseset is null) return new SendPreconditionState { ClientState = ClientStates.NoLeases };

        var l = MySessions.GetTunnelPair(dest, outtunnel);

        if (l is null) return new SendPreconditionState { ClientState = ClientStates.NoLeases };

        Logging.LogDebug($"{this}: CheckSendPreconditions: Using tunnels: {outtunnel} -> {l}");

        return new SendPreconditionState
        {
            ClientState = ClientStates.Established,
            OutTunnel = outtunnel,
            RemoteLease = l,
            RemoteLeaseSet = leaseset
        };
    }

    /// <summary>
    ///     Send cloves to the destination through a local out tunnel
    ///     after encrypting them for the Destination.
    /// </summary>
    /// <returns>The send.</returns>
    /// <param name="dest">The Destination</param>
    /// <param name="cloves">Cloves</param>
    internal ClientStates Send(I2PDestination dest, params GarlicClove[] cloves)
    {
        if (Terminated) throw new InvalidOperationException($"Destination {this} is terminated.");

        var isLocal = Router.GetClientDestination(dest.IdentHash) != null;

        var replytunnel = SelectInboundTunnel();
        if (replytunnel is null && !isLocal)
        {
            Logging.LogWarning($"{this}: Send: No inbound tunnel available for reply.");
            return ClientStates.NoTunnels;
        }

        var remoteleases = MySessions.GetLeaseSet(dest.IdentHash);
        if (remoteleases is null)
        {
            Logging.LogWarning($"{this}: Send: No LeaseSet for {dest.IdentHash.Id32Short}.");
            return ClientStates.NoLeases;
        }

        var remotepubkeys = remoteleases.PublicKeys;

        var keyTypes = string.Join(", ", remotepubkeys.Select(pk => pk.Certificate.PublicKeyType.ToString()));
        var leaseCount = remoteleases.Leases.Count();
        Logging.LogInformation($"{this}: Send: Remote {dest.IdentHash.Id32Short} LeaseSet has " +
                               $"{leaseCount} lease(s), encryption key types: [{keyTypes}]");

        var msg = MySessions.Encrypt(
            dest.IdentHash,
            remotepubkeys,
            replytunnel,
            new List<GarlicClove>(cloves));

        if (msg is null)
        {
            Logging.LogWarning($"{this}: Send: Garlic encryption returned null for {dest.IdentHash.Id32Short}.");
            return ClientStates.NoLeases;
        }

        return Send(dest, msg);
    }

    /// <summary>
    ///     Send a I2NPMessage to the Destination through a local out tunnel.
    /// </summary>
    /// <returns>The send.</returns>
    /// <param name="dest">The Destination</param>
    /// <param name="msg">I2NPMessage</param>
    internal ClientStates Send(I2PDestination dest, I2NpMessage msg)
    {
        return Send(dest.IdentHash, msg);
    }

    /// <summary>
    ///     Send a I2NPMessage to the Destination IdentHash through a local out tunnel.
    /// </summary>
    internal ClientStates Send(I2PIdentHash destHash, I2NpMessage msg)
    {
        if (Terminated) throw new InvalidOperationException($"This Destination {this} is terminated.");

        var localDest = Router.GetClientDestination(destHash);
        if (localDest != null && msg is GarlicMessage garlic)
        {
            Log("Debug", $"Loopback attempt to {destHash.Id32Short} (len={garlic.EgData.Length})");
            var decr = localDest.DecryptGarlic(garlic);
            if (decr != null)
            {
                var cloveTypes = string.Join(", ", decr.Cloves.Select(c => c.Message?.GetType().Name ?? "?"));
                Log("Decrypted", $"Loopback OK: {decr.Cloves.Count} cloves [{cloveTypes}]", destHash.Id32Short);
                // Use ThreadPool to avoid deep recursion (data→ACK→flush→data→ACK...)
                ThreadPool.UnsafeQueueUserWorkItem(_ => localDest.HandleDecryptedGarlic(decr, null), null);
                return ClientStates.Established;
            }

            // Loopback decrypt failed — log diagnostic to BOTH sender and receiver tunnel pages
            var egData = garlic.EgData.ToByteArray();
            var msgFp = egData.Length >= 8 ? BitConverter.ToString(egData, 0, 8) : "?";
            var myPub = localDest.MySessions?.EciesManager?.LocalStaticPublicKey;
            var destPubFp = myPub != null ? BitConverter.ToString(myPub, 0, 8) : "?";
            Log("Error", $"Loopback FAILED to {destHash.Id32Short}: msg[0:8]=[{msgFp}], dest pubkey=[{destPubFp}], len={egData.Length}");
            localDest.Log("Error", $"Loopback FAILED from {Destination.IdentHash.Id32Short}: msg[0:8]=[{msgFp}], my pubkey=[{destPubFp}], len={egData.Length}");

            // Also log Elligator2 diagnostic on failure
            if (egData.Length >= 32)
            {
                var ephEncoded = new byte[32];
                Array.Copy(egData, 0, ephEncoded, 0, 32);
                var ephDecoded = Crypto.Elligator2.Decode(ephEncoded);
                var decodedFp = ephDecoded != null ? BitConverter.ToString(ephDecoded, 0, 8) : "NULL";
                localDest.Log("Error", $"Loopback Elligator2: encoded[0:8]=[{BitConverter.ToString(ephEncoded, 0, 8)}] decoded=[{decodedFp}]");
            }

            return ClientStates.NoLeases;
        }

        var result = CheckSendPreconditions(destHash);

        switch (result.ClientState)
        {
            case ClientStates.Established:
                break;

            case ClientStates.NoTunnels:
                Logging.LogDebug($"{this}: No established tunnels (inbound or outbound) available.");
                return result.ClientState;

            case ClientStates.NoLeases:
                Logging.LogDebug($"{this}: No leases available for {destHash.Id32Short}.");
                LookupDestination(destHash, HandleDestinationLookupResult);
                return result.ClientState;
        }

        // Remote leases getting old?
        var newestlease = result.RemoteLeaseSet.Expire;
        var leasehorizon = newestlease - DateTime.UtcNow;

        if (leasehorizon.TotalSeconds < 0)
        {
            Logging.LogDebug($"{this} Send: Leases for {destHash.Id32Short} have all expired. Looking up.");
            LookupDestination(destHash, HandleDestinationLookupResult);
            return ClientStates.NoLeases;
        }

        if (leasehorizon < MinLeaseLifetime)
        {
            Logging.LogDebug($"{this} Send: Leases for {destHash.Id32Short} is getting old ({leasehorizon}). Looking up.");
            LookupDestination(destHash, HandleDestinationLookupResult);
        }

        Logging.LogInformation($"{this}: Send: Routing garlic via outbound tunnel " +
                               (result.OutTunnel?.TunnelDebugTrace ?? "LOCAL") + " to remote lease " +
                               $"GW={result.RemoteLease?.TunnelGw?.Id32Short ?? "LOCAL"} TunnelId={result.RemoteLease?.TunnelId ?? 0}, " +
                               $"msg type={msg.MessageType}, payload={msg.Payload.Length} bytes");

        if (result.OutTunnel != null && result.RemoteLease != null)
        {
            result.OutTunnel.Send(
                new TunnelMessageTunnel(
                    msg,
                    result.RemoteLease.TunnelGw, result.RemoteLease.TunnelId));
        }

        return ClientStates.Established;
    }

    private class SendPreconditionState
    {
        public ClientStates ClientState;
        public OutboundTunnel OutTunnel;
        public ILease RemoteLease;
        public ILeaseSet RemoteLeaseSet;
    }
}