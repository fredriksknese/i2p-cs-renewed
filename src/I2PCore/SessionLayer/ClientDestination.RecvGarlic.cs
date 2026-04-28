using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using I2PCore.Data;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.SessionLayer;

public partial class ClientDestination : IClient
{
    internal void InboundTunnel_GarlicMessageReceived(GarlicMessage msg)
    {
        try
        {
            var decr = MySessions.DecryptMessage(msg);
            if (decr == null)
            {
                // Fallback: try as a tunnel build reply garlic.
                // When paired tunnels are used (Java I2P BuildRequestor),
                // build reply garlic arrives on client inbound tunnels but
                // the tag is registered with TunnelProvider, not this client's SKM.
                if (TunnelProvider.Inst?.TryHandleBuildReplyGarlic(msg, null) == true)
                {
                    Logging.LogDebug($"{this}: GarlicMessageReceived: Handled as build reply garlic.");
                    return;
                }

                // Most undecryptable garlic on client tunnels is router-level
                // (build replies, DB lookups, delivery status) — not proxy errors.
                Logging.LogDebug(
                    $"{this}: GarlicMessageReceived: Failed to decrypt garlic (len={msg.EgData.Length}). Likely router-level garlic.");
                return;
            }

            var cloveTypes = string.Join(", ", decr.Cloves.Select(c => c.Message?.GetType().Name ?? "?"));
            HttpProxyLogger.Inst.Log("GARLIC", Destination?.IdentHash?.Id32Short ?? "?",
                "Decrypted", $"Garlic decrypted: {decr.Cloves.Count} cloves [{cloveTypes}]");

            HandleDecryptedGarlic(decr, null);
        }
        catch (Exception ex)
        {
            Logging.Log("ClientDestination GarlicDecrypt", ex);
        }
    }

    internal void HandleDecryptedGarlic(Garlic decr, InboundTunnel from)
    {
        try
        {
#if LOG_ALL_LEASE_MGMT
                Logging.LogDebug( $"{this}: HandleDecryptedGarlic: {decr}: {string.Join( ',', decr.Cloves.Select( c => c.Message ) ) }" );
#endif
            List<Tuple<DataMessage, I2PDestination>> destinationMessages = null;
            I2PDestination lastSender = null;

            foreach (var clove in decr.Cloves)
                try
                {
                    switch (clove.Delivery.Delivery)
                    {
                        case GarlicCloveDelivery.DeliveryMethod.Local:
#if LOG_ALL_LEASE_MGMT
                                Logging.LogDebug(
                                    $"{this}: HandleDecryptedGarlic: Delivered Local: {clove.Message}" );
#endif
                            if (clove.Message is DatabaseStoreMessage dbsmsgLocal && dbsmsgLocal.LeaseSet != null)
                            {
                                MySessions.ConfirmRemoteHash(decr.RemoteHash, dbsmsgLocal.LeaseSet.Destination.IdentHash);
                                MySessions.RemoteIsActive(dbsmsgLocal.LeaseSet.Destination.IdentHash);
                                MySessions.LeaseSetReceived(dbsmsgLocal.LeaseSet);
                                lastSender = dbsmsgLocal.LeaseSet.Destination;
                            }
                            TunnelProvider.Inst.DistributeIncomingMessage(null, clove.Message.CreateHeader16);
                            break;

                        case GarlicCloveDelivery.DeliveryMethod.Router:
                            var dest = ((GarlicCloveDeliveryRouter)clove.Delivery).Destination;
#if LOG_ALL_LEASE_MGMT
                                Logging.LogDebug(
                                    $"{this}: HandleDecryptedGarlic: Delivered Router: {dest.Id32Short} {clove.Message}" );
#endif
                            ThreadPool.QueueUserWorkItem(a => TransportProvider.Send(dest, clove.Message));
                            break;

                        case GarlicCloveDelivery.DeliveryMethod.Tunnel:
                            var tone = (GarlicCloveDeliveryTunnel)clove.Delivery;
#if LOG_ALL_LEASE_MGMT
                                Logging.LogDebug(
                                    $"{this}: HandleDecryptedGarlic: " +
                                    $"Delivered Tunnel: {tone.Destination.Id32Short} " +
                                    $"TunnelId: {tone.Tunnel} {clove.Message}" );
#endif
                            ThreadPool.QueueUserWorkItem(a => TransportProvider.Send(
                                tone.Destination,
                                new TunnelGatewayMessage(
                                    clove.Message,
                                    tone.Tunnel)));
                            break;

                        case GarlicCloveDelivery.DeliveryMethod.Destination:
#if LOG_ALL_LEASE_MGMT
                                Logging.LogDebug(
                                    $"{this}: HandleDecryptedGarlic: " +
                                    $"Delivered Destination: {clove.Message}" );
#endif
                            switch (clove?.Message)
                            {
                                case DatabaseStoreMessage dbsmsg when dbsmsg?.LeaseSet != null:
                                    MySessions.ConfirmRemoteHash(decr.RemoteHash, dbsmsg.LeaseSet?.Destination?.IdentHash);
                                    MySessions.RemoteIsActive(dbsmsg.LeaseSet?.Destination?.IdentHash);

                                    if (dbsmsg.LeaseSet.Expire > DateTime.UtcNow)
                                    {
                                        Logging.LogDebug(
                                            $"{this}: New lease set received in stream for {dbsmsg.LeaseSet.Destination} {dbsmsg.LeaseSet}.");
                                        var lsEncKeys = dbsmsg.LeaseSet.PublicKeys?
                                            .Select(pk => pk.Certificate?.PublicKeyType.ToString() ?? "?");
                                        HttpProxyLogger.Inst.Log("GARLIC",
                                            dbsmsg.LeaseSet.Destination?.IdentHash?.Id32Short ?? "?",
                                            "LeaseSet",
                                            $"Remote LeaseSet received via garlic: {dbsmsg.LeaseSet.Leases?.Count() ?? 0} leases, " +
                                            $"keys=[{string.Join(", ", lsEncKeys ?? Enumerable.Empty<string>())}], " +
                                            $"expires {dbsmsg.LeaseSet.Expire:HH:mm:ss}");
                                        MySessions.LeaseSetReceived(dbsmsg.LeaseSet);
                                        lastSender = dbsmsg.LeaseSet.Destination;
                                        ThreadPool.QueueUserWorkItem(a => UpdateClientState());
                                    }

                                    break;

                                case DataMessage dmsg when DataReceived != null:
                                    if (destinationMessages is null)
                                        destinationMessages = new List<Tuple<DataMessage, I2PDestination>>();
                                    destinationMessages.Add(new Tuple<DataMessage, I2PDestination>(dmsg, lastSender));
                                    break;

                                default:
                                    Logging.LogDebug($"{this}: Garlic discarded {clove.Message}");
                                    break;
                            }

                            break;
                    }
                }
                catch (Exception ex)
                {
                    Logging.Log("ClientDestination GarlicDecrypt Clove", ex);
                }

            if (destinationMessages != null)
                ThreadPool.QueueUserWorkItem(a =>
                {
                    foreach (var dmsg in destinationMessages)
                    {
#if LOG_ALL_LEASE_MGMT
                            Logging.LogDebug( $"{this}: DestinationMessageReceived: {dmsg.Item1}" );
#endif
                        DataReceived?.Invoke(this, dmsg.Item1.DataMessagePayload, dmsg.Item2);
                    }
                });
        }
        catch (Exception ex)
        {
            Logging.Log("ClientDestination HandleDecryptedGarlic", ex);
        }
    }
}