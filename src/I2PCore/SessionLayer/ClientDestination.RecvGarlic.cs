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
            var decr = MySessions.DecryptMessage(msg, suppressTunnelPageLog: true);
            if (decr == null)
            {
                // Fallback: try as a tunnel build reply garlic.
                if (TunnelProvider.Inst?.TryHandleBuildReplyGarlic(msg, null) == true)
                {
                    Logging.LogDebug($"{this}: GarlicMessageReceived: Handled as build reply garlic.");
                    return;
                }

                // Most undecryptable garlic on client tunnels is router-level
                // (build replies, DB lookups, delivery status) — not client errors.
                // Do NOT log to the tunnel page — it's noise.
                Logging.LogDebug(
                    $"{this}: GarlicMessageReceived: Failed to decrypt garlic (len={msg.EgData.Length}). Likely router-level garlic.");
                return;
            }

            var cloveTypes = string.Join(", ", decr.Cloves.Select(c => c.Message?.GetType().Name ?? "?"));
            Log("Decrypted", $"Garlic decrypted: {decr.Cloves.Count} cloves [{cloveTypes}]",
                decr.RemoteHash?.Id32Short);

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
            Logging.LogTrace( TraceCategories.LeaseMgmt, $"{this}: HandleDecryptedGarlic: {decr}: {string.Join( ',', decr.Cloves.Select( c => c.Message ) ) }" );
            List<Tuple<DataMessage, I2PDestination>> destinationMessages = null;
            I2PDestination lastSender = null;

            foreach (var clove in decr.Cloves)
                try
                {
                    switch (clove.Delivery.Delivery)
                    {
                        case GarlicCloveDelivery.DeliveryMethod.Local:
                            Logging.LogTrace( TraceCategories.LeaseMgmt, 
                                $"{this}: HandleDecryptedGarlic: Delivered Local: {clove.Message}" );
                            if (clove.Message is DatabaseStoreMessage dbsmsgLocal && dbsmsgLocal.LeaseSet != null)
                            {
                                MySessions.ConfirmRemoteHash(decr.RemoteHash, dbsmsgLocal.LeaseSet.Destination.IdentHash);
                                // Store the LeaseSet BEFORE RemoteIsActive so that
                                // SendLeaseSetUpdate (triggered by RemoteIsActive) can
                                // find the remote's public keys and actually send the
                                // reply.  This is critical for completing the ECIES
                                // handshake when the initial New Session contains only a
                                // LeaseSet update without a DataMessage.
                                MySessions.LeaseSetReceived(dbsmsgLocal.LeaseSet);
                                MySessions.RemoteIsActive(dbsmsgLocal.LeaseSet.Destination.IdentHash);
                                lastSender = dbsmsgLocal.LeaseSet.Destination;
                            }
                            TunnelProvider.Inst.DistributeIncomingMessage(null, clove.Message.CreateHeader16);
                            break;

                        case GarlicCloveDelivery.DeliveryMethod.Router:
                            var dest = ((GarlicCloveDeliveryRouter)clove.Delivery).Destination;
                            Logging.LogTrace( TraceCategories.LeaseMgmt, 
                                $"{this}: HandleDecryptedGarlic: Delivered Router: {dest.Id32Short} {clove.Message}" );
                            ThreadPool.QueueUserWorkItem(a => TransportProvider.Send(dest, clove.Message));
                            break;

                        case GarlicCloveDelivery.DeliveryMethod.Tunnel:
                            var tone = (GarlicCloveDeliveryTunnel)clove.Delivery;
                            Logging.LogTrace( TraceCategories.LeaseMgmt, 
                                $"{this}: HandleDecryptedGarlic: " +
                                $"Delivered Tunnel: {tone.Destination.Id32Short} " +
                                $"TunnelId: {tone.Tunnel} {clove.Message}" );
                            ThreadPool.QueueUserWorkItem(a => TransportProvider.Send(
                                tone.Destination,
                                new TunnelGatewayMessage(
                                    clove.Message,
                                    tone.Tunnel)));
                            break;

                        case GarlicCloveDelivery.DeliveryMethod.Destination:
                            Logging.LogTrace( TraceCategories.LeaseMgmt, 
                                $"{this}: HandleDecryptedGarlic: " +
                                $"Delivered Destination: {clove.Message}" );
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
                                        Log("LeaseSet",
                                            $"Remote LeaseSet received via garlic: {dbsmsg.LeaseSet.Leases?.Count() ?? 0} leases, " +
                                            $"keys=[{string.Join(", ", lsEncKeys ?? Enumerable.Empty<string>())}], " +
                                            $"expires {dbsmsg.LeaseSet.Expire:HH:mm:ss}",
                                            dbsmsg.LeaseSet.Destination?.IdentHash?.Id32Short ?? "?");
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
                        Logging.LogTrace( TraceCategories.LeaseMgmt, $"{this}: DestinationMessageReceived: {dmsg.Item1}" );
                        DataReceived?.Invoke(this, dmsg.Item1.DataMessagePayload, dmsg.Item2);
                    }
                });

            // If we received a New Session (ECIES handshake) but the garlic
            // contained no DataMessage, the remote is waiting for our handshake
            // reply.  Proactively send it now (piggy-backed on a LeaseSet update)
            // so the session is established and queued data can flow.
            if (decr.RemoteHash != null && destinationMessages == null)
            {
                if (MySessions.Sessions.TryGetValue(decr.RemoteHash, out var sess) && sess.HasPendingHandshake)
                    ThreadPool.QueueUserWorkItem(_ => sess.FlushHandshakeReply());
            }
        }
        catch (Exception ex)
        {
            Logging.Log("ClientDestination HandleDecryptedGarlic", ex);
        }
    }
}