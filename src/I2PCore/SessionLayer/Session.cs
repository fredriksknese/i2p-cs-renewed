using System;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;
using System.Collections.Generic;
using System.Collections.Concurrent;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.SessionLayer.ECIES;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;

namespace I2PCore.SessionLayer
{
    internal class Session
    {
        public static TimeSpan RemoteLeaseSetUpdateMargin = TimeSpan.FromMinutes( 3 );

        public static TickSpan SessionInactivityTimeout = TickSpan.Minutes( 25 );

        public static TickSpan WaitForLsUpdateAck = TickSpan.Seconds( 45 );

        readonly internal ClientDestination Context;

        private readonly I2PDestination MyDestination;
        private readonly I2PIdentHash RemoteDestination;

        private readonly EgaesSessionKeyOrigin EgaesKeys;
        private ECIESSessionKeyManager EciesKeys;

        private TimeWindowDictionary<uint,LeaseSetUpdateAck> NotAckedLsUpdates = new(WaitForLsUpdateAck);


        /// <summary>
        /// Expiry time of the newest ACKed LeaseSet transferred to RemoteDestination
        /// </summary>
        protected DateTime AcKedLeaseSetExpireTime = DateTime.MinValue;

        private readonly TimeSpan TimeCompareEpsilon = TimeSpan.FromSeconds( 2 );

        public ILeaseSet RemoteLeaseSet { get; protected set; }

        private TickCounter LastSendToRemote = new();

        internal Session( ClientDestination context, I2PDestination mydest, I2PIdentHash remotedest )
        {
            Context = context;
            MyDestination = mydest;
            RemoteDestination = remotedest;

            EgaesKeys = new EgaesSessionKeyOrigin(
                                    Context,
                                    mydest,
                                    remotedest );
        }

        /// <summary>
        /// Check if remote destination uses ECIES (X25519 or ML-KEM hybrid keys)
        /// </summary>
        private bool IsECIESDestination(IEnumerable<I2PPublicKey> remotepublickeys)
        {
            return remotepublickeys.Any(pk =>
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.X25519 ||
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519);
        }

        internal GarlicMessage Encrypt(
            IEnumerable<I2PPublicKey> remotepublickeys,
            InboundTunnel replytunnel,
            IList<TunnelLayer.I2NP.Data.GarlicClove> cloves,
            bool checkremotelsage = true )
        {
            if ( checkremotelsage && RemoteNeedsLeaseSetUpdate )
            {
                if ( replytunnel != null )
                {
                    Logging.LogDebug( $"{this}: Sending my leases to remote {RemoteDestination.Id32Short}." );
                    GenerateRemoteLsUpdate( cloves, replytunnel );
                }
                else
                {
                    Logging.LogWarning( $"{this}: Remote needs LeaseSet update but no reply tunnel available! Bob might not be able to respond." );
                }
            }

            // Detect ECIES destination and use appropriate encryption
            if (IsECIESDestination(remotepublickeys))
            {
                // Initialize ECIES session manager if needed
                if (EciesKeys == null)
                {
                    Logging.LogInformation($"{this}: Remote destination {RemoteDestination.Id32Short} is ECIES, searching for suitable keys");

                    // Get private key from ClientDestination context
                    var myPrivateKeys = Context.PrivateKeys;
                    if (myPrivateKeys != null && myPrivateKeys.Count > 0)
                    {
                        // Search for an X25519 key in our private keys
                        var myEciesPrivKey = myPrivateKeys.FirstOrDefault(pk => 
                            pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.X25519);

                        if (myEciesPrivKey != null)
                        {
                            var myEciesPubKey = Context.PublicKeys.FirstOrDefault(pk => 
                                pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.X25519);

                            if (myEciesPubKey != null)
                            {
                                Logging.LogInformation($"{this}: Using local X25519 key for ECIES session to {RemoteDestination.Id32Short}");
                                EciesKeys = new ECIESSessionKeyManager(MyDestination, myEciesPrivKey.ToByteArray(), myEciesPubKey.ToByteArray());
                            }
                            else
                            {
                                Logging.LogWarning($"{this}: Found ECIES private key but no matching public key, cannot initialize ECIES");
                            }
                        }
                        else
                        {
                            Logging.LogWarning($"{this}: MyDestination identity is {MyDestination.PublicKey.Certificate.PublicKeyType}, and no supplementary X25519 keys found. Cannot send ECIES to ECIES destination {RemoteDestination.Id32Short}");
                        }
                    }
                    else
                    {
                        Logging.LogWarning($"{this}: No private keys available, cannot initialize ECIES");
                    }
                }

                if (EciesKeys != null)
                {
                    return EncryptECIES(remotepublickeys, replytunnel, cloves);
                }
            }

            // Fall back to ElGamal for legacy destinations
            return EgaesKeys.Encrypt( remotepublickeys, replytunnel, cloves );
        }

        /// <summary>
        /// Encrypt Garlic message using ECIES (Noise IK pattern)
        /// </summary>
        private GarlicMessage EncryptECIES(
            IEnumerable<I2PPublicKey> remotepublickeys,
            InboundTunnel replytunnel,
            IList<TunnelLayer.I2NP.Data.GarlicClove> cloves)
        {
            // Serialize Garlic cloves into payload
            var garlic = new Garlic(cloves);
            var payload = garlic.ToByteArray();

            // Check if we have an existing session with this destination
            bool hasSession = EciesKeys.HasOutboundSession(RemoteDestination) && EciesKeys.HasAvailableOutboundTags(RemoteDestination);

            byte[] eciesMessage = null;

            if (hasSession)
            {
                // Use existing session with session tag
                try
                {
                    var existingMsg = EciesKeys.CreateExistingSession(RemoteDestination, payload);
                    eciesMessage = existingMsg.ToByteArray();

                    Logging.LogDebug($"{this}: Encrypted ECIES message using existing session to {RemoteDestination.Id32Short}, {eciesMessage.Length} bytes");
                }
                catch (Exception ex)
                {
                    // Fall back to new session if existing session fails
                    Logging.LogWarning($"{this}: Existing ECIES session failed, creating new session: {ex.Message}");
                    hasSession = false;
                }
            }

            if (!hasSession || eciesMessage == null)
            {
                // Find best hybrid variant from remotepublickeys
                NoiseIKhfs.KEMVariant? variant = null;
                if (remotepublickeys.Any(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519))
                    variant = NoiseIKhfs.KEMVariant.MLKEM1024;
                else if (remotepublickeys.Any(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519))
                    variant = NoiseIKhfs.KEMVariant.MLKEM768;
                else if (remotepublickeys.Any(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519))
                    variant = NoiseIKhfs.KEMVariant.MLKEM512;

                // Create new session with Noise IK or hybrid IKhfs handshake
                var x25519Key = remotepublickeys.FirstOrDefault( pk => 
                    pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.X25519 ||
                    pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
                    pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
                    pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519 );

                if ( x25519Key == null ) x25519Key = remotepublickeys.FirstOrDefault();

                if ( x25519Key == null )
                {
                    Logging.LogWarning($"{this}: No public keys available for {RemoteDestination.Id32Short}, cannot encrypt.");
                    return null;
                }

                eciesMessage = EciesKeys.CreateNewSession(RemoteDestination, x25519Key, payload, variant);

                Logging.LogInformation($"{this}: Encrypted ECIES message using new {(variant.HasValue ? variant.Value.ToString() : "IK")} session to {RemoteDestination.Id32Short}, {eciesMessage.Length} bytes");
            }

            // Wrap ECIES message in GarlicMessage format (I2NP type 11)
            // Format: 4-byte length + ECIES data
            var destbuf = new byte[eciesMessage.Length + I2NpMessage.I2NpMaxHeaderSize + 4];
            var writer = new I2PBufferCursor(destbuf, I2NpMessage.I2NpMaxHeaderSize);

            // Write length (big-endian)
            writer.WriteUInt32BigEndian((uint)eciesMessage.Length);

            // Write ECIES message
            writer.WriteBytes(eciesMessage);

            var totalLength = 4 + eciesMessage.Length;
            return new GarlicMessage(new I2PBufferCursor(destbuf, I2NpMessage.I2NpMaxHeaderSize, totalLength));
        }

        internal void MySignedLeasesUpdated( I2PIdentHash dest )
        {
            // Send ASAP
            AcKedLeaseSetExpireTime = DateTime.MinValue;

            if ( LastSendToRemote.DeltaToNow < SessionInactivityTimeout )
            {
                SendLeaseSetUpdate( dest );
            }
        }

        public void LeaseSetReceived( ILeaseSet ls )
        {
            lock ( OutboundRemoteLeasePairs )
            {
                if ( RemoteLeaseSet != null 
                        && ls.Expire < RemoteLeaseSet.Expire + TimeCompareEpsilon )
                {
                    Logging.LogDebug(
                        $"{this} Session: LeaseSetReceived: ignoring older remote LS {ls}" );

                    return;
                }

                Logging.LogDebug(
                    $"{this} Session: LeaseSetReceived: updating remote LS {ls}" );

                RemoteLeaseSet = ls;

                // Did a remote pair dissappear?
                var nolongeravailable = OutboundRemoteLeasePairs
                            .Where( p => !ls.Leases.Any( l => l.TunnelId == p.Value.TunnelId
                                                                && l.TunnelGw == p.Value.TunnelGw ) )
                            .ToArray();

                foreach( var toremove in nolongeravailable )
                {
                    OutboundRemoteLeasePairs.TryRemove( toremove.Key, out var _ );
                }
            }
        }

        internal void DeliveryStatusReceived( DeliveryStatusMessage msg, InboundTunnel from )
        {
            EgaesKeys.DeliveryStatusReceived( msg, from );

            if ( NotAckedLsUpdates.TryRemove( msg.StatusMessageId, out var lsupdate ) )
            {
                Logging.LogDebug( $"{this}: Remote LS update ACKed, expire {lsupdate.ExpireTimeForLeaseSet}" );

                RemoteLeaseSetUpdateAckReceived( lsupdate.ExpireTimeForLeaseSet );
            }
        }

        internal void SendLeaseSetUpdate( I2PIdentHash dest )
        {
            if ( RemoteLeaseSet is null )
                return;

            Logging.LogDebug(
                $"{this} Session: SendLeaseSetUpdate: sending LS to {dest.Id32Short}" );

            var replytunnel = Context.SelectInboundTunnel();
            var cloves = GenerateRemoteLsUpdate( new List<TunnelLayer.I2NP.Data.GarlicClove>(), replytunnel );

            Context.Send( 
                    RemoteLeaseSet.Destination,
                    Encrypt( 
                            RemoteLeaseSet.PublicKeys,
                            replytunnel,
                            cloves,
                            false ) );
        }

        internal void DataSentToRemote( I2PIdentHash dest )
        {
            LastSendToRemote.SetNow();
        }

        internal void RemoteIsActive( I2PIdentHash dest )
        {
            if ( RemoteNeedsLeaseSetUpdate
                    && LastSendToRemote.DeltaToNow < SessionInactivityTimeout )
            {
                SendLeaseSetUpdate( dest );
            }
        }

        internal bool RemoteNeedsLeaseSetUpdate
        {
            get 
            {
                if ( Context is null ) 
                {
                    Logging.LogWarning( $"{this}: RemoteNeedsLeaseSetUpdate: Context is null!" );
                    return false;
                }
                var signed = Context.SignedLeases;
                if ( signed is null ) return false;

                // remote never received our leases?
                if ( AcKedLeaseSetExpireTime == DateTime.MinValue ) return true;

                return signed.Expire > AcKedLeaseSetExpireTime + TimeCompareEpsilon;
            }
        }

        internal void RemoteLeaseSetUpdateAckReceived( DateTime expiration )
        {
            if ( expiration > AcKedLeaseSetExpireTime )
            {
                AcKedLeaseSetExpireTime = expiration;
            }
        }

        private TimeWindowDictionary<OutboundTunnel,ILease> OutboundRemoteLeasePairs = new(TickSpan.Minutes(15));

        internal ILease GetTunnelPair( OutboundTunnel outtunnel )
        {
            if ( RemoteLeaseSet is null )
                    return null;

            if ( OutboundRemoteLeasePairs.TryGetValue( outtunnel, out var lease ) )
            {
                if ( lease.Expire > DateTime.UtcNow )
                {
                    return lease;
                }

                OutboundRemoteLeasePairs.TryRemove( outtunnel, out var _ );
            }

            var usedleases = OutboundRemoteLeasePairs
                    .Select( p => p.Value )
                    .ToHashSet();

            var unused = RemoteLeaseSet
                            .Leases
                            .Where( lease => !usedleases.Contains( lease ) )
                            .ToArray();
            
            ILease result;

            if ( unused.Length > 0 )
            {
                result = ClientDestination.SelectLease( unused );
            }
            else
            {
                result = ClientDestination.SelectLease( RemoteLeaseSet.Leases );
            }

            if ( result is null ) return null;

            OutboundRemoteLeasePairs[outtunnel] = result;

            return result;
        }

        private class LeaseSetUpdateAck
        {
            /// <summary>MessageId of the DeliveryStatusMessage of the ACK.</summary>
            public uint MessageId;
            public DateTime ExpireTimeForLeaseSet;
        }

        private IList<TunnelLayer.I2NP.Data.GarlicClove> GenerateRemoteLsUpdate( IList<TunnelLayer.I2NP.Data.GarlicClove> cloves, InboundTunnel replytunnel )
        {
            var signedleases = Context.SignedLeases;
            if ( signedleases is null )
            {
                Logging.LogWarning( $"{this}: GenerateRemoteLsUpdate: SignedLeases is null! Cannot send update." );
                return cloves;
            }

            if ( replytunnel is null )
            {
                Logging.LogWarning( $"{this}: GenerateRemoteLsUpdate: replytunnel is null! Cannot send update." );
                return cloves;
            }

            var myleases = new DatabaseStoreMessage( signedleases );
            var lsack = new DeliveryStatusMessage( I2NpMessage.GenerateMessageId() );

            cloves.Add(
                new TunnelLayer.I2NP.Data.GarlicClove(
                    new GarlicCloveDeliveryDestination(
                        myleases,
                        RemoteDestination ) ) );

            cloves.Add(
                new TunnelLayer.I2NP.Data.GarlicClove(
                    new GarlicCloveDeliveryTunnel(
                            lsack,
                            replytunnel.Destination, replytunnel.GatewayTunnelId ) ) );


            NotAckedLsUpdates[lsack.StatusMessageId] = new LeaseSetUpdateAck
            {
                ExpireTimeForLeaseSet = signedleases.Expire,
                MessageId = lsack.MessageId,
            };

            return cloves;
        }

        public override string ToString()
        {
            return $"{Context} {MyDestination} -> {RemoteDestination?.Id32Short}";
        }
   }
}