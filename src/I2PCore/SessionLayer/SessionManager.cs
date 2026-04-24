using System;
using I2PCore.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.SessionLayer
{

    /// <summary>
    /// Manages temporary crypto keys and sessions with remote destinations
    /// and encrypts and decrypts communication.
    /// </summary>
    public class SessionManager
    {
        /// <summary>
        /// Used to decrypt ElGamal blocks.
        /// </summary>
        public List<I2PPrivateKey> PrivateKeys 
        { 
            get => PrivateKeysField; 
            set
            {
                PrivateKeysField = value;
                IncommingSessions.PrivateKeys = value;
            }
        }
        private List<I2PPrivateKey> PrivateKeysField;

        /// <summary>
        /// Used when constructing LeaseSets for this Destination.
        /// </summary>
        public List<I2PPublicKey> PublicKeys { get; set; }

        internal readonly ConcurrentDictionary<I2PIdentHash,Session> Sessions = new();

        private EgaesDecryptReceivedSessions IncommingSessions;
        private I2PCore.SessionLayer.ECIES.ECIESSessionKeyManager EciesManager;

        internal readonly ClientDestination Context;

        public SessionManager( ClientDestination context )
        {
            Context = context;
            IncommingSessions = new EgaesDecryptReceivedSessions( this );
        }

        public void GenerateTemporaryKeys()
        {
            var tmpprivkey = new I2PPrivateKey( new I2PCertificate( I2PKeyType.KeyTypes.ElGamal2048 ) );
            var tmppubkey = new I2PPublicKey( tmpprivkey );

            var eciesprivkey = new I2PPrivateKey( new I2PCertificate( I2PKeyType.KeyTypes.X25519 ) );
            var eciespubkey = new I2PPublicKey( eciesprivkey );

            PrivateKeys = new List<I2PPrivateKey>() { tmpprivkey };
            PublicKeys = new List<I2PPublicKey>() { tmppubkey };

            switch ( RouterContext.Inst.ProxyEncryption )
            {
                case RouterContext.HttpProxyEncryptionType.Ecies:
                    PrivateKeys.Add( eciesprivkey );
                    PublicKeys.Add( eciespubkey );
                    break;

                case RouterContext.HttpProxyEncryptionType.Mlkem:
                    {
                        var (mlkemPub, mlkemPriv) = I2PCore.Crypto.MLKEM.MLKEM768.GenerateKeyPair();
                        var combinedPriv = new byte[mlkemPriv.Length + 32];
                        Array.Copy( mlkemPriv, 0, combinedPriv, 0, mlkemPriv.Length );
                        Array.Copy( eciesprivkey.ToByteArray(), 0, combinedPriv, mlkemPriv.Length, 32 );
                        var combinedPub = new byte[mlkemPub.Length + 32];
                        Array.Copy( mlkemPub, 0, combinedPub, 0, mlkemPub.Length );
                        Array.Copy( eciespubkey.ToByteArray(), 0, combinedPub, mlkemPub.Length, 32 );

                        var mlkem768privkey = new I2PPrivateKey( new BufRef( combinedPriv ), new I2PCertificate( I2PKeyType.KeyTypes.MLKEM768_X25519 ) );
                        var mlkem768pubkey = new I2PPublicKey( new BufRef( combinedPub ), new I2PCertificate( I2PKeyType.KeyTypes.MLKEM768_X25519 ) );
                        PrivateKeys.Add( mlkem768privkey );
                        PublicKeys.Add( mlkem768pubkey );
                    }
                    break;

                case RouterContext.HttpProxyEncryptionType.Hybrid:
                    {
                        PrivateKeys.Add( eciesprivkey );
                        PublicKeys.Add( eciespubkey );

                        var (mlkemPub, mlkemPriv) = I2PCore.Crypto.MLKEM.MLKEM768.GenerateKeyPair();
                        var combinedPriv = new byte[mlkemPriv.Length + 32];
                        Array.Copy( mlkemPriv, 0, combinedPriv, 0, mlkemPriv.Length );
                        Array.Copy( eciesprivkey.ToByteArray(), 0, combinedPriv, mlkemPriv.Length, 32 );
                        var combinedPub = new byte[mlkemPub.Length + 32];
                        Array.Copy( mlkemPub, 0, combinedPub, 0, mlkemPub.Length );
                        Array.Copy( eciespubkey.ToByteArray(), 0, combinedPub, mlkemPub.Length, 32 );

                        var hmlkem768privkey = new I2PPrivateKey( new BufRef( combinedPriv ), new I2PCertificate( I2PKeyType.KeyTypes.MLKEM768_X25519 ) );
                        var hmlkem768pubkey = new I2PPublicKey( new BufRef( combinedPub ), new I2PCertificate( I2PKeyType.KeyTypes.MLKEM768_X25519 ) );
                        PrivateKeys.Add( hmlkem768privkey );
                        PublicKeys.Add( hmlkem768pubkey );
                    }
                    break;
            }

            EciesManager = new I2PCore.SessionLayer.ECIES.ECIESSessionKeyManager( Context.Destination, eciesprivkey.ToByteArray(), eciespubkey.ToByteArray() );
        }

        public Garlic DecryptMessage( GarlicMessage message )
        {
            // Try ECIES first if available
            if ( EciesManager != null )
            {
                var eciesResult = EciesManager.ProcessMessage( message.EgData.ToByteArray() );
                if ( eciesResult.Success )
                {
                    return TranslateEciesGarlic( eciesResult.Payload );
                }
            }

            return IncommingSessions.DecryptMessage( message );
        }

        private Garlic TranslateEciesGarlic( byte[] payload )
        {
            var eciesProcessor = new I2PCore.SessionLayer.ECIES.ECIESGarlicProcessor( EciesManager, Context.Destination );
            var result = eciesProcessor.ProcessGarlicMessage( payload );
            if ( !result.Success ) return null;

            var cloves = new List<I2PCore.TunnelLayer.I2NP.Data.GarlicClove>();
            foreach ( var eciesClove in result.CloveResults )
            {
                if ( !eciesClove.Success ) continue;

                var delivery = TranslateEciesDelivery( eciesClove );
                if ( delivery == null ) continue;

                var clove = new I2PCore.TunnelLayer.I2NP.Data.GarlicClove( delivery, new I2PDate( (ulong)eciesClove.Expiration * 1000 ) )
                {
                    CloveId = eciesClove.CloveId
                };
                cloves.Add( clove );
            }

            return new Garlic( cloves );
        }

        private GarlicCloveDelivery TranslateEciesDelivery( I2PCore.SessionLayer.ECIES.CloveResult eciesClove )
        {
            var msg = I2NpMessage.ReadHeader16( new BufRefLen( eciesClove.Payload ) ).Message;

            switch ( eciesClove.DeliveryType )
            {
                case I2PCore.SessionLayer.ECIES.DeliveryType.Local:
                    return new GarlicCloveDeliveryLocal( msg );

                case I2PCore.SessionLayer.ECIES.DeliveryType.Destination:
                    return new GarlicCloveDeliveryDestination( msg, eciesClove.ForwardDestination );

                case I2PCore.SessionLayer.ECIES.DeliveryType.Router:
                    return new GarlicCloveDeliveryRouter( msg, eciesClove.ForwardRouter );

                case I2PCore.SessionLayer.ECIES.DeliveryType.Tunnel:
                    return new GarlicCloveDeliveryTunnel( msg, eciesClove.ForwardRouter, eciesClove.ForwardTunnelId );

                default:
                    return null;
            }
        }

        private Session GetSession( I2PIdentHash dest )
        {
            return Sessions.GetOrAdd(
                        dest,
                        ( d ) => new Session(
                                    Context,
                                    Context.Destination,
                                    dest ) );
        }
        public GarlicMessage Encrypt(
            I2PIdentHash dest,
            IEnumerable<I2PPublicKey> remotepublickeys,
            InboundTunnel replytunnel,
            IList<GarlicClove> cloves )
        {
            var sess = GetSession( dest );
            return sess.Encrypt( remotepublickeys, replytunnel, cloves );
        }

        public void MySignedLeasesUpdated()
        {
            foreach( var sess in Sessions )
            {
                sess.Value.MySignedLeasesUpdated( sess.Key );
            }
        }

        public void LeaseSetReceived( ILeaseSet ls )
        {
            if ( ls.Destination.IdentHash == Context.Destination.IdentHash )
            {
                // that is me
                Logging.LogDebug(
                    $"{this}: Sessions: LeaseSetReceived: " +
                    $"discarding my lease set." );
                return;
            }

            if ( ls.Expire < DateTime.UtcNow )
            {
                Logging.LogDebug(
                    $"{this}: Sessions: LeaseSetReceived: " +
                    $"discarding expired lease set. {ls}" );
                return;
            }

            var sess = GetSession( ls.Destination.IdentHash );
            sess.LeaseSetReceived( ls );
        }

        internal void DeliveryStatusReceived( DeliveryStatusMessage msg, InboundTunnel from )
        {
            foreach( var sess in Sessions )
            {
                sess.Value.DeliveryStatusReceived( msg, from );
            }
        }

        public ILeaseSet GetLeaseSet( I2PIdentHash dest )
        {
            var sess = GetSession( dest );

            if ( sess?.RemoteLeaseSet is null )
            {
                var cachedls = NetDb.Inst.FindLeaseSet( dest );
                if ( cachedls != null )
                {
                    LeaseSetReceived( cachedls );
                    return cachedls;
                }

                return null;
            }

            return sess.RemoteLeaseSet;
        }

        public ILease GetTunnelPair( I2PIdentHash dest, OutboundTunnel outtunnel )
        {
            var sess = GetSession( dest );
            return sess.GetTunnelPair( outtunnel );
        }

        internal void DataSentToRemote( I2PIdentHash dest )
        {
            if ( Sessions.TryGetValue( dest, out var sess ) )
            {
                sess.DataSentToRemote( dest );
            }
        }

        public void RemoteIsActive( I2PIdentHash dest )
        {
            if ( Sessions.TryGetValue( dest, out var sess ) )
            {
                sess.RemoteIsActive( dest );
            }
        }

        public DatabaseLookupKeyInfo KeyGenerator( I2PIdentHash ffrouterid )
        {
            return IncommingSessions.KeyGenerator( ffrouterid );
        }

        public override string ToString()
        {
            return $"{Context} {GetType().Name}";
        }
    }
}