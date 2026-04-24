using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using System.Net;
using System.IO;
using I2PCore.Utils;
using System.Collections.Concurrent;
using I2PCore.TransportLayer;
using System.Net.Sockets;

// Todo list for all of I2PCore
// DONE: SSU2 PeerTest with automatic firewall detection (see SSU2Host.TryInitiatePeerTest)
// DONE: NTCP2 listener restart on settings change (see NTCP2Host._listenerRestartRequested)
// DONE: Replaced FailedToConnectException with return value (see TransportProvider.Send)
// DONE: IP block lists (see NTCP2Host._ipBlockFilter and SSU2Host._ipBlockFilter)
// DONE: Bandwidth limits enforced (see RouterContext.Limits, TunnelProvider, TransitTunnel, etc.)
// DONE: Cert / key split for oversized signing keys (see I2PKeysAndCert.SigningPublicKeyBuf)
// DONE: DatabaseLookup query support (see Router.HandleDatabaseLookup)
// DONE: Floodfill server support (see NetDb/FloodfillServer.cs)
// DONE: Connection limits (see NTCP2Host.MaxInboundConnections and SSU2Host.MaxIncomingSessions)
// DONE: NTCP2 uses async AcceptTcpClientAsync + ReadAsync; Watchdog removed (dead code)
// DONE: Decaying Bloom filter for packet dedup (see TunnelProvider.HandleIncomingMessage)

namespace I2PCore.SessionLayer
{
    public partial class RouterContext
    {
        public const int Ipv4HeaderSize = 20;
        public const int Ipv6HeaderSize = 40;
        public const int UdpHeaderSize = 8;
        public const int Ipv6Mtu = 1488;
        public const int Ipv4Mtu = 1484;

        public static int MaxPacketSize( AddressFamily af, int mtu )
        {
            if ( mtu <= 0 )
            {
                throw new ArgumentException( "MTU must be > 0" );
            }

            var result = af == AddressFamily.InterNetwork
                    ? mtu - Ipv4HeaderSize - UdpHeaderSize
                    : mtu - Ipv6HeaderSize - UdpHeaderSize;

            return result & ( ~0xf );
        }

        private bool IsFirewalledField = true;

        public bool IsFirewalled
        {
            get => IsFirewalledField;
            set
            {
                if ( IsFirewalledField != value )
                {
                    IsFirewalledField = value;
                    ApplyNewSettings();
                }
            }
        }

        public IPAddress LocalInterface { get => UseIpV6 ? IPAddress.IPv6Any : IPAddress.Any; }

        // IP settings
        public IPAddress DefaultExtAddress = null;

        public int DefaultTcpPort = 12123;
        public int TcpPort
        {
            get
            {
                if ( UPnpExternalTcpPortMapped )
                {
                    return UPnpExternalTcpPort;
                }
                return DefaultTcpPort;
            }
        }

        public int DefaultUdpPort = 12123;
        public int UdpPort
        {
            get
            {
                if ( UPnpExternalUdpPortMapped )
                {
                    return UPnpExternalUdpPort;
                }
                return DefaultUdpPort;
            }
        }

        private static bool _useIpV4Field = true;
        public static bool UseIpV4
        {
            get => _useIpV4Field;
            set
            {
                if ( TransportProvider.Inst != null )
                {
                    throw new Exception( "Transport provider have already been started" );
                }
                
                _useIpV4Field = value;
            }
        }

        private static bool _useIpV6Field = false;
        public static bool UseIpV6
        {
            get => _useIpV6Field;
            set
            {
                if ( TransportProvider.Inst != null )
                {
                    throw new Exception( "Transport provider have already been started" );
                }

                _useIpV6Field = value;
            }
        }

        public bool EnableSSU2 { get; set; } = true;

        public event Action NetworkSettingsChanged;

        // I2P
        public I2PDate Published { get; private set; }
        public I2PCertificate Certificate { get; private set; }
        public I2PPrivateKey PrivateKey { get; private set; }
        public I2PPublicKey PublicKey { get; private set; }

        /// <summary>
        /// Get the X25519 part of the private key (32 bytes).
        /// Handles Hybrid PQ keys by extracting the last 32 bytes.
        /// </summary>
        public byte[] X25519PrivateKey
        {
            get
            {
                var pk = PrivateKey.ToByteArray();
                return pk.Length == 32 ? pk : pk.Skip(pk.Length - 32).Take(32).ToArray();
            }
        }

        /// <summary>
        /// Get the X25519 part of the public key (32 bytes).
        /// Handles Hybrid PQ keys by extracting the last 32 bytes.
        /// </summary>
        public byte[] X25519PublicKey
        {
            get
            {
                var pk = PublicKey.ToByteArray();
                return pk.Length == 32 ? pk : pk.Skip(pk.Length - 32).Take(32).ToArray();
            }
        }

        public I2PSigningPrivateKey PrivateSigningKey { get; private set; }
        public I2PSigningPublicKey PublicSigningKey { get; private set; }

        public I2PRouterIdentity MyRouterIdentity { get; private set; }

        public bool FloodfillEnabled = false;

        public enum HttpProxyEncryptionType
        {
            Ecies,
            Mlkem,
            Hybrid
        }
        public HttpProxyEncryptionType ProxyEncryption = HttpProxyEncryptionType.Hybrid;

        // SSU
        public BufLen IntroKey = new( new byte[32] );

        // Store

        public static string RouterPath
        {
            get
            {
                return Path.GetFullPath( StreamUtils.AppPath );
            }
        }

        public static string GetFullPath( string filename )
        {
            return Path.Combine( RouterPath, filename );
        }

        /// <summary>
        /// The router settings file containing router id and intro keys.
        /// If you want to change this, do it before Router.Start() is called.
        /// </summary>
        public static string RouterSettingsFile = "Router.bin";

        private static RouterContext _staticInstance;
        private static readonly object StaticInstanceLock = new();

        /// <summary>
        /// Singleton access to the instance of RouterContext.
        /// </summary>
        /// <value>The inst.</value>
        public static RouterContext Inst
        {
            get
            {
                lock ( StaticInstanceLock )
                {
                    if ( _staticInstance != null ) return _staticInstance;
                    _staticInstance = new RouterContext( RouterSettingsFile );
                    return _staticInstance;
                }
            }
            set
            {
                if ( _staticInstance != null )
                {
                    throw new InvalidOperationException( "Router context already establshed" );
                }

                _staticInstance = value;
            }
        }

        /// <summary>
        /// Reset the singleton instance. Used for test isolation.
        /// Must only be called when the router is stopped.
        /// </summary>
        public static void Reset()
        {
            lock ( StaticInstanceLock )
            {
                _staticInstance = null;
            }
        }

        private static char _bandwidthCapability = 'X';
        private const string BandwidthCapabilitiesCharacters = "KLMNOPX";
        public static char BandwidthCapability
        {
            get => _bandwidthCapability;
            set
            {
                if ( !BandwidthCapabilitiesCharacters.Contains( value ) )
                {
                    throw new ArgumentException( $"BandwidthCapability must be one of '{BandwidthCapabilitiesCharacters}'" );
                }

                _bandwidthCapability = value;
            }
        }

        /// <summary>
        /// Hidden mode - matches Java I2P's router.hiddenMode.
        /// Hidden routers:
        /// - Don't publish RouterInfo to floodfills
        /// - Don't accept transit tunnels
        /// - Use 'L' bandwidth class regardless of actual capacity
        /// - Use shorter rekey intervals
        /// - Are always marked as unreachable ('U')
        /// </summary>
        public bool IsHidden { get; set; } = false;

        private I2PIdentHash _exploratoryKey = new I2PIdentHash( true );
        private DateTime _exploratoryKeyLastRefresh = DateTime.UtcNow;

        /// <summary>
        /// Stable XOR sorting key for exploratory tunnels. Refreshed every 10 minutes.
        /// </summary>
        public I2PIdentHash ExploratoryKey
        {
            get
            {
                if ( ( DateTime.UtcNow - _exploratoryKeyLastRefresh ).TotalMinutes > 10 )
                {
                    _exploratoryKey = new I2PIdentHash( true );
                    _exploratoryKeyLastRefresh = DateTime.UtcNow;
                    Logging.LogDebug( "RouterContext: Exploratory XOR key refreshed." );
                }
                return _exploratoryKey;
            }
        }

        /// <summary>
        /// Congestion level for this router, matching i2pd RouterContext congestion caps.
        /// </summary>
        public enum CongestionLevel
        {
            None,               // No congestion flag
            MediumCongestion,   // 'D' flag
            HighCongestion,     // 'E' flag
            RejectAll           // 'G' flag
        }

        private CongestionLevel _congestionLevel = CongestionLevel.None;
        private DateTime _congestionSetTime = DateTime.MinValue;
        private const int HighCongestionIntervalMinutes = 15; // i2pd: HIGH_CONGESTION_INTERVAL

        /// <summary>
        /// Current congestion level. Setting this clears the RouterInfo cache.
        /// </summary>
        public CongestionLevel Congestion
        {
            get => _congestionLevel;
            set
            {
                if ( _congestionLevel != value )
                {
                    _congestionLevel = value;
                    _congestionSetTime = DateTime.UtcNow;
                    ClearCache();
                }
            }
        }

        /// <summary>
        /// Set congestion based on transit tunnel load.
        /// Call periodically from the tunnel manager.
        /// </summary>
        public void UpdateCongestionFromTransitLoad( int activeTransitTunnels, int maxTransitTunnels )
        {
            if ( maxTransitTunnels <= 0 )
            {
                Congestion = CongestionLevel.RejectAll;
                return;
            }

            var ratio = (double)activeTransitTunnels / maxTransitTunnels;

            if ( ratio >= 0.95 )
                Congestion = CongestionLevel.RejectAll;
            else if ( ratio >= 0.80 )
                Congestion = CongestionLevel.HighCongestion;
            else if ( ratio >= 0.60 )
                Congestion = CongestionLevel.MediumCongestion;
            else
                Congestion = CongestionLevel.None;
        }

        public RouterContext(): this( (I2PCertificate)null )
        {
        }

        public RouterContext( I2PCertificate cert )
        {
            NewIdentity( cert );
        }

        public RouterContext( string filename )
        {
            Logging.LogInformation( $"RouterContext: Path: {RouterPath}" );

            var fullpath = GetFullPath( filename );

            if ( !File.Exists( fullpath ) )
            {
                Logging.LogInformation( "RouterContext: No existing identity found, generating new one." );
                var dir = Path.GetDirectoryName( fullpath );
                if ( !string.IsNullOrEmpty( dir ) && !Directory.Exists( dir ) )
                    Directory.CreateDirectory( dir );
                NewIdentity( null );
                Save( RouterSettingsFile );
                return;
            }

            try
            {
                Load( fullpath );
            }
            catch ( Exception ex )
            {
                Logging.Log( ex );
                NewIdentity( null );
                Save( RouterSettingsFile );
            }
        }

        private void NewIdentity( I2PCertificate cert )
        {
            Published = new I2PDate( DateTime.UtcNow.AddMinutes( -1 ) );

            // Create certificate with EdDSA signing AND X25519 encryption key types.
            // Both types are stored in the cert payload (4 bytes: 2 sig type + 2 key type).
            // Modern i2pd routers expect X25519 (key type 4) for ECIES support.
            Certificate = cert ?? new I2PCertificate( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );
            // Set the public key type to X25519 in the certificate payload
            Certificate.KeyPublicKeyType = I2PKeyType.KeyTypes.X25519;

            PrivateSigningKey = new I2PSigningPrivateKey( Certificate );
            PublicSigningKey = new I2PSigningPublicKey( PrivateSigningKey );

            // Use X25519 keys - the Certificate now has key type 4 (X25519)
            PrivateKey = new I2PPrivateKey( Certificate );
            PublicKey = new I2PPublicKey( PrivateKey );

            MyRouterIdentity = new I2PRouterIdentity( PublicKey, PublicSigningKey );
            IntroKey.Randomize();
        }

        private void Load( string filename )
        {
            using ( var fs = new FileStream( filename, FileMode.Open, FileAccess.Read ) )
            {
                using ( var ms = new MemoryStream() )
                {
                    byte[] buf = new byte[8192];
                    int len;
                    while ( ( len = fs.Read( buf, 0, buf.Length ) ) != 0 ) ms.Write( buf, 0, len );

                    var reader = new BufRefLen( ms.ToArray() );

                    Certificate = new I2PCertificate( reader );
                    PrivateSigningKey = new I2PSigningPrivateKey( reader, Certificate );
                    PublicSigningKey = new I2PSigningPublicKey( reader, Certificate );

                    PrivateKey = new I2PPrivateKey( reader, Certificate );
                    PublicKey = new I2PPublicKey( reader, Certificate );

                    MyRouterIdentity = new I2PRouterIdentity( reader );
                    Published = new I2PDate( reader );
                    IntroKey = reader.ReadBufLen( 32 );
                }
            }
        }

        public void Save( string filename )
        {
            var fullpath = GetFullPath( filename );

            var dir = Path.GetDirectoryName( fullpath );
            if ( !Directory.Exists( dir ) )
            {
                Directory.CreateDirectory( dir );
            }

            using ( var fs = new FileStream( fullpath, FileMode.Create, FileAccess.Write ) )
            {
                var dest = new BufRefStream();

                Certificate.Write( dest );
                PrivateSigningKey.Write( dest );
                PublicSigningKey.Write( dest );

                PrivateKey.Write( dest );
                PublicKey.Write( dest );

                MyRouterIdentity.Write( dest );
                Published.Write( dest );
                IntroKey.WriteTo( dest );

                var ar = dest.ToArray();
                fs.Write( ar, 0, ar.Length );
            }
        }

        private TickCounter MyRouterInfoCacheCreated = TickCounter.MaxDelta;
        private I2PRouterInfo MyRouterInfoCache = null;

        public I2PRouterInfo MyRouterInfo
        {
            get
            {
                lock ( MyRouterInfoCacheCreated )
                {
                    var cache = MyRouterInfoCache;
                    if ( cache != null &&
                        MyRouterInfoCacheCreated.DeltaToNow < NetDb.RouterInfoExpiryTime / 3 )
                    {
                        return cache;
                    }

                    MyRouterInfoCacheCreated.SetNow();

                    var caps = new I2PMapping();

                    // Build caps per Java I2P Router.getCapabilities():
                    // 1. Single bandwidth char (L if hidden, else from configured class)
                    // 2. Optional 'f' for floodfill (not if hidden)
                    // 3. Optional 'H' for hidden
                    // 4. Reachability: 'U' if hidden/firewalled, 'R' if reachable
                    // 5. Optional congestion flags (only for reachable)
                    var bw = IsHidden ? 'L' : GetBandwidthCapChar();
                    var capsstring = bw.ToString();

                    if ( FloodfillEnabled && !IsHidden ) capsstring += "f";

                    if ( IsHidden ) capsstring += "H";

                    if ( IsHidden || IsFirewalled )
                    {
                        capsstring += "U";
                    }
                    else
                    {
                        capsstring += "R";

                        // Congestion flags only for reachable routers
                        switch ( _congestionLevel )
                        {
                            case CongestionLevel.MediumCongestion:
                                capsstring += "D";
                                break;
                            case CongestionLevel.HighCongestion:
                                capsstring += "E";
                                break;
                            case CongestionLevel.RejectAll:
                                capsstring += "G";
                                break;
                        }
                    }

                    caps["caps"] = capsstring;

                    caps["netId"] = I2PConstants.I2PNetworkId.ToString();
                    caps["router.version"] = I2PConstants.ProtocolVersion;

                    var addresses = RouterAddresses.Values.SelectMany( a => a ).ToArray();
                    var result = new I2PRouterInfo(
                        MyRouterIdentity,
                        new I2PDate( DateTime.UtcNow.AddMinutes( -1 ) ),
                        addresses,
                        caps,
                        PrivateSigningKey );

                    MyRouterInfoCache = result;
                    NetDb.Inst.FloodfillUpdate.TrigUpdateRouterInfo( "MyRouterInfo changed" );

                    Logging.Log( $"RouterContext: New settings: {result}" );

                    return result;
                }
            }
        }

        private void ClearCache()
        {
            MyRouterInfoCache = null;
        }

        private readonly ConcurrentDictionary<ITransportProtocol, List<I2PRouterAddress>> RouterAddresses = new();

        public void UpdateAddress( ITransportProtocol proto, List<I2PRouterAddress> addrs )
        {
            if ( addrs is null )
            {
                RouterAddresses.TryRemove( proto, out _ );
                ClearCache();
                return;
            }

            RouterAddresses[proto] = addrs;
            ClearCache();
        }

        /// <summary>
        /// Force recreation of the RouterInfo for this instance.
        /// </summary>
        public void ApplyNewSettings()
        {
            ClearCache();
            NetworkSettingsChanged?.Invoke();
        }
    }
}
