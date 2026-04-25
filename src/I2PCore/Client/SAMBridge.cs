using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.Streaming;
using I2PCore.TransportLayer;
using I2PCore.Utils;

namespace I2PCore.Client
{
    /// <summary>
    /// SAM v3.3 Bridge implementation.
    /// Listens on a TCP port and provides a text-based protocol for I2P applications
    /// to create sessions, connect streams, and perform naming lookups.
    /// </summary>
    public class SAMBridge : IDisposable
    {
        public const string SAM_VERSION = "3.3";
        public const string SAM_MIN_VERSION = "3.0";
        public const int DEFAULT_PORT = 7656;

        private readonly int _listenPort;
        private readonly IPAddress _listenAddress;
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private Thread _acceptThread;
        private bool _disposed;

        // Active SAM sessions keyed by session ID
        private readonly ConcurrentDictionary<string, SAMSession> _sessions = new();

        // Active client handler tasks
        private readonly ConcurrentDictionary<int, Task> _clientTasks = new();
        private int _clientIdCounter;

        public bool IsRunning { get; private set; }

        // AUTH support (SAM v3.2+)
        public bool AuthEnabled { get; internal set; }
        private readonly ConcurrentDictionary<string, string> _authCredentials = new();

        internal void AddAuthCredential( string user, string password )
        {
            _authCredentials[user] = password;
        }

        internal void RemoveAuthCredential( string user )
        {
            _authCredentials.TryRemove( user, out _ );
        }

        internal void ClearAuthCredentials()
        {
            _authCredentials.Clear();
        }

        internal bool ValidateAuth( string user, string password )
        {
            if ( !AuthEnabled ) return true;
            return _authCredentials.TryGetValue( user, out var storedPassword )
                && storedPassword == password;
        }

        /// <summary>
        /// Create a new SAM Bridge on the specified address and port.
        /// </summary>
        /// <param name="listenAddress">Address to listen on. Defaults to loopback.</param>
        /// <param name="listenPort">Port to listen on. Defaults to 7656.</param>
        public SAMBridge( IPAddress listenAddress = null, int listenPort = DEFAULT_PORT )
        {
            _listenAddress = listenAddress ?? IPAddress.Loopback;
            _listenPort = listenPort;
        }

        /// <summary>
        /// Start accepting SAM client connections.
        /// </summary>
        public void Start()
        {
            if ( IsRunning ) return;

            _cts = new CancellationTokenSource();
            _listener = new TcpListener( _listenAddress, _listenPort );
            _listener.Start();
            IsRunning = true;

            _acceptThread = new Thread( AcceptLoop )
            {
                Name = "SAMBridge",
                IsBackground = true
            };
            _acceptThread.Start();

            Logging.LogInformation( $"SAMBridge: Listening on {_listenAddress}:{_listenPort}" );
        }

        /// <summary>
        /// Stop the SAM Bridge and shut down all sessions.
        /// </summary>
        public void Stop()
        {
            if ( !IsRunning ) return;
            IsRunning = false;

            _cts.Cancel();

            try
            {
                _listener.Stop();
            }
            catch ( Exception ex )
            {
                Logging.LogDebug( $"SAMBridge: Error stopping listener: {ex.Message}" );
            }

            // Shut down all sessions
            foreach ( var kvp in _sessions )
            {
                try
                {
                    kvp.Value.Shutdown();
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug( $"SAMBridge: Error shutting down session {kvp.Key}: {ex.Message}" );
                }
            }
            _sessions.Clear();

            Logging.LogInformation( "SAMBridge: Stopped." );
        }

        private void AcceptLoop()
        {
            while ( !_cts.IsCancellationRequested )
            {
                try
                {
                    var client = _listener.AcceptTcpClient();
                    var clientId = Interlocked.Increment( ref _clientIdCounter );
                    var task = Task.Run( () => HandleClient( client, clientId, _cts.Token ) );
                    _clientTasks[clientId] = task;

                    // Clean up completed client tasks
                    foreach ( var kvp in _clientTasks )
                    {
                        if ( kvp.Value.IsCompleted )
                            _clientTasks.TryRemove( kvp.Key, out _ );
                    }
                }
                catch ( SocketException ) when ( _cts.IsCancellationRequested )
                {
                    break;
                }
                catch ( ObjectDisposedException )
                {
                    break;
                }
                catch ( Exception ex )
                {
                    Logging.LogWarning( $"SAMBridge: Accept error: {ex.Message}" );
                }
            }
        }

        private async Task HandleClient( TcpClient client, int clientId, CancellationToken ct )
        {
            var remoteEp = client.Client.RemoteEndPoint;
            Logging.LogDebug( $"SAMBridge: Client {clientId} connected from {remoteEp}" );

            try
            {
                using ( var stream = client.GetStream() )
                {
                    var handler = new SAMClientHandler( this, stream, ct );
                    await handler.RunAsync();
                }
            }
            catch ( IOException )
            {
                // Client disconnected
            }
            catch ( OperationCanceledException )
            {
                // Shutting down
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"SAMBridge: Client {clientId} error: {ex.Message}" );
            }
            finally
            {
                Logging.LogDebug( $"SAMBridge: Client {clientId} disconnected." );
                _clientTasks.TryRemove( clientId, out _ );
            }
        }

        internal bool TryAddSession( string id, SAMSession session )
        {
            return _sessions.TryAdd( id, session );
        }

        internal bool TryGetSession( string id, out SAMSession session )
        {
            return _sessions.TryGetValue( id, out session );
        }

        internal bool TryRemoveSession( string id )
        {
            if ( _sessions.TryRemove( id, out var session ) )
            {
                session.Shutdown();
                return true;
            }
            return false;
        }

        public void Dispose()
        {
            if ( _disposed ) return;
            _disposed = true;
            Stop();
            _cts?.Dispose();
        }
    }

    /// <summary>
    /// Represents an active SAM session backed by a ClientDestination.
    /// </summary>
    internal class SAMSession
    {
        public string Id { get; }
        public SessionStyle Style { get; }
        public ClientDestination Destination { get; }
        public I2PDestinationInfo DestinationInfo { get; }
        public StreamingDestination Streaming { get; private set; }
        public DatagramDestination Datagram { get; private set; }

        /// <summary>
        /// Subsessions for MASTER style sessions, keyed by subsession ID.
        /// </summary>
        public ConcurrentDictionary<string, SAMSubSession> SubSessions { get; } = new();

        /// <summary>
        /// Event fired when a datagram is received (for Datagram/Raw sessions).
        /// </summary>
        public event Action<I2PDestination, ushort, ushort, byte[]> DatagramReceived;

        public SAMSession( string id, SessionStyle style, ClientDestination destination,
                           I2PDestinationInfo destinationInfo )
        {
            Id = id;
            Style = style;
            Destination = destination;
            DestinationInfo = destinationInfo;

            if ( style == SessionStyle.Stream )
            {
                var destBytes = destination.Destination.ToByteArray();
                Streaming = new StreamingDestination( destination.Destination, 
                    destinationInfo?.PrivateSigningKey, destBytes );
                Streaming.SetSendCallback( ( dest, data ) =>
                {
                    destination.Send( dest, data );
                } );

                destination.DataReceived += ( dest, data, sender ) =>
                {
                    Streaming.HandleDataMessagePayload( data.ToByteArray(), sender );
                };
            }
            else if ( style == SessionStyle.Datagram || style == SessionStyle.Raw )
            {
                Datagram = new DatagramDestination(
                    destination.Destination,
                    destinationInfo?.PrivateSigningKey,
                    ( identHash, data ) =>
                    {
                        // Wrap raw datagram bytes in an I2NP DataMessage for transport
                        var msg = new TunnelLayer.I2NP.Messages.DataMessage( new I2PByteBlock( data ) );
                        TransportProvider.Send( identHash, msg );
                    } );

                Datagram.DatagramReceived += ( sender, args ) =>
                {
                    DatagramReceived?.Invoke(
                        args.Sender, args.FromPort, args.ToPort, args.Payload );
                };
            }
        }

        public void Shutdown()
        {
            try
            {
                // Shut down all subsessions first
                foreach ( var kvp in SubSessions )
                {
                    kvp.Value.Shutdown();
                }
                SubSessions.Clear();

                Streaming?.Dispose();
                Datagram?.Dispose();
                Destination?.Shutdown();
            }
            catch ( Exception ex )
            {
                Logging.LogDebug( $"SAMSession: Error during shutdown of '{Id}': {ex.Message}" );
            }
        }
    }

    /// <summary>
    /// Represents a subsession within a MASTER style SAM session.
    /// </summary>
    internal class SAMSubSession
    {
        public string Id { get; }
        public SessionStyle Style { get; }
        public SAMSession ParentSession { get; }

        public SAMSubSession( string id, SessionStyle style, SAMSession parentSession )
        {
            Id = id;
            Style = style;
            ParentSession = parentSession;
        }

        public void Shutdown()
        {
            Logging.LogDebug( $"SAMSubSession: Shutting down subsession '{Id}'" );
        }
    }

    /// <summary>
    /// Session styles supported by SAM v3.3.
    /// </summary>
    internal enum SessionStyle
    {
        Stream,
        Datagram,
        Raw,
        Master
    }

    /// <summary>
    /// Handles one SAM client TCP connection, parsing text commands and dispatching them.
    /// </summary>
    internal class SAMClientHandler
    {
        private readonly SAMBridge _bridge;
        private readonly Stream _stream;
        private readonly CancellationToken _ct;

        private bool _handshakeDone;
        private string _boundSessionId;

        public SAMClientHandler( SAMBridge bridge, Stream stream, CancellationToken ct )
        {
            _bridge = bridge;
            _stream = stream;
            _ct = ct;
        }

        public async Task RunAsync()
        {
            while ( !_ct.IsCancellationRequested )
            {
                var line = await ReadLineAsync();
                if ( line == null )
                    break; // Client disconnected

                line = line.Trim();
                if ( string.IsNullOrEmpty( line ) )
                    continue;

                Logging.LogDebug( $"SAMBridge: << {line}" );

                try
                {
                    if ( !await DispatchCommandAsync( line ) )
                        break; // Switched to transparent mode or otherwise finished
                }
                catch ( Exception ex )
                {
                    Logging.LogWarning( $"SAMBridge: Command error: {ex.Message}" );
                    await SendReplyAsync( $"ERROR RESULT=I2P_ERROR MESSAGE=\"{EscapeValue( ex.Message )}\"" );
                }
            }
        }

        private async Task<bool> DispatchCommandAsync( string line )
        {
            // SAM commands are: COMMAND SUBCOMMAND [KEY=VALUE ...]
            // Examples:
            //   HELLO VERSION MIN=3.0 MAX=3.1
            //   SESSION CREATE STYLE=STREAM ID=mySession DESTINATION=TRANSIENT
            //   STREAM CONNECT ID=mySession DESTINATION=base64dest
            //   NAMING LOOKUP NAME=host.i2p

            var parts = TokenizeLine( line );
            if ( parts.Count < 1 )
            {
                await SendReplyAsync( "ERROR RESULT=I2P_ERROR MESSAGE=\"Invalid command\"" );
                return true;
            }

            var command = parts[0].ToUpperInvariant();

            // PING is special: "PING [data]" responds with "PONG [data]"
            if ( command == "PING" )
            {
                var pingData = parts.Count > 1 ? string.Join( " ", parts.Skip( 1 ) ) : "";
                await HandlePingAsync( pingData );
                return true;
            }

            if ( parts.Count < 2 )
            {
                await SendReplyAsync( "ERROR RESULT=I2P_ERROR MESSAGE=\"Invalid command\"" );
                return true;
            }

            var subCommand = parts[1].ToUpperInvariant();
            var parameters = ParseParameters( parts, 2 );

            switch ( command )
            {
                case "HELLO":
                    await HandleHelloAsync( subCommand, parameters );
                    return true;

                case "SESSION":
                    await HandleSessionAsync( subCommand, parameters );
                    return true;

                case "STREAM":
                    return await HandleStreamAsync( subCommand, parameters );

                case "NAMING":
                    await HandleNamingAsync( subCommand, parameters );
                    return true;

                case "DEST":
                    await HandleDestAsync( subCommand, parameters );
                    return true;

                case "DATAGRAM":
                    await HandleDatagramAsync( subCommand, parameters );
                    return true;

                case "RAW":
                    await HandleRawAsync( subCommand, parameters );
                    return true;

                case "AUTH":
                    await HandleAuthAsync( subCommand, parameters );
                    return true;

                default:
                    await SendReplyAsync(
                        $"ERROR RESULT=I2P_ERROR MESSAGE=\"Unknown command: {EscapeValue( command )}\"" );
                    return true;
            }
        }

        #region HELLO

        private async Task HandleHelloAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( subCommand != "VERSION" )
            {
                await SendReplyAsync( "HELLO REPLY RESULT=I2P_ERROR MESSAGE=\"Unknown HELLO subcommand\"" );
                return;
            }

            var minVersion = parameters.GetValueOrDefault( "MIN", "3.0" );
            var maxVersion = parameters.GetValueOrDefault( "MAX", "3.3" );

            // Version negotiation: find the highest version both sides support
            var negotiated = NegotiateVersion( minVersion, maxVersion );
            if ( negotiated == null )
            {
                await SendReplyAsync( "HELLO REPLY RESULT=NOVERSION MESSAGE=\"No compatible version\"" );
                return;
            }

            _handshakeDone = true;
            await SendReplyAsync( $"HELLO REPLY RESULT=OK VERSION={negotiated}" );
        }

        private static string NegotiateVersion( string minStr, string maxStr )
        {
            if ( !TryParseVersion( minStr, out var clientMin ) ||
                 !TryParseVersion( maxStr, out var clientMax ) )
                return null;

            var ourMax = ParseVersionUnchecked( SAMBridge.SAM_VERSION );
            var ourMin = ParseVersionUnchecked( SAMBridge.SAM_MIN_VERSION );

            // The negotiated version is the minimum of the two max versions,
            // but it must be >= both minimums
            var negotiated = clientMax <= ourMax ? clientMax : ourMax;
            if ( negotiated < clientMin || negotiated < ourMin )
                return null;

            return negotiated.ToString( System.Globalization.CultureInfo.InvariantCulture );
        }

        private static bool TryParseVersion( string str, out decimal version )
        {
            return decimal.TryParse( str, System.Globalization.NumberStyles.Any,
                System.Globalization.CultureInfo.InvariantCulture, out version );
        }

        private static decimal ParseVersionUnchecked( string str )
        {
            decimal.TryParse( str, System.Globalization.NumberStyles.Any,
                System.Globalization.CultureInfo.InvariantCulture, out var v );
            return v;
        }

        #endregion

        #region SESSION

        private async Task HandleSessionAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( !RequireHandshake() )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Handshake not completed\"" );
                return;
            }

            switch ( subCommand )
            {
                case "CREATE":
                    await HandleSessionCreateAsync( parameters );
                    break;

                case "ADD":
                    await HandleSessionAddAsync( parameters );
                    break;

                case "REMOVE":
                    await HandleSessionRemoveAsync( parameters );
                    break;

                default:
                    await SendReplyAsync(
                        $"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Unknown SESSION subcommand: {EscapeValue( subCommand )}\"" );
                    break;
            }
        }

        private async Task HandleSessionCreateAsync( Dictionary<string, string> parameters )
        {
            // Required: STYLE, ID, DESTINATION
            if ( !parameters.TryGetValue( "STYLE", out var styleStr ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"STYLE not specified\"" );
                return;
            }

            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( string.IsNullOrWhiteSpace( sessionId ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"ID is empty\"" );
                return;
            }

            if ( !TryParseStyle( styleStr, out var style ) )
            {
                await SendReplyAsync(
                    $"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Unknown STYLE: {EscapeValue( styleStr )}\"" );
                return;
            }

            var destParam = parameters.GetValueOrDefault( "DESTINATION", "TRANSIENT" );

            I2PDestinationInfo destInfo;
            try
            {
                destInfo = CreateDestinationInfo( destParam, parameters );
            }
            catch ( Exception ex )
            {
                await SendReplyAsync(
                    $"SESSION STATUS RESULT=INVALID_KEY MESSAGE=\"{EscapeValue( ex.Message )}\"" );
                return;
            }

            ClientDestination clientDest;
            try
            {
                clientDest = Router.CreateDestination( destInfo, true, out var alreadyRunning );
                if ( alreadyRunning )
                {
                    Logging.LogDebug( $"SAMBridge: Reusing existing destination for session '{sessionId}'" );
                }
            }
            catch ( Exception ex )
            {
                await SendReplyAsync(
                    $"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"{EscapeValue( ex.Message )}\"" );
                return;
            }

            clientDest.Name = $"SAM-{sessionId}";

            if ( parameters.TryGetValue( "INBOUND.LENGTH", out var inLengthStr ) && int.TryParse( inLengthStr, out var inLength ) )
            {
                clientDest.InboundTunnelHopCount = inLength;
            }

            if ( parameters.TryGetValue( "OUTBOUND.LENGTH", out var outLengthStr ) && int.TryParse( outLengthStr, out var outLength ) )
            {
                clientDest.OutboundTunnelHopCount = outLength;
            }

            if ( parameters.TryGetValue( "INBOUND.QUANTITY", out var inQtyStr ) && int.TryParse( inQtyStr, out var inQty ) )
            {
                clientDest.TargetInboundTunnelCount = inQty;
            }

            if ( parameters.TryGetValue( "OUTBOUND.QUANTITY", out var outQtyStr ) && int.TryParse( outQtyStr, out var outQty ) )
            {
                clientDest.TargetOutboundTunnelCount = outQty;
            }

            var session = new SAMSession( sessionId, style, clientDest, destInfo );
            if ( !_bridge.TryAddSession( sessionId, session ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=DUPLICATED_ID MESSAGE=\"Session ID already exists\"" );
                return;
            }

            _boundSessionId = sessionId;

            var destBase64 = destInfo.Destination.ToByteArray();
            var destB64Str = FreenetBase64.Encode( new I2PByteBlock( destBase64 ) );

            var privKeyBase64 = destInfo.ToBase64();

            await SendReplyAsync(
                $"SESSION STATUS RESULT=OK DESTINATION={destB64Str}" );

            Logging.LogInformation(
                $"SAMBridge: Session '{sessionId}' created, style={style}, " +
                $"dest={destInfo.Destination.IdentHash.Id32Short}" );
        }

        private static I2PDestinationInfo CreateDestinationInfo( string destParam,
                                                                  Dictionary<string, string> parameters )
        {
            if ( destParam.Equals( "TRANSIENT", StringComparison.OrdinalIgnoreCase ) )
            {
                // Determine signing key type from parameters
                var sigType = I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519;

                if ( parameters.TryGetValue( "SIGNATURE_TYPE", out var sigTypeStr ) )
                {
                    if ( int.TryParse( sigTypeStr, out var sigTypeInt ) )
                    {
                        sigType = (I2PSigningKey.SigningKeyTypes)sigTypeInt;
                    }
                }

                return new I2PDestinationInfo( sigType );
            }
            else
            {
                // Existing destination provided as Base64
                return new I2PDestinationInfo( destParam );
            }
        }

        private static bool TryParseStyle( string styleStr, out SessionStyle style )
        {
            switch ( styleStr.ToUpperInvariant() )
            {
                case "STREAM":
                    style = SessionStyle.Stream;
                    return true;
                case "DATAGRAM":
                    style = SessionStyle.Datagram;
                    return true;
                case "RAW":
                    style = SessionStyle.Raw;
                    return true;
                case "MASTER":
                    style = SessionStyle.Master;
                    return true;
                default:
                    style = default;
                    return false;
            }
        }

        private async Task HandleSessionAddAsync( Dictionary<string, string> parameters )
        {
            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( !_bridge.TryGetSession( sessionId, out var session ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=INVALID_ID MESSAGE=\"Session not found\"" );
                return;
            }

            if ( session.Style != SessionStyle.Master )
            {
                await SendReplyAsync(
                    "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Session is not MASTER style\"" );
                return;
            }

            if ( !parameters.TryGetValue( "STYLE", out var styleStr ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"STYLE not specified\"" );
                return;
            }

            if ( !TryParseStyle( styleStr, out var subStyle ) )
            {
                await SendReplyAsync(
                    $"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Unknown STYLE: {EscapeValue( styleStr )}\"" );
                return;
            }

            // Subsession ID defaults to the main session ID if not provided via a FROM_PORT or similar param
            var subId = parameters.GetValueOrDefault( "ID", sessionId );

            var subSession = new SAMSubSession( subId, subStyle, session );
            if ( !session.SubSessions.TryAdd( subId, subSession ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=DUPLICATED_ID MESSAGE=\"Subsession ID already exists\"" );
                return;
            }

            await SendReplyAsync( "SESSION STATUS RESULT=OK" );
            Logging.LogInformation(
                $"SAMBridge: Subsession '{subId}' added to MASTER session '{sessionId}', style={subStyle}" );
        }

        private async Task HandleSessionRemoveAsync( Dictionary<string, string> parameters )
        {
            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( !_bridge.TryGetSession( sessionId, out var session ) )
            {
                await SendReplyAsync( "SESSION STATUS RESULT=INVALID_ID MESSAGE=\"Session not found\"" );
                return;
            }

            if ( session.Style != SessionStyle.Master )
            {
                await SendReplyAsync(
                    "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Session is not MASTER style\"" );
                return;
            }

            if ( session.SubSessions.TryRemove( sessionId, out var removed ) )
            {
                removed.Shutdown();
                await SendReplyAsync( "SESSION STATUS RESULT=OK" );
                Logging.LogInformation(
                    $"SAMBridge: Subsession '{sessionId}' removed from MASTER session '{session.Id}'" );
            }
            else
            {
                await SendReplyAsync(
                    "SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Subsession not found\"" );
            }
        }

        #endregion

        #region STREAM

        private async Task<bool> HandleStreamAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( !RequireHandshake() )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Handshake not completed\"" );
                return true;
            }

            switch ( subCommand )
            {
                case "CONNECT":
                    await HandleStreamConnectAsync( parameters );
                    return false; // Switched to transparent mode

                case "ACCEPT":
                    await HandleStreamAcceptAsync( parameters );
                    return false; // Switched to transparent mode

                case "FORWARD":
                    await HandleStreamForwardAsync( parameters );
                    return true;

                default:
                    await SendReplyAsync(
                        $"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Unknown STREAM subcommand: {EscapeValue( subCommand )}\"" );
                    return true;
            }
        }

        private async Task HandleStreamConnectAsync( Dictionary<string, string> parameters )
        {
            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( !_bridge.TryGetSession( sessionId, out var session ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=INVALID_ID MESSAGE=\"Session not found\"" );
                return;
            }

            if ( session.Style != SessionStyle.Stream )
            {
                await SendReplyAsync(
                    "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Session is not STREAM style\"" );
                return;
            }

            if ( !parameters.TryGetValue( "DESTINATION", out var destBase64 ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"DESTINATION not specified\"" );
                return;
            }

            I2PDestination remoteDest;
            try
            {
                var destBytes = FreenetBase64.Decode( destBase64 );
                remoteDest = new I2PDestination( new I2PBufferCursor( destBytes ) );
            }
            catch ( Exception ex )
            {
                await SendReplyAsync(
                    $"STREAM STATUS RESULT=INVALID_KEY MESSAGE=\"{EscapeValue( ex.Message )}\"" );
                return;
            }

            // Look up the remote destination to ensure we have a LeaseSet
            var lookupDone = new ManualResetEventSlim( false );
            bool lookupSuccess = false;

            session.Destination.LookupDestination(
                remoteDest.IdentHash,
                ( id, ls, tag ) =>
                {
                    lookupSuccess = ls != null;
                    lookupDone.Set();
                } );

            // Wait for lookup with timeout
            if ( !lookupDone.Wait( TimeSpan.FromSeconds( 30 ) ) )
            {
                await SendReplyAsync(
                    "STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"Destination lookup timed out\"" );
                return;
            }

            if ( !lookupSuccess )
            {
                await SendReplyAsync(
                    "STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"Destination not found\"" );
                return;
            }

            I2PStream i2pStream;
            try
            {
                i2pStream = session.Streaming.CreateStream( remoteDest );
            }
            catch ( Exception ex )
            {
                await SendReplyAsync(
                    $"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"{EscapeValue( ex.Message )}\"" );
                return;
            }

            await SendReplyAsync( "STREAM STATUS RESULT=OK" );

            Logging.LogDebug(
                $"SAMBridge: STREAM CONNECT to {remoteDest.IdentHash.Id32Short} in session '{sessionId}'" );

            // Enter bidirectional data relay mode
            await RelayStreamDataAsync( i2pStream );
        }

        private async Task HandleStreamAcceptAsync( Dictionary<string, string> parameters )
        {
            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( !_bridge.TryGetSession( sessionId, out var session ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=INVALID_ID MESSAGE=\"Session not found\"" );
                return;
            }

            if ( session.Style != SessionStyle.Stream )
            {
                await SendReplyAsync(
                    "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Session is not STREAM style\"" );
                return;
            }

            var silent = parameters.GetValueOrDefault( "SILENT", "false" )
                .Equals( "true", StringComparison.OrdinalIgnoreCase );

            I2PStream i2pStream;
            try
            {
                // Block until an incoming stream arrives
                i2pStream = await session.Streaming.AcceptStreamAsync( _ct );
            }
            catch ( OperationCanceledException )
            {
                return;
            }

            if ( i2pStream == null )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Accept failed\"" );
                return;
            }

            if ( !silent )
            {
                // Send the remote destination before entering relay mode
                // In the SAM spec, the destination is sent as the first line after OK
                await SendReplyAsync( "STREAM STATUS RESULT=OK" );
            }
            else
            {
                await SendReplyAsync( "STREAM STATUS RESULT=OK" );
            }

            Logging.LogDebug(
                $"SAMBridge: STREAM ACCEPT in session '{sessionId}', stream {i2pStream.RecvStreamId:X8}" );

            // Enter bidirectional data relay mode
            await RelayStreamDataAsync( i2pStream );
        }

        private async Task HandleStreamForwardAsync( Dictionary<string, string> parameters )
        {
            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( !_bridge.TryGetSession( sessionId, out var session ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=INVALID_ID MESSAGE=\"Session not found\"" );
                return;
            }

            if ( session.Style != SessionStyle.Stream && session.Style != SessionStyle.Master )
            {
                await SendReplyAsync(
                    "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Session is not STREAM or MASTER style\"" );
                return;
            }

            if ( !parameters.TryGetValue( "PORT", out var portStr ) || !int.TryParse( portStr, out var port ) )
            {
                await SendReplyAsync( "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"PORT not specified or invalid\"" );
                return;
            }

            var host = parameters.GetValueOrDefault( "HOST", "127.0.0.1" );

            var silent = parameters.GetValueOrDefault( "SILENT", "false" )
                .Equals( "true", StringComparison.OrdinalIgnoreCase );

            await SendReplyAsync( "STREAM STATUS RESULT=OK" );

            Logging.LogInformation(
                $"SAMBridge: STREAM FORWARD in session '{sessionId}' to {host}:{port}" );

            // Accept incoming I2P streams and forward them to the local TCP port
            _ = Task.Run( async () =>
            {
                try
                {
                    while ( !_ct.IsCancellationRequested )
                    {
                        I2PStream i2pStream;
                        try
                        {
                            i2pStream = await session.Streaming.AcceptStreamAsync( _ct );
                        }
                        catch ( OperationCanceledException )
                        {
                            break;
                        }

                        if ( i2pStream == null )
                            continue;

                        // Each accepted stream gets its own TCP connection to the local host:port
                        _ = Task.Run( async () =>
                        {
                            try
                            {
                                using ( var tcpClient = new TcpClient() )
                                {
                                    await tcpClient.ConnectAsync( IPAddress.Parse( host ), port );
                                    using ( var tcpStream = tcpClient.GetStream() )
                                    using ( i2pStream )
                                    {
                                        await RelayForwardedStreamAsync( i2pStream, tcpStream );
                                    }
                                }
                            }
                            catch ( Exception ex )
                            {
                                Logging.LogDebug(
                                    $"SAMBridge: STREAM FORWARD relay error: {ex.Message}" );
                            }
                        }, _ct );
                    }
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug(
                        $"SAMBridge: STREAM FORWARD accept loop error: {ex.Message}" );
                }
            }, _ct );
        }

        /// <summary>
        /// Relay data between an accepted I2P stream and a local TCP connection
        /// used by STREAM FORWARD.
        /// </summary>
        private async Task RelayForwardedStreamAsync( I2PStream i2pStream, NetworkStream tcpStream )
        {
            var recvDone = new ManualResetEventSlim( false );

            // I2P stream -> TCP socket
            i2pStream.DataReceived += ( stream, data ) =>
            {
                try
                {
                    tcpStream.Write( data, 0, data.Length );
                    tcpStream.Flush();
                }
                catch ( Exception )
                {
                    recvDone.Set();
                }
            };

            i2pStream.StreamClosed += ( stream ) =>
            {
                recvDone.Set();
            };

            // TCP socket -> I2P stream
            var sendTask = Task.Run( async () =>
            {
                var buffer = new byte[I2PStream.STREAMING_MTU];
                try
                {
                    while ( !_ct.IsCancellationRequested )
                    {
                        var bytesRead = await tcpStream.ReadAsync(
                            buffer, 0, buffer.Length, _ct );
                        if ( bytesRead == 0 )
                            break;

                        var sendBuf = new byte[bytesRead];
                        Array.Copy( buffer, 0, sendBuf, 0, bytesRead );
                        i2pStream.Send( sendBuf );
                    }
                }
                catch ( Exception )
                {
                    // Connection closed
                }
            }, _ct );

            await Task.WhenAny(
                sendTask,
                Task.Run( () => recvDone.Wait( _ct ), _ct ) );

            i2pStream.Close();
        }

        /// <summary>
        /// Relay raw data between the TCP socket and the I2P stream.
        /// After STREAM CONNECT or STREAM ACCEPT succeeds, the SAM socket
        /// becomes a transparent data pipe.
        /// </summary>
        private async Task RelayStreamDataAsync( I2PStream i2pStream )
        {
            using ( i2pStream )
            {
                var recvDone = new ManualResetEventSlim( false );

                // I2P stream -> TCP socket
                i2pStream.DataReceived += ( stream, data ) =>
                {
                    try
                    {
                        _stream.Write( data, 0, data.Length );
                        _stream.Flush();
                    }
                    catch ( Exception )
                    {
                        recvDone.Set();
                    }
                };

                i2pStream.StreamClosed += ( stream ) =>
                {
                    recvDone.Set();
                };

                // TCP socket -> I2P stream
                var sendTask = Task.Run( async () =>
                {
                    var buffer = new byte[I2PStream.STREAMING_MTU];
                    try
                    {
                        while ( !_ct.IsCancellationRequested )
                        {
                            var bytesRead = await _stream.ReadAsync(
                                buffer, 0, buffer.Length, _ct );
                            if ( bytesRead == 0 )
                                break; // Client disconnected

                            var sendBuf = new byte[bytesRead];
                            Array.Copy( buffer, 0, sendBuf, 0, bytesRead );
                            i2pStream.Send( sendBuf );
                        }
                    }
                    catch ( Exception )
                    {
                        // Connection closed
                    }
                }, _ct );

                // Wait for either direction to finish
                await Task.WhenAny(
                    sendTask,
                    Task.Run( () => recvDone.Wait( _ct ), _ct ) );

                i2pStream.Close();
            }
        }

        #endregion

        #region NAMING

        private async Task HandleNamingAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( !RequireHandshake() )
            {
                await SendReplyAsync(
                    "NAMING REPLY RESULT=I2P_ERROR MESSAGE=\"Handshake not completed\"" );
                return;
            }

            if ( subCommand != "LOOKUP" )
            {
                await SendReplyAsync(
                    $"NAMING REPLY RESULT=I2P_ERROR MESSAGE=\"Unknown NAMING subcommand: {EscapeValue( subCommand )}\"" );
                return;
            }

            if ( !parameters.TryGetValue( "NAME", out var name ) )
            {
                await SendReplyAsync( "NAMING REPLY RESULT=I2P_ERROR MESSAGE=\"NAME not specified\"" );
                return;
            }

            // ME returns the destination of the bound session
            if ( name.Equals( "ME", StringComparison.OrdinalIgnoreCase ) )
            {
                if ( _boundSessionId == null || !_bridge.TryGetSession( _boundSessionId, out var session ) )
                {
                    await SendReplyAsync(
                        "NAMING REPLY RESULT=I2P_ERROR NAME=ME MESSAGE=\"No session bound\"" );
                    return;
                }

                var destBytes = session.Destination.Destination.ToByteArray();
                var destB64 = FreenetBase64.Encode( new I2PByteBlock( destBytes ) );
                await SendReplyAsync( $"NAMING REPLY RESULT=OK NAME=ME VALUE={destB64}" );
                return;
            }

            // For .b32.i2p addresses, derive from the base32 hash
            if ( name.EndsWith( ".b32.i2p", StringComparison.OrdinalIgnoreCase ) )
            {
                try
                {
                    var hash = new I2PIdentHash( name );

                    // We need a session to do a lookup
                    if ( _boundSessionId != null &&
                         _bridge.TryGetSession( _boundSessionId, out var session ) )
                    {
                        var lookupDone = new ManualResetEventSlim( false );
                        ILeaseSet foundLs = null;

                        session.Destination.LookupDestination(
                            hash,
                            ( id, ls, tag ) =>
                            {
                                foundLs = ls;
                                lookupDone.Set();
                            } );

                        if ( lookupDone.Wait( TimeSpan.FromSeconds( 30 ) ) && foundLs != null )
                        {
                            var destBytes = foundLs.Destination.ToByteArray();
                            var destB64 = FreenetBase64.Encode( new I2PByteBlock( destBytes ) );
                            await SendReplyAsync(
                                $"NAMING REPLY RESULT=OK NAME={name} VALUE={destB64}" );
                        }
                        else
                        {
                            await SendReplyAsync(
                                $"NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name} MESSAGE=\"Lookup failed\"" );
                        }
                    }
                    else
                    {
                        await SendReplyAsync(
                            $"NAMING REPLY RESULT=I2P_ERROR NAME={name} MESSAGE=\"No session for lookup\"" );
                    }
                }
                catch ( Exception ex )
                {
                    await SendReplyAsync(
                        $"NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name} MESSAGE=\"{EscapeValue( ex.Message )}\"" );
                }
                return;
            }

            // For regular .i2p hostnames, we would need an addressbook/hosts.txt
            // For now, return KEY_NOT_FOUND for unresolvable names
            await SendReplyAsync(
                $"NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name} MESSAGE=\"Name resolution not available\"" );
        }

        #endregion

        #region DEST

        private async Task HandleDestAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( !RequireHandshake() )
            {
                await SendReplyAsync( "DEST REPLY RESULT=I2P_ERROR MESSAGE=\"Handshake not completed\"" );
                return;
            }

            if ( subCommand != "GENERATE" )
            {
                await SendReplyAsync(
                    $"DEST REPLY RESULT=I2P_ERROR MESSAGE=\"Unknown DEST subcommand: {EscapeValue( subCommand )}\"" );
                return;
            }

            // Determine signing key type from parameters
            var sigType = I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519;

            if ( parameters.TryGetValue( "SIGNATURE_TYPE", out var sigTypeStr ) )
            {
                if ( int.TryParse( sigTypeStr, out var sigTypeInt ) )
                {
                    sigType = (I2PSigningKey.SigningKeyTypes)sigTypeInt;
                }
            }

            I2PDestinationInfo destInfo;
            try
            {
                destInfo = new I2PDestinationInfo( sigType );
            }
            catch ( Exception ex )
            {
                await SendReplyAsync(
                    $"DEST REPLY RESULT=I2P_ERROR MESSAGE=\"{EscapeValue( ex.Message )}\"" );
                return;
            }

            var pubBase64 = FreenetBase64.Encode( new I2PByteBlock( destInfo.Destination.ToByteArray() ) );
            var privBase64 = destInfo.ToBase64();

            await SendReplyAsync( $"DEST REPLY PUB={pubBase64} PRIV={privBase64}" );
        }

        #endregion

        #region PING

        private async Task<string> ReadLineAsync()
        {
            var sb = new StringBuilder();
            var oneByte = new byte[1];

            while ( true )
            {
                int read = await _stream.ReadAsync( oneByte, 0, 1, _ct );
                if ( read == 0 ) return sb.Length > 0 ? sb.ToString() : null;

                var b = oneByte[0];
                if ( b == '\n' ) return sb.ToString().TrimEnd( '\r' );
                sb.Append( (char)b );

                if ( sb.Length > 10000 ) throw new InvalidOperationException( "SAM command too long" );
            }
        }
        private async Task HandlePingAsync( string data )
        {
            if ( string.IsNullOrEmpty( data ) )
                await SendReplyAsync( "PONG" );
            else
                await SendReplyAsync( $"PONG {data}" );
        }

        #endregion

        #region Protocol helpers

        private bool RequireHandshake()
        {
            return _handshakeDone;
        }

        private async Task SendReplyAsync( string reply )
        {
            Logging.LogDebug( $"SAMBridge: >> {reply}" );
            var bytes = Encoding.ASCII.GetBytes( reply + "\n" );
            await _stream.WriteAsync( bytes, 0, bytes.Length, _ct );
        }

        /// <summary>
        /// Tokenize a SAM protocol line, respecting quoted values.
        /// Handles: COMMAND SUB KEY=VALUE KEY="quoted value" KEY=unquoted
        /// </summary>
        private static List<string> TokenizeLine( string line )
        {
            var tokens = new List<string>();
            var sb = new StringBuilder();
            bool inQuote = false;

            for ( int i = 0; i < line.Length; i++ )
            {
                char c = line[i];

                if ( inQuote )
                {
                    if ( c == '"' )
                    {
                        inQuote = false;
                    }
                    else if ( c == '\\' && i + 1 < line.Length )
                    {
                        sb.Append( line[++i] );
                    }
                    else
                    {
                        sb.Append( c );
                    }
                }
                else if ( c == '"' )
                {
                    inQuote = true;
                }
                else if ( c == ' ' || c == '\t' )
                {
                    if ( sb.Length > 0 )
                    {
                        tokens.Add( sb.ToString() );
                        sb.Clear();
                    }
                }
                else
                {
                    sb.Append( c );
                }
            }

            if ( sb.Length > 0 )
                tokens.Add( sb.ToString() );

            return tokens;
        }

        /// <summary>
        /// Parse KEY=VALUE pairs from tokens starting at the given offset.
        /// </summary>
        private static Dictionary<string, string> ParseParameters( List<string> tokens, int startIndex )
        {
            var parameters = new Dictionary<string, string>( StringComparer.OrdinalIgnoreCase );

            for ( int i = startIndex; i < tokens.Count; i++ )
            {
                var token = tokens[i];
                var eqIndex = token.IndexOf( '=' );
                if ( eqIndex > 0 )
                {
                    var key = token.Substring( 0, eqIndex ).ToUpperInvariant();
                    var value = token.Substring( eqIndex + 1 );
                    parameters[key] = value;
                }
            }

            return parameters;
        }

        /// <summary>
        /// Escape a string for inclusion in a SAM reply value.
        /// </summary>
        private static string EscapeValue( string value )
        {
            if ( value == null ) return string.Empty;
            return value
                .Replace( "\\", "\\\\" )
                .Replace( "\"", "\\\"" )
                .Replace( "\n", " " )
                .Replace( "\r", "" );
        }

        #endregion

        #region DATAGRAM

        /// <summary>
        /// Handle DATAGRAM SEND command.
        /// Format: DATAGRAM SEND ID=session DESTINATION=base64 [FROM_PORT=n] [TO_PORT=n] SIZE=n\n[payload]
        /// </summary>
        private async Task HandleDatagramAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( !RequireHandshake() )
            {
                await SendReplyAsync( "DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=\"Handshake not completed\"" );
                return;
            }

            if ( subCommand != "SEND" )
            {
                await SendReplyAsync(
                    $"DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=\"Unknown DATAGRAM subcommand: {EscapeValue( subCommand )}\"" );
                return;
            }

            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( !_bridge.TryGetSession( sessionId, out var session ) )
            {
                await SendReplyAsync( "DATAGRAM STATUS RESULT=INVALID_ID MESSAGE=\"Session not found\"" );
                return;
            }

            if ( session.Datagram == null )
            {
                await SendReplyAsync( "DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=\"Session is not a DATAGRAM session\"" );
                return;
            }

            if ( !parameters.TryGetValue( "DESTINATION", out var destStr ) )
            {
                await SendReplyAsync( "DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=\"DESTINATION not specified\"" );
                return;
            }

            if ( !parameters.TryGetValue( "SIZE", out var sizeStr ) || !int.TryParse( sizeStr, out var size ) )
            {
                await SendReplyAsync( "DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=\"SIZE not specified or invalid\"" );
                return;
            }

            ushort fromPort = 0, toPort = 0;
            if ( parameters.TryGetValue( "FROM_PORT", out var fpStr ) )
                ushort.TryParse( fpStr, out fromPort );
            if ( parameters.TryGetValue( "TO_PORT", out var tpStr ) )
                ushort.TryParse( tpStr, out toPort );

            // Read payload bytes
            var payload = new byte[size];
            int totalRead = 0;
            while ( totalRead < size )
            {
                var read = await _stream.ReadAsync( payload, totalRead, size - totalRead, _ct );
                if ( read <= 0 ) break;
                totalRead += read;
            }

            try
            {
                var destBytes = FreenetBase64.Decode( destStr );
                var dest = new I2PDestination( new I2PBufferCursor( destBytes ) );
                var destHash = new I2PIdentHash( dest );

                session.Datagram.SendRepliableDatagram( destHash, payload, fromPort, toPort );
            }
            catch ( Exception ex )
            {
                await SendReplyAsync(
                    $"DATAGRAM STATUS RESULT=I2P_ERROR MESSAGE=\"Send failed: {EscapeValue( ex.Message )}\"" );
            }
        }

        #endregion

        #region RAW

        /// <summary>
        /// Handle RAW SEND command.
        /// Format: RAW SEND ID=session DESTINATION=base64 [FROM_PORT=n] [TO_PORT=n] SIZE=n\n[payload]
        /// </summary>
        private async Task HandleRawAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( !RequireHandshake() )
            {
                await SendReplyAsync( "RAW STATUS RESULT=I2P_ERROR MESSAGE=\"Handshake not completed\"" );
                return;
            }

            if ( subCommand != "SEND" )
            {
                await SendReplyAsync(
                    $"RAW STATUS RESULT=I2P_ERROR MESSAGE=\"Unknown RAW subcommand: {EscapeValue( subCommand )}\"" );
                return;
            }

            if ( !parameters.TryGetValue( "ID", out var sessionId ) )
            {
                await SendReplyAsync( "RAW STATUS RESULT=I2P_ERROR MESSAGE=\"ID not specified\"" );
                return;
            }

            if ( !_bridge.TryGetSession( sessionId, out var session ) )
            {
                await SendReplyAsync( "RAW STATUS RESULT=INVALID_ID MESSAGE=\"Session not found\"" );
                return;
            }

            if ( session.Datagram == null )
            {
                await SendReplyAsync( "RAW STATUS RESULT=I2P_ERROR MESSAGE=\"Session is not a RAW session\"" );
                return;
            }

            if ( !parameters.TryGetValue( "DESTINATION", out var destStr ) )
            {
                await SendReplyAsync( "RAW STATUS RESULT=I2P_ERROR MESSAGE=\"DESTINATION not specified\"" );
                return;
            }

            if ( !parameters.TryGetValue( "SIZE", out var sizeStr ) || !int.TryParse( sizeStr, out var size ) )
            {
                await SendReplyAsync( "RAW STATUS RESULT=I2P_ERROR MESSAGE=\"SIZE not specified or invalid\"" );
                return;
            }

            ushort fromPort = 0, toPort = 0;
            if ( parameters.TryGetValue( "FROM_PORT", out var fpStr ) )
                ushort.TryParse( fpStr, out fromPort );
            if ( parameters.TryGetValue( "TO_PORT", out var tpStr ) )
                ushort.TryParse( tpStr, out toPort );

            // Read payload bytes from the TCP stream
            var payload = new byte[size];
            int totalRead = 0;
            while ( totalRead < size )
            {
                var read = await _stream.ReadAsync( payload, totalRead, size - totalRead, _ct );
                if ( read <= 0 ) break;
                totalRead += read;
            }

            try
            {
                var destBytes = FreenetBase64.Decode( destStr );
                var dest = new I2PDestination( new I2PBufferCursor( destBytes ) );
                var destHash = new I2PIdentHash( dest );

                session.Datagram.SendRawDatagram( destHash, payload, fromPort, toPort );
            }
            catch ( Exception ex )
            {
                await SendReplyAsync(
                    $"RAW STATUS RESULT=I2P_ERROR MESSAGE=\"Send failed: {EscapeValue( ex.Message )}\"" );
            }
        }

        #endregion

        #region AUTH

        /// <summary>
        /// Handle AUTH command (SAM v3.2+)
        /// AUTH ENABLE USER=user PASSWORD=password
        /// AUTH DISABLE
        /// AUTH ADD USER=user PASSWORD=password
        /// AUTH REMOVE USER=user
        /// </summary>
        private async Task HandleAuthAsync( string subCommand, Dictionary<string, string> parameters )
        {
            if ( !RequireHandshake() )
            {
                await SendReplyAsync( "AUTH STATUS RESULT=I2P_ERROR MESSAGE=\"Handshake not completed\"" );
                return;
            }

            switch ( subCommand )
            {
                case "ENABLE":
                    {
                        if ( !parameters.TryGetValue( "USER", out var user ) ||
                             !parameters.TryGetValue( "PASSWORD", out var password ) )
                        {
                            await SendReplyAsync( "AUTH STATUS RESULT=I2P_ERROR MESSAGE=\"USER and PASSWORD required\"" );
                            return;
                        }

                        _bridge.AuthEnabled = true;
                        _bridge.AddAuthCredential( user, password );
                        await SendReplyAsync( "AUTH STATUS RESULT=OK" );
                    }
                    break;

                case "DISABLE":
                    _bridge.AuthEnabled = false;
                    _bridge.ClearAuthCredentials();
                    await SendReplyAsync( "AUTH STATUS RESULT=OK" );
                    break;

                case "ADD":
                    {
                        if ( !parameters.TryGetValue( "USER", out var user ) ||
                             !parameters.TryGetValue( "PASSWORD", out var password ) )
                        {
                            await SendReplyAsync( "AUTH STATUS RESULT=I2P_ERROR MESSAGE=\"USER and PASSWORD required\"" );
                            return;
                        }

                        _bridge.AddAuthCredential( user, password );
                        await SendReplyAsync( "AUTH STATUS RESULT=OK" );
                    }
                    break;

                case "REMOVE":
                    {
                        if ( !parameters.TryGetValue( "USER", out var user ) )
                        {
                            await SendReplyAsync( "AUTH STATUS RESULT=I2P_ERROR MESSAGE=\"USER required\"" );
                            return;
                        }

                        _bridge.RemoveAuthCredential( user );
                        await SendReplyAsync( "AUTH STATUS RESULT=OK" );
                    }
                    break;

                default:
                    await SendReplyAsync(
                        $"AUTH STATUS RESULT=I2P_ERROR MESSAGE=\"Unknown AUTH subcommand: {EscapeValue( subCommand )}\"" );
                    break;
            }
        }

        #endregion
    }
}
