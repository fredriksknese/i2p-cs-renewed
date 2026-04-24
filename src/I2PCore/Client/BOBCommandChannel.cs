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
using I2PCore.Utils;

namespace I2PCore.Client
{
    /// <summary>
    /// BOB (Basic Open Bridge) protocol implementation.
    /// Listens on a TCP port and provides a simple text-based command protocol
    /// for creating and managing I2P tunnels.
    /// Disabled by default; must be explicitly started.
    /// </summary>
    public class BOBCommandChannel : IDisposable
    {
        public const int DEFAULT_PORT = 2827;

        private readonly int _listenPort;
        private readonly IPAddress _listenAddress;
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private Thread _acceptThread;
        private bool _disposed;

        // Active BOB destinations keyed by nickname
        private readonly ConcurrentDictionary<string, BOBDestination> _destinations = new();

        // Active client handler tasks
        private readonly ConcurrentDictionary<int, Task> _clientTasks = new();
        private int _clientIdCounter;

        public bool IsRunning { get; private set; }

        /// <summary>
        /// Create a new BOB Command Channel on the specified address and port.
        /// </summary>
        /// <param name="listenAddress">Address to listen on. Defaults to loopback.</param>
        /// <param name="listenPort">Port to listen on. Defaults to 2827.</param>
        public BOBCommandChannel( IPAddress listenAddress = null, int listenPort = DEFAULT_PORT )
        {
            _listenAddress = listenAddress ?? IPAddress.Loopback;
            _listenPort = listenPort;
        }

        /// <summary>
        /// Start accepting BOB client connections.
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
                Name = "BOBCommandChannel",
                IsBackground = true
            };
            _acceptThread.Start();

            Logging.LogInformation( $"BOBCommandChannel: Listening on {_listenAddress}:{_listenPort}" );
        }

        /// <summary>
        /// Stop the BOB Command Channel and shut down all destinations.
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
                Logging.LogDebug( $"BOBCommandChannel: Error stopping listener: {ex.Message}" );
            }

            foreach ( var kvp in _destinations )
            {
                try
                {
                    kvp.Value.Shutdown();
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug( $"BOBCommandChannel: Error shutting down destination '{kvp.Key}': {ex.Message}" );
                }
            }
            _destinations.Clear();

            Logging.LogInformation( "BOBCommandChannel: Stopped." );
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
                    Logging.LogWarning( $"BOBCommandChannel: Accept error: {ex.Message}" );
                }
            }
        }

        private async Task HandleClient( TcpClient client, int clientId, CancellationToken ct )
        {
            var remoteEp = client.Client.RemoteEndPoint;
            Logging.LogDebug( $"BOBCommandChannel: Client {clientId} connected from {remoteEp}" );

            try
            {
                using ( client )
                using ( var stream = client.GetStream() )
                using ( var reader = new StreamReader( stream, Encoding.ASCII ) )
                using ( var writer = new StreamWriter( stream, Encoding.ASCII ) { AutoFlush = true } )
                {
                    await writer.WriteLineAsync( "BOB 00.00.10" );

                    var handler = new BOBClientHandler( this, reader, writer, ct );
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
                Logging.LogWarning( $"BOBCommandChannel: Client {clientId} error: {ex.Message}" );
            }
            finally
            {
                Logging.LogDebug( $"BOBCommandChannel: Client {clientId} disconnected." );
                _clientTasks.TryRemove( clientId, out _ );
            }
        }

        internal bool TryGetDestination( string nick, out BOBDestination dest )
        {
            return _destinations.TryGetValue( nick, out dest );
        }

        internal bool TryAddDestination( string nick, BOBDestination dest )
        {
            return _destinations.TryAdd( nick, dest );
        }

        internal bool TryRemoveDestination( string nick )
        {
            if ( _destinations.TryRemove( nick, out var dest ) )
            {
                dest.Shutdown();
                return true;
            }
            return false;
        }

        internal IEnumerable<KeyValuePair<string, BOBDestination>> GetAllDestinations()
        {
            return _destinations.ToArray();
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
    /// Represents a BOB destination with associated tunnels and forwarding configuration.
    /// </summary>
    internal class BOBDestination
    {
        public string Nickname { get; set; }
        public I2PDestinationInfo DestinationInfo { get; set; }
        public ClientDestination ClientDestination { get; private set; }
        public bool IsRunning { get; private set; }

        // Forwarding configuration
        public string OutHost { get; set; } = "localhost";
        public int OutPort { get; set; }
        public string InHost { get; set; } = "localhost";
        public int InPort { get; set; }

        public bool Quiet { get; set; }

        // Tunnel type: "client", "server", "socks", "httpproxy"
        public string TunnelType { get; set; } = "client";

        // Options
        public Dictionary<string, string> Options { get; } = new( StringComparer.OrdinalIgnoreCase );

        public void Start()
        {
            if ( IsRunning ) return;

            if ( DestinationInfo == null )
            {
                throw new InvalidOperationException( "No keys set for this destination" );
            }

            ClientDestination = Router.CreateDestination( DestinationInfo, true, out _ );
            ClientDestination.Name = $"BOB-{Nickname}";
            IsRunning = true;

            Logging.LogInformation( $"BOBDestination: '{Nickname}' started." );
        }

        public void Stop()
        {
            if ( !IsRunning ) return;
            IsRunning = false;

            try
            {
                ClientDestination?.Shutdown();
            }
            catch ( Exception ex )
            {
                Logging.LogDebug( $"BOBDestination: Error stopping '{Nickname}': {ex.Message}" );
            }

            ClientDestination = null;
            Logging.LogInformation( $"BOBDestination: '{Nickname}' stopped." );
        }

        public void Shutdown()
        {
            Stop();
        }

        public string GetDestinationBase64()
        {
            if ( DestinationInfo == null ) return null;
            var destBytes = DestinationInfo.Destination.ToByteArray();
            return FreenetBase64.Encode( new BufLen( destBytes ) );
        }
    }

    /// <summary>
    /// Handles one BOB client TCP connection, parsing text commands line by line.
    /// </summary>
    internal class BOBClientHandler
    {
        private readonly BOBCommandChannel _channel;
        private readonly StreamReader _reader;
        private readonly StreamWriter _writer;
        private readonly CancellationToken _ct;

        // Current session state
        private string _currentNick;
        private BOBDestination _currentDest;

        public BOBClientHandler( BOBCommandChannel channel, StreamReader reader,
                                 StreamWriter writer, CancellationToken ct )
        {
            _channel = channel;
            _reader = reader;
            _writer = writer;
            _ct = ct;
        }

        public async Task RunAsync()
        {
            while ( !_ct.IsCancellationRequested )
            {
                var line = await _reader.ReadLineAsync();
                if ( line == null )
                    break;

                line = line.Trim();
                if ( string.IsNullOrEmpty( line ) )
                    continue;

                Logging.LogDebug( $"BOBCommandChannel: << {line}" );

                try
                {
                    var quit = await DispatchCommandAsync( line );
                    if ( quit ) break;
                }
                catch ( Exception ex )
                {
                    Logging.LogWarning( $"BOBCommandChannel: Command error: {ex.Message}" );
                    await Reply( $"ERROR {ex.Message}" );
                }
            }
        }

        private async Task<bool> DispatchCommandAsync( string line )
        {
            var spaceIndex = line.IndexOf( ' ' );
            string command;
            string args;

            if ( spaceIndex >= 0 )
            {
                command = line.Substring( 0, spaceIndex ).ToLowerInvariant();
                args = line.Substring( spaceIndex + 1 ).Trim();
            }
            else
            {
                command = line.ToLowerInvariant();
                args = string.Empty;
            }

            switch ( command )
            {
                case "setnick":
                    await HandleSetNick( args );
                    break;

                case "getnick":
                    await HandleGetNick( args );
                    break;

                case "newkeys":
                    await HandleNewKeys();
                    break;

                case "getkeys":
                    await HandleGetKeys();
                    break;

                case "setkeys":
                    await HandleSetKeys( args );
                    break;

                case "getdest":
                    await HandleGetDest();
                    break;

                case "outhost":
                    await HandleOutHost( args );
                    break;

                case "outport":
                    await HandleOutPort( args );
                    break;

                case "inhost":
                    await HandleInHost( args );
                    break;

                case "inport":
                    await HandleInPort( args );
                    break;

                case "start":
                    await HandleStart();
                    break;

                case "stop":
                    await HandleStop();
                    break;

                case "clear":
                    await HandleClear();
                    break;

                case "list":
                    await HandleList();
                    break;

                case "option":
                    await HandleOption( args );
                    break;

                case "status":
                    await HandleStatus( args );
                    break;

                case "help":
                    await HandleHelp();
                    break;

                case "quit":
                    await Reply( "OK Bye!" );
                    return true;

                case "lookup":
                    await HandleLookup( args );
                    break;

                case "lookuplocal":
                    await HandleLookupLocal( args );
                    break;

                case "ping":
                    await Reply( "OK" );
                    break;

                case "zap":
                    await Reply( "OK Bye!" );
                    // Signal the BOB server to shut down
                    Logging.LogInformation( "BOB: 'zap' received, shutting down BOB server" );
                    return true; // Signal shutdown

                case "settunneltype":
                    await HandleSetTunnelType( args );
                    break;

                default:
                    await Reply( $"ERROR unknown command: {command}" );
                    break;
            }

            return false;
        }

        private async Task HandleSetTunnelType( string tunnelType )
        {
            if ( string.IsNullOrWhiteSpace( tunnelType ) )
            {
                await Reply( "ERROR no tunnel type specified" );
                return;
            }

            if ( _currentDest == null )
            {
                await Reply( "ERROR no current destination" );
                return;
            }

            tunnelType = tunnelType.Trim().ToLowerInvariant();
            if ( tunnelType != "client" && tunnelType != "server"
                && tunnelType != "socks" && tunnelType != "httpproxy" )
            {
                await Reply( $"ERROR unknown tunnel type: {tunnelType}" );
                return;
            }

            // Store tunnel type on the current destination
            _currentDest.TunnelType = tunnelType;

            await Reply( $"OK tunnel type set to {tunnelType}" );
        }

        private async Task HandleSetNick( string nick )
        {
            if ( string.IsNullOrWhiteSpace( nick ) )
            {
                await Reply( "ERROR no nickname specified" );
                return;
            }

            if ( _channel.TryGetDestination( nick, out var existing ) )
            {
                _currentNick = nick;
                _currentDest = existing;
                await Reply( $"OK Nickname set to {nick}" );
                return;
            }

            var dest = new BOBDestination { Nickname = nick };
            if ( _channel.TryAddDestination( nick, dest ) )
            {
                _currentNick = nick;
                _currentDest = dest;
                await Reply( $"OK Nickname set to {nick}" );
            }
            else
            {
                // Race: someone else added it
                _channel.TryGetDestination( nick, out dest );
                _currentNick = nick;
                _currentDest = dest;
                await Reply( $"OK Nickname set to {nick}" );
            }
        }

        private async Task HandleGetNick( string nick )
        {
            if ( string.IsNullOrWhiteSpace( nick ) )
            {
                await Reply( "ERROR no nickname specified" );
                return;
            }

            if ( _channel.TryGetDestination( nick, out var dest ) )
            {
                _currentNick = nick;
                _currentDest = dest;
                await Reply( $"OK Nickname set to {nick}" );
            }
            else
            {
                await Reply( $"ERROR nickname {nick} not found" );
            }
        }

        private async Task HandleNewKeys()
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( _currentDest.IsRunning )
            {
                await Reply( "ERROR tunnel is running" );
                return;
            }

            _currentDest.DestinationInfo = new I2PDestinationInfo(
                I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );

            var destB64 = _currentDest.GetDestinationBase64();
            await Reply( $"OK {destB64}" );
        }

        private async Task HandleGetKeys()
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( _currentDest.DestinationInfo == null )
            {
                await Reply( "ERROR no keys set" );
                return;
            }

            var privB64 = _currentDest.DestinationInfo.ToBase64();
            await Reply( $"OK {privB64}" );
        }

        private async Task HandleSetKeys( string keysBase64 )
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( _currentDest.IsRunning )
            {
                await Reply( "ERROR tunnel is running" );
                return;
            }

            if ( string.IsNullOrWhiteSpace( keysBase64 ) )
            {
                await Reply( "ERROR no keys specified" );
                return;
            }

            try
            {
                _currentDest.DestinationInfo = new I2PDestinationInfo( keysBase64 );
                var destB64 = _currentDest.GetDestinationBase64();
                await Reply( $"OK {destB64}" );
            }
            catch ( Exception ex )
            {
                await Reply( $"ERROR invalid keys: {ex.Message}" );
            }
        }

        private async Task HandleGetDest()
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            var destB64 = _currentDest.GetDestinationBase64();
            if ( destB64 == null )
            {
                await Reply( "ERROR no keys set" );
                return;
            }

            await Reply( $"OK {destB64}" );
        }

        private async Task HandleOutHost( string host )
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( string.IsNullOrWhiteSpace( host ) )
            {
                await Reply( "ERROR no host specified" );
                return;
            }

            _currentDest.OutHost = host;
            await Reply( $"OK outhost set to {host}" );
        }

        private async Task HandleOutPort( string portStr )
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( !int.TryParse( portStr, out var port ) || port < 0 || port > 65535 )
            {
                await Reply( "ERROR invalid port" );
                return;
            }

            _currentDest.OutPort = port;
            await Reply( $"OK outport set to {port}" );
        }

        private async Task HandleInHost( string host )
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( string.IsNullOrWhiteSpace( host ) )
            {
                await Reply( "ERROR no host specified" );
                return;
            }

            _currentDest.InHost = host;
            await Reply( $"OK inhost set to {host}" );
        }

        private async Task HandleInPort( string portStr )
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( !int.TryParse( portStr, out var port ) || port < 0 || port > 65535 )
            {
                await Reply( "ERROR invalid port" );
                return;
            }

            _currentDest.InPort = port;
            await Reply( $"OK inport set to {port}" );
        }

        private async Task HandleStart()
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( _currentDest.IsRunning )
            {
                await Reply( "ERROR tunnel is already running" );
                return;
            }

            try
            {
                _currentDest.Start();
                await Reply( "OK tunnel starting" );
            }
            catch ( Exception ex )
            {
                await Reply( $"ERROR {ex.Message}" );
            }
        }

        private async Task HandleStop()
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( !_currentDest.IsRunning )
            {
                await Reply( "ERROR tunnel is not running" );
                return;
            }

            _currentDest.Stop();
            await Reply( "OK tunnel stopping" );
        }

        private async Task HandleClear()
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( _currentDest.IsRunning )
            {
                await Reply( "ERROR tunnel is running, stop it first" );
                return;
            }

            _channel.TryRemoveDestination( _currentNick );
            _currentNick = null;
            _currentDest = null;
            await Reply( "OK cleared" );
        }

        private async Task HandleList()
        {
            var sb = new StringBuilder();
            sb.AppendLine( "OK Listing" );

            foreach ( var kvp in _channel.GetAllDestinations() )
            {
                var d = kvp.Value;
                var status = d.IsRunning ? "RUNNING" : "STOPPED";
                sb.AppendLine( $"DATA NICKNAME: {kvp.Key} STARTING: false RUNNING: {d.IsRunning} STOPPING: false KEYS: {( d.DestinationInfo != null ? "true" : "false" )} QUIET: {d.Quiet} INPORT: {d.InPort} INHOST: {d.InHost} OUTPORT: {d.OutPort} OUTHOST: {d.OutHost}" );
            }

            sb.Append( "OK Listing done" );
            await Reply( sb.ToString() );
        }

        private async Task HandleOption( string optionStr )
        {
            if ( _currentDest == null )
            {
                await Reply( "ERROR no current nickname" );
                return;
            }

            if ( string.IsNullOrWhiteSpace( optionStr ) )
            {
                await Reply( "ERROR no option specified" );
                return;
            }

            var eqIndex = optionStr.IndexOf( '=' );
            if ( eqIndex <= 0 )
            {
                await Reply( "ERROR invalid option format, use KEY=VALUE" );
                return;
            }

            var key = optionStr.Substring( 0, eqIndex ).Trim();
            var value = optionStr.Substring( eqIndex + 1 ).Trim();
            _currentDest.Options[key] = value;

            if ( key.Equals( "quiet", StringComparison.OrdinalIgnoreCase ) )
            {
                _currentDest.Quiet = value.Equals( "true", StringComparison.OrdinalIgnoreCase );
            }

            await Reply( $"OK {key}={value}" );
        }

        private async Task HandleStatus( string nick )
        {
            if ( string.IsNullOrWhiteSpace( nick ) )
            {
                nick = _currentNick;
            }

            if ( string.IsNullOrWhiteSpace( nick ) )
            {
                await Reply( "ERROR no nickname specified" );
                return;
            }

            if ( !_channel.TryGetDestination( nick, out var dest ) )
            {
                await Reply( $"ERROR nickname {nick} not found" );
                return;
            }

            var status = dest.IsRunning ? "RUNNING" : "STOPPED";
            await Reply( $"OK {status}" );
        }

        private async Task HandleHelp()
        {
            var sb = new StringBuilder();
            sb.AppendLine( "OK Help" );
            sb.AppendLine( "setnick <nick>      - Create or set current nickname" );
            sb.AppendLine( "getnick <nick>      - Set current nickname to existing destination" );
            sb.AppendLine( "newkeys             - Generate new keys for current nickname" );
            sb.AppendLine( "getkeys             - Get private keys for current nickname" );
            sb.AppendLine( "setkeys <base64>    - Set private keys for current nickname" );
            sb.AppendLine( "getdest             - Get destination for current nickname" );
            sb.AppendLine( "outhost <host>      - Set outbound host" );
            sb.AppendLine( "outport <port>      - Set outbound port" );
            sb.AppendLine( "inhost <host>       - Set inbound host" );
            sb.AppendLine( "inport <port>       - Set inbound port" );
            sb.AppendLine( "start               - Start the tunnel" );
            sb.AppendLine( "stop                - Stop the tunnel" );
            sb.AppendLine( "clear               - Remove the current destination" );
            sb.AppendLine( "list                - List all destinations" );
            sb.AppendLine( "option <key=value>  - Set an option" );
            sb.AppendLine( "status [<nick>]     - Get status of a destination" );
            sb.AppendLine( "lookup <name>       - Look up a destination by name" );
            sb.AppendLine( "lookuplocal <name>  - Look up a destination locally" );
            sb.AppendLine( "ping                - Ping" );
            sb.AppendLine( "help                - This help text" );
            sb.Append( "quit                - Close connection" );
            await Reply( sb.ToString() );
        }

        private async Task HandleLookup( string name )
        {
            if ( string.IsNullOrWhiteSpace( name ) )
            {
                await Reply( "ERROR no name specified" );
                return;
            }

            // For .b32.i2p addresses, try to resolve via IdentResolver
            try
            {
                var hash = new I2PIdentHash( name );
                var ri = NetDb.Inst[hash];
                if ( ri != null )
                {
                    var destB64 = FreenetBase64.Encode( new BufLen( ri.Identity.ToByteArray() ) );
                    await Reply( $"OK {destB64}" );
                    return;
                }
            }
            catch
            {
                // Not a valid hash, try other methods
            }

            await Reply( $"ERROR lookup for {name} failed" );
        }

        private async Task HandleLookupLocal( string name )
        {
            if ( string.IsNullOrWhiteSpace( name ) )
            {
                await Reply( "ERROR no name specified" );
                return;
            }

            try
            {
                var hash = new I2PIdentHash( name );
                var ri = NetDb.Inst[hash];
                if ( ri != null )
                {
                    var destB64 = FreenetBase64.Encode( new BufLen( ri.Identity.ToByteArray() ) );
                    await Reply( $"OK {destB64}" );
                    return;
                }
            }
            catch
            {
                // Not a valid hash
            }

            await Reply( $"ERROR local lookup for {name} failed" );
        }

        private async Task Reply( string msg )
        {
            Logging.LogDebug( $"BOBCommandChannel: >> {msg}" );
            await _writer.WriteLineAsync( msg );
        }
    }
}
