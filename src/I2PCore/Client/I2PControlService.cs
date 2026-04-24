using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;

namespace I2PCore.Client
{
    /// <summary>
    /// I2PControl JSON-RPC service for remote administration.
    /// Listens on a TCP port with TLS/SSL and provides a JSON-RPC interface
    /// for querying router status, managing the router, and configuration.
    /// Disabled by default; must be explicitly started.
    /// </summary>
    public class I2PControlService : IDisposable
    {
        public const int DEFAULT_PORT = 7650;
        private const string DEFAULT_PASSWORD = "itoopie";
        private const int TOKEN_LIFETIME_SECONDS = 600;

        private readonly int _listenPort;
        private readonly IPAddress _listenAddress;
        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private Thread _acceptThread;
        private bool _disposed;

        private string _password;
        private readonly ConcurrentDictionary<string, DateTime> _tokens = new();
        private readonly TickCounter _startTime = new();

        private X509Certificate2 _certificate;

        public bool IsRunning { get; private set; }

        /// <summary>
        /// Create a new I2PControl service on the specified address and port.
        /// </summary>
        /// <param name="listenAddress">Address to listen on. Defaults to loopback.</param>
        /// <param name="listenPort">Port to listen on. Defaults to 7650.</param>
        /// <param name="password">Admin password. Defaults to "itoopie".</param>
        public I2PControlService( IPAddress listenAddress = null, int listenPort = DEFAULT_PORT,
                                  string password = DEFAULT_PASSWORD )
        {
            _listenAddress = listenAddress ?? IPAddress.Loopback;
            _listenPort = listenPort;
            _password = password;
        }

        /// <summary>
        /// Start accepting I2PControl client connections.
        /// </summary>
        public void Start()
        {
            if ( IsRunning ) return;

            _certificate = GenerateSelfSignedCertificate();

            _cts = new CancellationTokenSource();
            _listener = new TcpListener( _listenAddress, _listenPort );
            _listener.Start();
            IsRunning = true;

            _acceptThread = new Thread( AcceptLoop )
            {
                Name = "I2PControlService",
                IsBackground = true
            };
            _acceptThread.Start();

            Logging.LogInformation( $"I2PControlService: Listening on {_listenAddress}:{_listenPort}" );
        }

        /// <summary>
        /// Stop the I2PControl service.
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
                Logging.LogDebug( $"I2PControlService: Error stopping listener: {ex.Message}" );
            }

            _tokens.Clear();
            _certificate?.Dispose();
            _certificate = null;

            Logging.LogInformation( "I2PControlService: Stopped." );
        }

        private void AcceptLoop()
        {
            while ( !_cts.IsCancellationRequested )
            {
                try
                {
                    var client = _listener.AcceptTcpClient();
                    _ = Task.Run( () => HandleClient( client, _cts.Token ) );
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
                    Logging.LogWarning( $"I2PControlService: Accept error: {ex.Message}" );
                }
            }
        }

        private async Task HandleClient( TcpClient client, CancellationToken ct )
        {
            try
            {
                using ( client )
                {
                    SslStream sslStream = null;
                    Stream activeStream;

                    try
                    {
                        sslStream = new SslStream( client.GetStream(), false );
                        await sslStream.AuthenticateAsServerAsync( _certificate );
                        activeStream = sslStream;
                    }
                    catch ( Exception )
                    {
                        // Fall back to plain TCP if TLS handshake fails (e.g. dev/testing)
                        sslStream?.Dispose();
                        activeStream = client.GetStream();
                    }

                    using ( activeStream )
                    using ( var reader = new StreamReader( activeStream, Encoding.UTF8 ) )
                    using ( var writer = new StreamWriter( activeStream, Encoding.UTF8 ) { AutoFlush = true } )
                    {
                        // Read the JSON-RPC request (single line or content-length based)
                        var requestBody = await ReadRequestAsync( reader, ct );
                        if ( string.IsNullOrEmpty( requestBody ) ) return;

                        Logging.LogDebug( $"I2PControlService: << {requestBody}" );

                        var response = ProcessJsonRpcRequest( requestBody );

                        Logging.LogDebug( $"I2PControlService: >> {response}" );
                        await writer.WriteAsync( response );
                    }
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
                Logging.LogWarning( $"I2PControlService: Client error: {ex.Message}" );
            }
        }

        private static async Task<string> ReadRequestAsync( StreamReader reader, CancellationToken ct )
        {
            var sb = new StringBuilder();
            int braceDepth = 0;
            bool started = false;

            while ( !ct.IsCancellationRequested )
            {
                var ch = reader.Read();
                if ( ch == -1 ) break;

                var c = (char)ch;
                sb.Append( c );

                if ( c == '{' )
                {
                    started = true;
                    braceDepth++;
                }
                else if ( c == '}' && started )
                {
                    braceDepth--;
                    if ( braceDepth <= 0 )
                        break;
                }

                // Safety limit
                if ( sb.Length > 65536 ) break;
            }

            return sb.ToString().Trim();
        }

        private string ProcessJsonRpcRequest( string requestJson )
        {
            try
            {
                using var doc = JsonDocument.Parse( requestJson );
                var root = doc.RootElement;

                var id = root.TryGetProperty( "id", out var idElem )
                    ? idElem.GetRawText()
                    : "null";

                if ( !root.TryGetProperty( "method", out var methodElem ) )
                {
                    return BuildErrorResponse( id, -32600, "Missing method" );
                }

                var method = methodElem.GetString();
                var parameters = root.TryGetProperty( "params", out var paramsElem )
                    ? paramsElem
                    : default;

                // Authenticate does not require a token
                if ( string.Equals( method, "Authenticate", StringComparison.OrdinalIgnoreCase ) )
                {
                    return HandleAuthenticate( id, parameters );
                }

                // All other methods require a valid token
                if ( !ValidateToken( parameters ) )
                {
                    return BuildErrorResponse( id, -32003, "Invalid or expired token" );
                }

                switch ( method )
                {
                    case "Echo":
                        return HandleEcho( id, parameters );

                    case "GetRate":
                        return HandleGetRate( id, parameters );

                    case "RouterInfo":
                        return HandleRouterInfo( id, parameters );

                    case "RouterManager":
                        return HandleRouterManager( id, parameters );

                    case "I2PControl":
                        return HandleI2PControl( id, parameters );

                    default:
                        return BuildErrorResponse( id, -32601, $"Method not found: {method}" );
                }
            }
            catch ( JsonException ex )
            {
                return BuildErrorResponse( "null", -32700, $"Parse error: {ex.Message}" );
            }
            catch ( Exception ex )
            {
                return BuildErrorResponse( "null", -32603, $"Internal error: {ex.Message}" );
            }
        }

        private string HandleAuthenticate( string id, JsonElement parameters )
        {
            var password = GetParamString( parameters, "Password" );

            if ( password == null )
            {
                // Try alternative casing
                password = GetParamString( parameters, "API" );
            }

            if ( !string.Equals( password, _password, StringComparison.Ordinal ) )
            {
                return BuildErrorResponse( id, -32001, "Invalid password" );
            }

            var token = GenerateToken();
            _tokens[token] = DateTime.UtcNow;

            // Clean up expired tokens
            CleanExpiredTokens();

            return BuildResultResponse( id, new Dictionary<string, object>
            {
                { "API", 1 },
                { "Token", token }
            } );
        }

        private string HandleEcho( string id, JsonElement parameters )
        {
            var echoValue = GetParamString( parameters, "Echo" ) ?? "";
            return BuildResultResponse( id, new Dictionary<string, object>
            {
                { "Result", echoValue }
            } );
        }

        private string HandleGetRate( string id, JsonElement parameters )
        {
            var stat = GetParamString( parameters, "Stat" ) ?? "";
            var period = GetParamInt( parameters, "Period", 60000 );

            // Return zero rate as a placeholder; real implementation would
            // query the router statistics subsystem.
            return BuildResultResponse( id, new Dictionary<string, object>
            {
                { "Result", 0.0 }
            } );
        }

        private string HandleRouterInfo( string id, JsonElement parameters )
        {
            var result = new Dictionary<string, object>();

            // Collect all requested info parameters
            if ( parameters.ValueKind == JsonValueKind.Object )
            {
                foreach ( var prop in parameters.EnumerateObject() )
                {
                    if ( prop.Name == "Token" ) continue;

                    switch ( prop.Name )
                    {
                        case "i2p.router.status":
                            result["i2p.router.status"] = Router.Started ? "OK" : "NOT_STARTED";
                            break;

                        case "i2p.router.uptime":
                            result["i2p.router.uptime"] = _startTime.DeltaToNowMilliseconds;
                            break;

                        case "i2p.router.version":
                            result["i2p.router.version"] = "0.9.50";
                            break;

                        case "i2p.router.net.status":
                            result["i2p.router.net.status"] = 0; // OK
                            break;

                        case "i2p.router.netdb.knownpeers":
                            result["i2p.router.netdb.knownpeers"] = NetDb.Inst?.RouterCount ?? 0;
                            break;

                        case "i2p.router.net.tunnels.participating":
                            result["i2p.router.net.tunnels.participating"] = 0;
                            break;

                        case "i2p.router.net.bw.inbound.1s":
                            result["i2p.router.net.bw.inbound.1s"] = 0.0;
                            break;

                        case "i2p.router.net.bw.outbound.1s":
                            result["i2p.router.net.bw.outbound.1s"] = 0.0;
                            break;

                        default:
                            result[prop.Name] = null;
                            break;
                    }
                }
            }

            return BuildResultResponse( id, result );
        }

        private string HandleRouterManager( string id, JsonElement parameters )
        {
            var result = new Dictionary<string, object>();

            if ( parameters.ValueKind == JsonValueKind.Object )
            {
                foreach ( var prop in parameters.EnumerateObject() )
                {
                    if ( prop.Name == "Token" ) continue;

                    switch ( prop.Name )
                    {
                        case "Shutdown":
                            Logging.LogInformation( "I2PControlService: Shutdown requested via I2PControl" );
                            result["Shutdown"] = null;
                            // Trigger router shutdown on a background thread
                            System.Threading.ThreadPool.QueueUserWorkItem( _ =>
                            {
                                try
                                {
                                    SessionLayer.Router.Stop();
                                    ClientContext.Inst?.Stop();
                                }
                                catch ( Exception ex )
                                {
                                    Logging.LogWarning( $"I2PControlService: Shutdown error: {ex.Message}" );
                                }
                            } );
                            break;

                        case "ShutdownGraceful":
                            Logging.LogInformation( "I2PControlService: Graceful shutdown requested via I2PControl" );
                            result["ShutdownGraceful"] = null;
                            // Graceful shutdown: stop accepting new tunnels, wait for existing ones
                            System.Threading.ThreadPool.QueueUserWorkItem( _ =>
                            {
                                try
                                {
                                    // Give 60 seconds for tunnels to expire
                                    Logging.LogInformation( "I2PControlService: Graceful shutdown - waiting 60s for tunnels to expire" );
                                    System.Threading.Thread.Sleep( 60000 );
                                    SessionLayer.Router.Stop();
                                    ClientContext.Inst?.Stop();
                                }
                                catch ( Exception ex )
                                {
                                    Logging.LogWarning( $"I2PControlService: Graceful shutdown error: {ex.Message}" );
                                }
                            } );
                            break;

                        case "Reseed":
                            Logging.LogInformation( "I2PControlService: Reseed requested via I2PControl" );
                            result["Reseed"] = null;
                            System.Threading.ThreadPool.QueueUserWorkItem( async _ =>
                            {
                                try { await I2PCore.Bootstrap.NetworkBootstrap(); }
                                catch ( Exception ex )
                                {
                                    Logging.LogWarning( $"I2PControlService: Reseed error: {ex.Message}" );
                                }
                            } );
                            break;

                        default:
                            result[prop.Name] = null;
                            break;
                    }
                }
            }

            return BuildResultResponse( id, result );
        }

        private string HandleI2PControl( string id, JsonElement parameters )
        {
            var result = new Dictionary<string, object>();

            if ( parameters.ValueKind == JsonValueKind.Object )
            {
                foreach ( var prop in parameters.EnumerateObject() )
                {
                    if ( prop.Name == "Token" ) continue;

                    switch ( prop.Name )
                    {
                        case "i2pcontrol.password":
                            var newPassword = prop.Value.GetString();
                            if ( !string.IsNullOrEmpty( newPassword ) )
                            {
                                _password = newPassword;
                                _tokens.Clear();
                                result["i2pcontrol.password"] = null;
                                Logging.LogInformation( "I2PControlService: Password changed via I2PControl" );
                            }
                            break;

                        case "i2pcontrol.port":
                            // Port change would require a restart; log the request
                            result["i2pcontrol.port"] = null;
                            break;

                        default:
                            result[prop.Name] = null;
                            break;
                    }
                }
            }

            return BuildResultResponse( id, result );
        }

        private bool ValidateToken( JsonElement parameters )
        {
            var token = GetParamString( parameters, "Token" );
            if ( string.IsNullOrEmpty( token ) ) return false;

            if ( _tokens.TryGetValue( token, out var created ) )
            {
                if ( ( DateTime.UtcNow - created ).TotalSeconds < TOKEN_LIFETIME_SECONDS )
                {
                    // Refresh the token
                    _tokens[token] = DateTime.UtcNow;
                    return true;
                }

                _tokens.TryRemove( token, out _ );
            }

            return false;
        }

        private void CleanExpiredTokens()
        {
            var now = DateTime.UtcNow;
            foreach ( var kvp in _tokens )
            {
                if ( ( now - kvp.Value ).TotalSeconds >= TOKEN_LIFETIME_SECONDS )
                {
                    _tokens.TryRemove( kvp.Key, out _ );
                }
            }
        }

        private static string GenerateToken()
        {
            var tokenBytes = new byte[16];
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( tokenBytes );
            }
            return Convert.ToBase64String( tokenBytes );
        }

        private static string GetParamString( JsonElement parameters, string name )
        {
            if ( parameters.ValueKind != JsonValueKind.Object ) return null;
            if ( parameters.TryGetProperty( name, out var val ) && val.ValueKind == JsonValueKind.String )
            {
                return val.GetString();
            }
            return null;
        }

        private static int GetParamInt( JsonElement parameters, string name, int defaultValue )
        {
            if ( parameters.ValueKind != JsonValueKind.Object ) return defaultValue;
            if ( parameters.TryGetProperty( name, out var val ) && val.ValueKind == JsonValueKind.Number )
            {
                return val.GetInt32();
            }
            return defaultValue;
        }

        private static string BuildResultResponse( string id, Dictionary<string, object> result )
        {
            var sb = new StringBuilder();
            sb.Append( "{\"id\":" );
            sb.Append( id );
            sb.Append( ",\"result\":{" );

            var first = true;
            foreach ( var kvp in result )
            {
                if ( !first ) sb.Append( ',' );
                first = false;

                sb.Append( '"' );
                sb.Append( EscapeJsonString( kvp.Key ) );
                sb.Append( "\":" );
                sb.Append( FormatJsonValue( kvp.Value ) );
            }

            sb.Append( "},\"jsonrpc\":\"2.0\"}" );
            return sb.ToString();
        }

        private static string BuildErrorResponse( string id, int code, string message )
        {
            return $"{{\"id\":{id},\"error\":{{\"code\":{code},\"message\":\"{EscapeJsonString( message )}\"}},\"jsonrpc\":\"2.0\"}}";
        }

        private static string FormatJsonValue( object value )
        {
            if ( value == null ) return "null";
            if ( value is string s ) return $"\"{EscapeJsonString( s )}\"";
            if ( value is bool b ) return b ? "true" : "false";
            if ( value is double d ) return d.ToString( System.Globalization.CultureInfo.InvariantCulture );
            if ( value is int i ) return i.ToString();
            if ( value is long l ) return l.ToString();
            return $"\"{EscapeJsonString( value.ToString() )}\"";
        }

        private static string EscapeJsonString( string s )
        {
            if ( s == null ) return string.Empty;
            return s.Replace( "\\", "\\\\" )
                    .Replace( "\"", "\\\"" )
                    .Replace( "\n", "\\n" )
                    .Replace( "\r", "\\r" )
                    .Replace( "\t", "\\t" );
        }

        private static X509Certificate2 GenerateSelfSignedCertificate()
        {
            try
            {
                using var rsa = RSA.Create( 2048 );
                var request = new CertificateRequest(
                    "CN=I2PControl",
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1 );

                var cert = request.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays( -1 ),
                    DateTimeOffset.UtcNow.AddYears( 5 ) );

                return cert;
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"I2PControlService: Failed to generate self-signed certificate: {ex.Message}" );
                return null;
            }
        }

        public void Dispose()
        {
            if ( _disposed ) return;
            _disposed = true;
            Stop();
            _cts?.Dispose();
        }
    }
}
