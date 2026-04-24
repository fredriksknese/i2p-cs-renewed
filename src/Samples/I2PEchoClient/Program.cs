using System;
using I2PCore.Data;
using System.Net.Sockets;
using System.IO;
using System.Threading;
using I2PCore.Utils;
using I2PCore.SessionLayer;
using System.Net;
using System.Collections.Generic;
using I2P.Streaming;
using static I2P.Streaming.StreamingPacket;
using static I2P.I2CP.Messages.I2CpMessage;
using static System.Configuration.ConfigurationManager;

namespace I2PEchoClient
{
    internal class Program
    {
        private static I2PDestinationInfo _myDestinationInfo;
        private static ClientDestination _unpublishedDestination;

        private static bool _connected = false;

        private static void Main( string[] args )
        {
            Logging.ReadAppConfig();
            Logging.LogToDebug = false;
            Logging.LogToConsole = true;

            RouterContext.RouterSettingsFile = "EchoClientRouter.bin";
            RouterContext.Inst = new RouterContext(
                        new I2PCertificate(
                                I2PSigningKey.SigningKeyTypes.DsaSha1 ) );

            for ( int i = 0; i < args.Length; ++i )
            {
                switch ( args[i] )
                {
                    case "--addr":
                    case "--address":
                        if ( args.Length > i + 1 ) 
                        {
                            RouterContext.Inst.DefaultExtAddress = IPAddress.Parse( args[++i] );
                            Console.WriteLine( $"addr {RouterContext.Inst.DefaultExtAddress}" );
                        }
                        else
                        {
                            Console.WriteLine( "--addr require ip number" );
                            return;
                        }
                        break;

                    case "--port":
                        if ( args.Length > i + 1 )
                        {
                            var port = int.Parse( args[++i] );
                            RouterContext.Inst.DefaultTcpPort = port;
                            RouterContext.Inst.DefaultUdpPort = port;
                            Console.WriteLine( $"port {port}" );
                        }
                        else
                        {
                            Console.WriteLine( "--port require port number" );
                            return;
                        }
                        break;
                        
                    case "--nofw":
                        RouterContext.Inst.IsFirewalled = false;
                        Console.WriteLine( $"Firewalled {RouterContext.Inst.IsFirewalled}" );
                        break;

                    default:
                        Console.WriteLine( args[i] );
                        Console.WriteLine( "Usage: I2P.exe --addr 12.34.56.78 --port 8081 --nofw" );
                        break;
                }
            }

            RouterContext.Inst.ApplyNewSettings();
            Router.Start();

            var destb32 = AppSettings["RemoteDestination"];
            var remotedest = new I2PIdentHash( destb32 );

            _myDestinationInfo = new I2PDestinationInfo( I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 );

            _unpublishedDestination = Router.CreateDestination(
                    _myDestinationInfo, 
                    false, 
                    out _ );

            _unpublishedDestination.DataReceived += MyDestination_DataReceived;
            _unpublishedDestination.Name = "UnpublishedDestination";

            Logging.LogInformation( $"MyDestination: {_unpublishedDestination.Destination.IdentHash} {_myDestinationInfo.Destination.Certificate}" );

            var interval = new PeriodicAction( TickSpan.Seconds( 40 ) );

            while ( true )
            {
                try
                {
                    _connected = true;

                    while ( _connected )
                    {
                        Thread.Sleep( 2000 );

                        uint recvid = BufUtils.RandomUintNz();

                        interval.Do( () =>
                        {
                            Logging.LogInformation( $"Program {_unpublishedDestination}: Looking for {remotedest}." );
                            _unpublishedDestination.LookupDestination( remotedest, ( hash, ls, tag ) =>
                            {
                                if ( ls is null )
                                {
                                    Logging.LogInformation( $"Program {_unpublishedDestination}: Failed to lookup {hash.Id32Short}." );
                                    return;
                                }

                                var test = new I2PIdentHash( ls.Destination );
                                Logging.LogInformation( $"Program {_unpublishedDestination}: Found {remotedest}, test: {test.Id32Short}." );

                                var s = new BufRefStream();
                                var sh = new StreamingPacket(
                                        PacketFlags.Synchronize
                                        | PacketFlags.FromIncluded
                                        | PacketFlags.SignatureIncluded
                                        | PacketFlags.MaxPacketSizeIncluded
                                        | PacketFlags.NoAck )
                                {
                                    From = _unpublishedDestination.Destination,
                                    SigningKey = _myDestinationInfo.PrivateSigningKey,
                                    ReceiveStreamId = recvid,
                                    NacKs = new List<uint>(),
                                    Payload = new BufLen( new byte[0] ),
                                };

                                sh.Write( s );
                                var buf = s.ToByteArray();
                                var zipped = LzUtils.BcgZipCompressNew( new BufLen( buf ) );
                                zipped.PokeFlip16( 4353, 4 ); // source port
                                zipped.PokeFlip16( 25, 6 ); // dest port
                                zipped[9] = (byte)PayloadFormat.Streaming; // streaming

                                Logging.LogInformation( $"Program {_unpublishedDestination}: Sending {zipped:20}." );

                                _unpublishedDestination.Send( ls.Destination, zipped );
                            } );
                        } );
                    }
                }
                catch ( SocketException ex )
                {
                    Logging.Log( ex );
                }
                catch ( IOException ex )
                {
                    Logging.Log( ex );
                }
                catch ( Exception ex )
                {
                    Logging.Log( ex );
                }
            }
        }

        private static void MyDestination_DataReceived( ClientDestination dest, BufLen data, I2PDestination sender )
        {
            Logging.LogInformation( $"Program {_unpublishedDestination}: data received {data:20}" );

            var reader = new BufRefLen( data );
            var unzip = LzUtils.BcgZipDecompressNew( (BufLen)reader );
            var packet = new StreamingPacket( (BufRefLen)unzip );

            Logging.LogInformation( $"Program {_unpublishedDestination}: {packet}" );
        }
    }
}
