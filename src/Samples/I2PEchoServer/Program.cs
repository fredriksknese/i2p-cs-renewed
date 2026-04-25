using System;
using System.Buffers;
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

namespace I2PEchoServer
{
    internal class Program
    {
        private static I2PDestinationInfo _myDestinationInfo;
        private static ClientDestination _publishedDestination;

        private static bool _connected = false;

        private static void Main( string[] args )
        {
            Logging.ReadAppConfig();
            Logging.LogToDebug = false;
            Logging.LogToConsole = true;

            RouterContext.RouterSettingsFile = "EchoServerRouter.bin";
            //RouterContext.Inst = new RouterContext(
                        //new I2PCertificate(
                                //I2PSigningKey.SigningKeyTypes.EdDSA_SHA512_Ed25519 ) );

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

            var destb32 = AppSettings["Destination"];
            _myDestinationInfo = new I2PDestinationInfo( destb32 );

            _publishedDestination = Router.CreateDestination(
                        _myDestinationInfo,
                        true,
                        out _ );

            _publishedDestination.DataReceived += MyDestination_DataReceived;
            _publishedDestination.Name = "PublishedDestination";

            Logging.LogInformation( $"MyDestination: {_publishedDestination.Destination.IdentHash}.b32.i2p {_myDestinationInfo.Destination.Certificate}" );

            while ( true )
            {
                try
                {
                    _connected = true;

                    while ( _connected )
                    {
                        Thread.Sleep( 2000 );
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

        private static uint _sendId = BufUtils.RandomUintNz();

        private static void MyDestination_DataReceived( ClientDestination dest, I2PByteBlock data, I2PDestination sender )
        {
            Logging.LogInformation( $"Program {_publishedDestination}: data received {data:15}" );

            var unzip = LzUtils.BcgZipDecompressNew( data );
            var packet = new StreamingPacket( new I2PBufferCursor( unzip ) );

            Logging.LogInformation( $"Program {_publishedDestination}: {packet} {packet.Payload}" );

            _publishedDestination.LookupDestination( packet?.From.IdentHash, ( hash, ls, tag ) =>
            {
                if ( ls is null )
                {
                    Logging.LogInformation( $"Program {_publishedDestination}: Failed to lookup {hash?.Id32Short}." );
                    return;
                }

                var s = new ArrayBufferWriter<byte>();
                var sh = new StreamingPacket(
                        PacketFlags.Synchronize
                        | PacketFlags.FromIncluded
                        | PacketFlags.SignatureIncluded
                        | PacketFlags.MaxPacketSizeIncluded
                        | PacketFlags.NoAck )
                {
                    From = _publishedDestination.Destination,
                    SigningKey = _myDestinationInfo.PrivateSigningKey,
                    ReceiveStreamId = packet.ReceiveStreamId,
                    SendStreamId = _sendId,
                    NacKs = new List<uint>(),
                    Payload = new I2PByteBlock( BufUtils.RandomBytes( 30 ) ),
                };

                sh.Write( s );
                var buf = s.WrittenSpan.ToArray();
                var zipped = LzUtils.BcgZipCompressNew( new I2PByteBlock( buf ) );
                zipped.WriteUInt16BigEndian( 4353, 4 ); // source port
                zipped.WriteUInt16BigEndian( 25, 6 ); // dest port
                zipped[9] = (byte)PayloadFormat.Streaming; // streaming

                Logging.LogInformation( $"Program {_publishedDestination}: Sending {zipped:20}." );
                _publishedDestination.Send( ls.Destination, zipped );
            } );
        }
    }
}
