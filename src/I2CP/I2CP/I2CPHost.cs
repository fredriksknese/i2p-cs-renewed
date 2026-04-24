using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.SessionLayer;
using System.Threading;
using System.Net.Sockets;
using System.Net;
using System.Collections.Concurrent;

namespace I2P.I2CP
{
    public class I2CpHost
    {
        private Thread Worker;
        private bool Terminated = false;

        public const int DefaultI2CpPort = 7654;
        private static bool _useIpV6 = false;

        internal ConcurrentDictionary<IPEndPoint, I2CpSession> Sessions = new();

        public I2CpHost()
        {
            Worker = new Thread( RunHost )
            {
                Name = "NTCPHost",
                IsBackground = true
            };
            Worker.Start();
        }

        private void RunHost()
        {
            try
            {
                while ( !Terminated )
                {
                    var listener = new TcpListener( RouterContext.Inst.LocalInterface, DefaultI2CpPort );
                    if ( RouterContext.UseIpV6 ) listener.Server.DualMode = true;
                    listener.Start();

                    try
                    {
                        listener.BeginAcceptTcpClient( HandleListenerAsyncCallback, listener );

                        while ( !Terminated )
                        {
                            Thread.Sleep( 10000 );

                            var stuck = Sessions.Where( s =>
                                    s.Value.LastReception.DeltaToNow > TickSpan.Minutes( 30 ) );

                            foreach ( var one in stuck )
                            {
                                try
                                {
                                    Logging.LogWarning( $"{this}: Terminating stuck session {one} {one.Value.LastReception}" );
                                    one.Value.Terminate();
                                }
                                catch ( Exception ex )
                                {
                                    Logging.Log( ex );
                                }
                            }

                            var terminated = Sessions.Where( s =>
                                    s.Value.CurrentState is null );

                            foreach ( var one in terminated )
                            {
                                try
                                {
                                    Logging.LogInformation( $"{this}: Removing terminated session {one}" );
                                    Sessions.TryRemove( one.Key, out _ );
                                }
                                catch ( Exception ex )
                                {
                                    Logging.Log( ex );
                                }
                            }
                        }
                    }
                    catch ( ThreadAbortException ex )
                    {
                        Logging.Log( ex );
                    }
                    catch ( Exception ex )
                    {
                        Logging.Log( ex );
                    }
                    finally 
                    {
                        listener.Stop();
                    }
                }
            }
            finally
            {
                Terminated = true;
                Worker = null;
            }
        }

        private void HandleListenerAsyncCallback( IAsyncResult ar )
        {
            if ( !ar.IsCompleted ) return;

            var listener = (TcpListener)ar.AsyncState;
            var tcpclient = listener.EndAcceptTcpClient( ar );

            var i2Cpc = new I2CpSession( this, tcpclient );
            Logging.LogInformation( $"{this}: incoming connection ${i2Cpc.DebugId} from {tcpclient.Client.RemoteEndPoint} created." );

            Sessions[(IPEndPoint)tcpclient.Client.RemoteEndPoint] = i2Cpc;

            _ = i2Cpc.Run();

            listener.BeginAcceptTcpClient( HandleListenerAsyncCallback, listener );
        }

        public override string ToString()
        {
            return GetType().Name;
        }
    }
}
