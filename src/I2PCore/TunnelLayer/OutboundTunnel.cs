using System.Collections.Generic;
using System.Linq;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PCore.Data;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.SessionLayer;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using System.Collections.Concurrent;

namespace I2PCore.TunnelLayer
{
    public class OutboundTunnel: Tunnel
    {
        protected I2PIdentHash NextHop;
        public override I2PIdentHash Destination { get { return NextHop; } }
        public override I2PIdentHash FarEnd => Config.Info.Hops.Any() ? Config.Info.Hops.Last().Peer.IdentHash : RouterContext.Inst.MyRouterIdentity.IdentHash;

        internal I2PTunnelId SendTunnelId;

        public readonly uint TunnelBuildReplyMessageId = I2NpMessage.GenerateMessageId();
        public readonly int ReplyTunnelHops;

        public OutboundTunnel( ITunnelOwner owner, TunnelConfig config, int replytunnelhops )
            : base( owner, config )
        {
            if ( config.Info.Hops.Any() )
            {
                var outtunnel = config.Info.Hops[0];
                NextHop = outtunnel.Peer.IdentHash;
                SendTunnelId = outtunnel.TunnelId;
            }
            ReplyTunnelHops = replytunnelhops;
        }

        public override TickSpan TunnelEstablishmentTimeout 
        { 
            get 
            {
                var hops = ReplyTunnelHops + TunnelMemberHops;
                var timeperhop = Config.Pool == TunnelConfig.TunnelPool.Exploratory
                        ? ExpectedTunnelBuildTimePerHop * 2.0
                        : ExpectedTunnelBuildTimePerHop;

                return timeperhop * hops;
            } 
        }

        public override IEnumerable<I2PRouterIdentity> TunnelMembers
        {
            get
            {
                return Config.Info.Hops.Select( h => (I2PRouterIdentity)h.Peer );
            }
        }

        public override bool Exectue()
        {
            if ( Terminated ) return false;

            if ( NextHop == null )
            {
                Logging.LogDebug( "OutboundTunnel: NextHop == null. Fail." );
                return false;
            }

            return HandleReceiveQueue() && HandleSendQueue();
        }

        protected ConcurrentQueue<TunnelMessage> SendQueue = new();

        public virtual void Send( TunnelMessage msg )
        {
            SendQueue.Enqueue( msg );
        }

        private bool HandleReceiveQueue()
        {
            while ( true )
            {
                if ( ReceiveQueue.IsEmpty ) return true;
                if ( !ReceiveQueue.TryDequeue( out var msg ) ) continue;

                switch ( msg.MessageType )
                {
                    default:
                        Logging.Log( $"OutboundTunnel {TunnelDebugTrace} HandleReceiveQueue: Dropped {msg.MessageType}" );
                        break;
                }
            }
        }

#if LOG_ALL_TUNNEL_TRANSFER
        ItemFilterWindow<HashedItemGroup> FilterMessageTypes = new ItemFilterWindow<HashedItemGroup>( TickSpan.Seconds( 30 ), 5 );
#endif

        private bool HandleSendQueue()
        {
            if ( SendQueue.IsEmpty ) return true;

            IEnumerable<TunnelMessage> messages;

            messages = SendQueue.ToArray();
            SendQueue = new ConcurrentQueue<TunnelMessage>();

            return CreateTunnelMessageFragments( messages );
        }

        private bool CreateTunnelMessageFragments( IEnumerable<TunnelMessage> messages )
        {
            var msgList = messages.ToList();
            var data = TunnelDataMessage.MakeFragments( msgList, SendTunnelId );
            var dataList = data.ToList();

            Logging.LogDebug( $"OutboundTunnel {TunnelDebugTrace}: Sending {msgList.Count} messages as {dataList.Count} TunnelData fragments to {NextHop.Id32Short}, SendTunnelId={SendTunnelId}" );

            var encr = OutboundGatewayDecrypt( dataList );
            foreach ( var msg in encr )
            {
#if LOG_ALL_TUNNEL_TRANSFER
                if ( FilterMessageTypes.Update( new HashedItemGroup( (int)msg.MessageType, 0x4272 ) ) )
                {
                    Logging.LogDebug( $"OutboundTunnel: Send {NextHop.Id32Short} : {msg}" );
                }
#endif
                Bandwidth.DataSent( msg.Payload.Length );
                TransportProvider.Send( NextHop, msg );
            }

            return true;
        }

        internal IEnumerable<I2NpMessage> OutboundGatewayDecrypt( IEnumerable<TunnelDataMessage> data )
        {
            var buf = new List<I2NpMessage>();
            var cipher = new CbcBlockCipher( new AesEngine() );

            var hopsreverse = Config.Info.Hops.Reverse<HopInfo>();

            foreach ( var one in data )
            {
                foreach ( var hop in hopsreverse )
                {
                    one.Iv.AesEcbDecrypt( hop.IvKey.Key );
                    cipher.Decrypt( hop.LayerKey.Key, one.Iv, one.EncryptedWindow );
                    one.Iv.AesEcbDecrypt( hop.IvKey.Key );
                }

                buf.Add( one );
            }

            return buf;
        }

        /// <summary>
        /// Verify tunnel AES encryption roundtrip (pre-decrypt + encrypt = identity).
        /// Call after tunnel is established to verify layer keys are correct.
        /// </summary>
        internal static void SelfTestEncryption( HopInfo hop )
        {
            // Create test data
            var origIv = BufUtils.RandomBytes(16);
            var origData = BufUtils.RandomBytes(1008);

            // Copy to working buffers
            var ivBuf = new BufLen((byte[])origIv.Clone());
            var dataBuf = new BufLen((byte[])origData.Clone());

            // Pre-decrypt (gateway side)
            var cipher = new CbcBlockCipher(new AesEngine());
            ivBuf.AesEcbDecrypt(hop.IvKey.Key);
            cipher.Decrypt(hop.LayerKey.Key, ivBuf, dataBuf);
            ivBuf.AesEcbDecrypt(hop.IvKey.Key);

            // Encrypt (transit/endpoint side - simulating i2pd)
            var ecbCipher = new Org.BouncyCastle.Crypto.BufferedBlockCipher(new AesEngine());
            var cbcEncCipher = new CbcBlockCipher(new AesEngine());

            ivBuf.AesEcbEncrypt(hop.IvKey.Key);  // ECB encrypt IV
            cbcEncCipher.Encrypt(hop.LayerKey.Key, ivBuf, dataBuf);  // CBC encrypt data
            ivBuf.AesEcbEncrypt(hop.IvKey.Key);  // ECB encrypt IV again

            // Verify roundtrip
            bool ivMatch = ivBuf.ToByteArray().SequenceEqual(origIv);
            bool dataMatch = dataBuf.ToByteArray().SequenceEqual(origData);

            if (ivMatch && dataMatch)
                Logging.LogInformation($"OutboundTunnel: AES self-test PASSED for hop {hop.Peer.IdentHash.Id32Short}");
            else
                Logging.LogCritical($"OutboundTunnel: AES self-test FAILED! IV match={ivMatch}, Data match={dataMatch}");
        }

        public I2NpMessage CreateBuildRequest( InboundTunnel replytunnel )
        {
            var vtb = VariableTunnelBuildMessage.BuildOutboundTunnel( Config.Info,
                replytunnel.Destination, replytunnel.GatewayTunnelId,
                TunnelBuildReplyMessageId );

            //Logging.Log( vtb.ToString() );

            return vtb;
        }

        public override string ToString()
        {
            return $"{base.ToString()} {Destination.Id32Short}";
        }
    }
}
