#define RUN_TUNNEL_TESTS

using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using System.Threading;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TransportLayer;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TunnelLayer.I2NP;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace I2PCore.TunnelLayer
{
    public enum TunnelPoolSelection { RejectExploratory, AllowExploratory, RequireExploratory }
    public class TunnelProvider
    {
        public static TunnelProvider Inst { get; protected set; }

        /// <summary>
        /// Tunnel build requests that is not a known Inbound or Outbound tunnel.
        /// The I2PIdentHash parameter is the transport-level sender (previous hop).
        /// </summary>
        public event Action<Ii2NpHeader, TunnelBuildRequestDecrypt, I2PIdentHash>
            TunnelBuildRequestEvents;

        /// <summary>
        /// Non-tunnel build messages received.
        /// </summary>
        public static event Action<Ii2NpHeader,InboundTunnel> I2NpMessageReceived;

        public int InboundTunnelCount { get => EstablishedInbound.Count; }
        public int OutboundTunnelCount { get => EstablishedOutbound.Count; }

        private const double TunnelSelectionElitism = 2.0;

        /// <summary>
        /// Registry of garlic tags for tunnel build reply decryption.
        /// Key: 8-byte garlic tag, Value: (garlicKey, outboundTunnel)
        /// </summary>
        private ConcurrentDictionary<ulong, (byte[] Key, Tunnel Tunnel)> PendingGarlicTags = new();

        /// <summary>
        /// Register a garlic tag for an outbound tunnel build.
        /// When a Garlic message arrives with this tag, it will be decrypted and processed as a build reply.
        /// </summary>
        public void RegisterBuildReplyGarlicTag(ulong tag, byte[] key, Tunnel tunnel)
        {
            PendingGarlicTags[tag] = (key, tunnel);
            Logging.LogInformation($"TunnelProvider: Registered garlic tag {tag:X16} for {tunnel.TunnelDebugTrace}");

            try
            {
                // Also register with ECIESRouterSKM for unified ECIES Garlic handling
                var tagBytes = BitConverter.GetBytes(BufUtils.Flip64(tag));
                var tagObj = new SessionLayer.ECIES.SessionTag(tagBytes);
                SessionLayer.Router.EciesRouterProcessor?.SessionManager?.RegisterOneTimeSession(tagObj, key);
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"TunnelProvider: RegisterBuildReplyGarlicTag ECIES error: {ex.Message}");
            }
        }

        /// <summary>
        /// Try to decrypt and handle a Garlic message as a tunnel build reply.
        /// Returns true if the message was a build reply and was handled.
        /// </summary>
        public bool TryHandleBuildReplyGarlic(I2PCore.TunnelLayer.I2NP.Messages.GarlicMessage garlicmsg, InboundTunnel from)
        {
            // I2NP Garlic payload format: ECIES_garlic(tag(8) + ciphertext)
            // The EgData property correctly handles skipping the legacy 4-byte count if present.
            var data = garlicmsg.EgData?.ToByteArray();
            if (data == null || data.Length < 8) return false;

            // First 8 bytes of ECIES garlic data is the session tag
            var tagValue = BitConverter.ToUInt64(data, 0);
            var tag = BufUtils.Flip64(tagValue);
            Logging.LogInformation($"TunnelProvider: TryHandleBuildReplyGarlic tag={tag:X16}, data={data.Length} bytes, rawTagLE={tagValue:X16}");

            if (!PendingGarlicTags.TryRemove(tag, out var entry))
            {
                if (PendingGarlicTags.Count > 0)
                {
                    var allTags = string.Join(", ", PendingGarlicTags.Keys.Select(k => k.ToString("X16")));
                    Logging.LogInformation($"TunnelProvider: TryHandleBuildReplyGarlic tag={tag:X16} NOT FOUND. Pending Tags: {allTags}");
                }
                return false;
            }

            var tunnelType = entry.Tunnel is InboundTunnel ? "INBOUND" : "OUTBOUND";
            Logging.LogInformation($"TunnelProvider: Matched garlic tag {tag:X16} for {tunnelType} tunnel build reply {entry.Tunnel.TunnelDebugTrace}");

            try
            {
                // Decrypt: data format is tag(8) + encrypted(N) where encrypted is ChaCha20-Poly1305
                var encrypted = new byte[data.Length - 8];
                Array.Copy(data, 8, encrypted, 0, encrypted.Length);

                // Nonce is 0 for garlic
                var nonce = new byte[12];
                var ad = data[..8]; // AD = the tag bytes

                var decrypted = TransportLayer.Crypto.ChaCha20Poly1305.Decrypt(
                    entry.Key, nonce, encrypted, ad);

                if (decrypted == null)
                {
                    Logging.LogWarning($"TunnelProvider: Garlic AEAD decryption failed for tag {tag:X16}");
                    return true; // consumed the tag even though decryption failed
                }

                Logging.LogInformation($"TunnelProvider: Garlic decrypted {decrypted.Length} bytes for tag {tag:X16}");
                if (decrypted.Length > 0)
                {
                    var hex = BitConverter.ToString(decrypted, 0, Math.Min(64, decrypted.Length)).Replace("-", " ");
                    Logging.LogInformation($"TunnelProvider: Garlic decrypted preview (first 64 bytes): {hex}");
                }
                
                // Parse ECIES garlic blocks to find the ShortTunnelBuildReply clove
                ProcessDecryptedBuildReplyGarlic(decrypted, from);
                return true;
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"TunnelProvider: Error processing garlic build reply: {ex.Message}");
                return true;
            }
        }

        private void ProcessDecryptedBuildReplyGarlic(byte[] decrypted, InboundTunnel from)
        {
            // Parse ECIES block format:
            // Each block: type(1) + length(2) + data(length)
            var offset = 0;
            while (offset + 3 <= decrypted.Length)
            {
                var blockType = decrypted[offset];
                var blockLen = (ushort)((decrypted[offset + 1] << 8) | decrypted[offset + 2]);
                Logging.LogInformation($"TunnelProvider: Garlic block type={blockType}, len={blockLen}");
                offset += 3;

                if (offset + blockLen > decrypted.Length)
                    break;

                // Block type 11 = GarlicClove (eECIESx25519BlkGalicClove)
                if (blockType == 11)
                {
                    // ECIES garlic clove format (readBytesRatchet):
                    // DeliveryInstructions + I2NPMessage (NTCP2 format: type(1) + ID(4) + expiration(4) + payload)
                    try
                    {
                        var cloveBuf = new BufRefLen(new BufLen(decrypted, offset, blockLen));
                        var di = GarlicCloveDelivery.CreateGarlicCloveDelivery(cloveBuf);

                        // ECIES Garlic Message format (fromRawByteArrayNTCP2 in Java):
                        // type(1) + ID(4) + expiration(4) + payload
                        var msgType = (I2NP.Messages.I2NpMessage.MessageTypes)cloveBuf.Read8();
                        var msgId = cloveBuf.ReadFlip32();
                        var expirationSeconds = cloveBuf.ReadFlip32();
                        var expirationDate = new I2PDate((ulong)expirationSeconds * 1000);

                        Logging.LogInformation($"TunnelProvider: Garlic clove: type={msgType}, ID={msgId:X8}, expiration={expirationDate}");

                        if (cloveBuf.Length > 0)
                        {
                            // I2NpMessage needs 16 bytes of header space BEFORE the payload.
                            // Decrypted garlic data doesn't have this space, so we must copy it.
                            var payloadData = cloveBuf.Read(cloveBuf.Length);
                            var copy = new byte[payloadData.Length + I2NP.Messages.I2NpMessage.I2NpMaxHeaderSize];
                            Array.Copy(payloadData, 0, copy, I2NP.Messages.I2NpMessage.I2NpMaxHeaderSize, payloadData.Length);
                            
                            var msg = I2NP.I2NpUtil.GetMessage(msgType, new BufRef(copy, I2NP.Messages.I2NpMessage.I2NpMaxHeaderSize), msgId);
                            if (msg != null)
                            {
                                msg.Expiration = expirationDate;
                                Logging.LogInformation($"TunnelProvider: Extracted {msgType} from garlic build reply. Buffer size: {copy.Length}");
                                
                                if (msg is ShortTunnelBuildReplyMessage stbr)
                                {
                                    HandleShortTunnelBuildReply(stbr);
                                }
                                else
                                {
                                    HandleIncomingMessage(msg.CreateHeader16, from);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logging.LogDebug($"TunnelProvider: Error parsing garlic clove: {ex.Message}");
                    }
                }
                else if (blockType == 254) // Padding
                {
                    // Skip padding
                }
                else
                {
                    Logging.LogDebug($"TunnelProvider: Garlic block type {blockType} len {blockLen}");
                }

                offset += blockLen;
            }
        }

        private static GarlicMessage CreateECIESGarlicMessage( I2NpMessage msg, byte[] garlicKey, ulong garlicTag )
        {
            // ECIES block format: type(1) + length(2) + data(length)
            // Block type 11 = GarlicClove (eECIESx25519BlkGalicClove)
            // Clove format per ECIES spec (readBytesRatchet):
            //   DeliveryInstructions(1 byte for local) + type(1) + msgID(4) + expiration_secs(4) + payload

            var cloveStream = new BufRefStream();
            // DeliveryInstructions: Local (flag byte 0x00, no extra fields)
            cloveStream.Write( (byte)0 );

            // I2NP message in ECIES format: type(1) + id(4) + expiration_secs(4) + payload
            cloveStream.Write( (byte)msg.MessageType );
            cloveStream.Write( BufUtils.Flip32Bl( msg.MessageId ) );
            var expirationSecs = (uint)( DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60 );
            cloveStream.Write( BufUtils.Flip32Bl( expirationSecs ) );
            cloveStream.Write( msg.Payload );

            var blocks = new List<SessionLayer.ECIES.Block>
            {
                new DateTimeBlock { Timestamp = (uint)( DateTimeOffset.UtcNow.ToUnixTimeSeconds() ) },
                new GarlicCloveBlock { Data = cloveStream.ToByteArray() },
                new PaddingBlock { Data = BufUtils.RandomBytes( 16 + BufUtils.RandomInt( 32 ) ) }
            };

            var plaintext = ECIESBlockFormat.BuildBlocks( blocks );

            // AEAD encrypt: ChaChaPoly(key, nonce=0, AD=tagBytes, plaintext)
            var tagBytes = BitConverter.GetBytes( BufUtils.Flip64( garlicTag ) );
            var nonce = new byte[12];
            var encrypted = TransportLayer.Crypto.ChaCha20Poly1305.Encrypt( garlicKey, nonce, plaintext, tagBytes );

            // I2NP Garlic payload format for ECIES: tag(8) + ciphertext(N)
            // NO 4-byte count prefix (per Proposal 144)
            var result = new byte[8 + encrypted.Length];
            Array.Copy( tagBytes, 0, result, 0, 8 );
            Array.Copy( encrypted, 0, result, 8, encrypted.Length );

            // Use the byte[] constructor which properly allocates with AllocateBuffer
            return new GarlicMessage( result );
        }

        // The byte value have no real meaning, the dictionaries are hash sets.
        private ConcurrentDictionary<InboundTunnel, byte> PendingInbound = new();
        private ConcurrentDictionary<OutboundTunnel,byte> PendingOutbound = new();

        private ConcurrentDictionary<InboundTunnel, byte> EstablishedInbound = new();
        private ConcurrentDictionary<OutboundTunnel, byte> EstablishedOutbound = new();

        private readonly TunnelIdSubsriptions TunnelIds = new();

        protected static Thread Worker;

        private ConcurrentQueue<(Ii2NpHeader msg, I2PIdentHash transportFrom)> IncomingMessageQueue = new();

        protected static Thread IncomingMessagePump;

        internal bool ClientTunnelsStatusOk { get; set; }
        internal bool AcceptTransitTunnels { get => ClientTunnelsStatusOk || !RouterContext.Inst.IsFirewalled; }

        private TunnelProvider()
        {
            Worker = new Thread( Run )
            {
                Name = "TunnelProvider",
                IsBackground = true
            };
            Worker.Start();

            IncomingMessagePump = new Thread( RunIncomingMessagePump )
            {
                Name = "TunnelProvider IncomingMessagePump",
                IsBackground = true
            };
            IncomingMessagePump.Start();

            TransportProvider.Inst.IncomingMessage += new Action<ITransport,Ii2NpHeader>( DistributeIncomingMessage );
        }

        public static void Start()
        {
            if ( Inst != null ) return;
            Inst = new TunnelProvider();

            // Run self-loopback test to verify our Noise N encryption
            // is compatible with our own decryption
            RunNoiseNSelfTest();
        }

        /// <summary>
        /// Self-loopback test: encrypt a ShortTunnelBuild record to our own identity key,
        /// then decrypt it with our transit handler. If this fails, our Noise N encryption
        /// is incompatible and remote peers will also fail to decrypt our build requests.
        /// </summary>
        private static void RunNoiseNSelfTest()
        {
            try
            {
                var ourIdentHash = RouterContext.Inst.MyRouterIdentity.IdentHash;
                var ourPubKey = RouterContext.Inst.X25519PublicKey;
                var ourPrivKey = RouterContext.Inst.X25519PrivateKey;

                // Extract X25519 component if hybrid
                var encPubKey = ourPubKey.Length == 32 ? ourPubKey : ourPubKey.Skip(ourPubKey.Length - 32).Take(32).ToArray();

                Logging.LogCritical( $"[SELF-TEST] NoiseN: Identity pubkey ({encPubKey.Length}b): {BitConverter.ToString(encPubKey, 0, 8)}..." );

                // Create a test build request record
                var testRecord = new ECIES.ShortBuildRequestRecord
                {
                    ReceiveTunnelId = new I2PTunnelId( 12345u ),
                    NextRouterHash = ourIdentHash,
                    NextTunnelId = new I2PTunnelId( 67890u ),
                    Flags = (byte)ECIES.ShortBuildRequestRecord.BuildRequestFlags.OutboundEndpoint,
                    RequestTime = (uint)((DateTime.UtcNow - I2PDate.RefDate).TotalMinutes),
                    RequestExpiration = 600,
                    NextMessageId = 0xDEADBEEF,
                };

                var cleartext = testRecord.ToByteArray();
                Logging.LogCritical( $"[SELF-TEST] NoiseN: Cleartext ({cleartext.Length}b): {BitConverter.ToString(cleartext, 0, Math.Min(16, cleartext.Length))}..." );

                // Encrypt with Noise N (initiator)
                var noiseInit = TransportLayer.Crypto.NoiseN.CreateInitiator( encPubKey );
                var noiseMessage = noiseInit.CreateMessage( cleartext );
                var initCK = noiseInit.GetChainingKey();
                var initHash = noiseInit.GetHash();
                noiseInit.Dispose();

                Logging.LogCritical( $"[SELF-TEST] NoiseN: Encrypted ({noiseMessage.Length}b): ephemeral={BitConverter.ToString(noiseMessage, 0, 8)}..." );
                Logging.LogCritical( $"[SELF-TEST] NoiseN: Initiator CK={BitConverter.ToString(initCK, 0, 8)}..., Hash={BitConverter.ToString(initHash, 0, 8)}..." );

                // Build the on-wire record (218 bytes)
                var onWireRecord = new byte[ECIES.ShortBuildRequestRecord.OnWireRecordSize];
                var hashBytes = ourIdentHash.Hash.ToByteArray();
                Array.Copy( hashBytes, 0, onWireRecord, 0, 16 ); // Router hash prefix
                Array.Copy( noiseMessage, 0, onWireRecord, 16, noiseMessage.Length ); // Noise N message

                // Now decrypt (responder) - this is what remote peers do
                var decPrivKey = ourPrivKey.Length == 32 ? ourPrivKey : ourPrivKey.Skip(ourPrivKey.Length - 32).Take(32).ToArray();
                var noiseResp = TransportLayer.Crypto.NoiseN.CreateResponder( decPrivKey, encPubKey );
                var decrypted = noiseResp.ProcessMessage( noiseMessage );
                var respCK = noiseResp.GetChainingKey();
                var respHash = noiseResp.GetHash();
                noiseResp.Dispose();

                Logging.LogCritical( $"[SELF-TEST] NoiseN: Decrypted ({decrypted.Length}b): {BitConverter.ToString(decrypted, 0, Math.Min(16, decrypted.Length))}..." );
                Logging.LogCritical( $"[SELF-TEST] NoiseN: Responder CK={BitConverter.ToString(respCK, 0, 8)}..., Hash={BitConverter.ToString(respHash, 0, 8)}..." );

                // Verify cleartext matches
                bool cleartextMatch = cleartext.SequenceEqual( decrypted );
                bool ckMatch = initCK.SequenceEqual( respCK );
                bool hashMatch = initHash.SequenceEqual( respHash );

                Logging.LogCritical( $"[SELF-TEST] NoiseN: Cleartext match={cleartextMatch}, CK match={ckMatch}, Hash match={hashMatch}" );

                if ( !cleartextMatch || !ckMatch || !hashMatch )
                {
                    Logging.LogCritical( "[SELF-TEST] NoiseN: FAILED - Noise N encryption/decryption mismatch!" );
                    return;
                }

                // Verify key derivation matches on both sides
                var (initLayer, initIv, initReply, initAD, initGarlic, initTag) =
                    ECIES.ShortBuildRequestRecord.DeriveAllKeys( initCK, initHash, true );
                var (respLayer, respIv, respReply, respAD, respGarlic, respTag) =
                    ECIES.ShortBuildRequestRecord.DeriveAllKeys( respCK, respHash, true );

                bool layerMatch = initLayer.SequenceEqual( respLayer );
                bool ivMatch = initIv.SequenceEqual( respIv );
                bool replyMatch = initReply.SequenceEqual( respReply );
                bool garlicMatch = initGarlic != null && respGarlic != null && initGarlic.SequenceEqual( respGarlic );
                bool tagMatch = initTag == respTag;

                Logging.LogCritical( $"[SELF-TEST] NoiseN: Key derivation: layer={layerMatch}, iv={ivMatch}, reply={replyMatch}, garlic={garlicMatch}, tag={tagMatch}" );
                Logging.LogCritical( $"[SELF-TEST] NoiseN: Garlic tag init={initTag:X16}, resp={respTag:X16}" );

                if ( !layerMatch || !ivMatch || !replyMatch || !garlicMatch || !tagMatch )
                {
                    Logging.LogCritical( "[SELF-TEST] NoiseN: FAILED - Key derivation mismatch!" );
                    return;
                }

                // Now test the full pipeline: create a ShortTunnelBuildMessage and process it
                var stbm = new ShortTunnelBuildMessage( new System.Collections.Generic.List<byte[]> { onWireRecord,
                    BufUtils.RandomBytes( ECIES.ShortBuildRequestRecord.OnWireRecordSize ),
                    BufUtils.RandomBytes( ECIES.ShortBuildRequestRecord.OnWireRecordSize ),
                    BufUtils.RandomBytes( ECIES.ShortBuildRequestRecord.OnWireRecordSize ) } );

                // Verify bytes survived STBM round-trip
                var stbmRecord = stbm.Records[0];
                var stbmRecordBytes = stbmRecord.ToByteArray();
                bool bytesPreserved = onWireRecord.SequenceEqual( stbmRecordBytes );
                Logging.LogCritical( $"[SELF-TEST] NoiseN: STBM bytes preserved={bytesPreserved}, " +
                    $"origLen={onWireRecord.Length}, stbmLen={stbmRecordBytes.Length}" );

                if ( !bytesPreserved )
                {
                    // Find first difference
                    for ( int d = 0; d < Math.Min( onWireRecord.Length, stbmRecordBytes.Length ); ++d )
                    {
                        if ( onWireRecord[d] != stbmRecordBytes[d] )
                        {
                            Logging.LogCritical( $"[SELF-TEST] NoiseN: First diff at offset {d}: orig=0x{onWireRecord[d]:X2}, stbm=0x{stbmRecordBytes[d]:X2}" );
                            break;
                        }
                    }
                }

                // Also verify extracting just the Noise N message portion
                var extractedNoise = new byte[202];
                Array.Copy( stbmRecordBytes, 16, extractedNoise, 0, 202 );
                bool noisePreserved = noiseMessage.SequenceEqual( extractedNoise );
                Logging.LogCritical( $"[SELF-TEST] NoiseN: Noise msg preserved={noisePreserved}" );

                // Also test direct decryption of extracted bytes (bypassing BufLen)
                try
                {
                    var noiseResp2 = TransportLayer.Crypto.NoiseN.CreateResponder( decPrivKey, encPubKey );
                    var decrypted2 = noiseResp2.ProcessMessage( extractedNoise );
                    noiseResp2.Dispose();
                    Logging.LogCritical( $"[SELF-TEST] NoiseN: Direct decrypt of extracted bytes: OK ({decrypted2.Length}b)" );
                }
                catch ( Exception ex2 )
                {
                    Logging.LogCritical( $"[SELF-TEST] NoiseN: Direct decrypt of extracted bytes FAILED: {ex2.Message}" );
                }

                // Test with BufLen.Peek extraction (same as ECIESTunnelDecrypt uses)
                var peekNoise = new byte[202];
                stbmRecord.Peek( peekNoise, 0, 16, 202 );
                bool peekPreserved = noiseMessage.SequenceEqual( peekNoise );
                Logging.LogCritical( $"[SELF-TEST] NoiseN: Peek-extracted noise preserved={peekPreserved}" );

                if ( !peekPreserved )
                {
                    Logging.LogCritical( $"[SELF-TEST] NoiseN: peekNoise[0:8]={BitConverter.ToString(peekNoise, 0, 8)}, expected={BitConverter.ToString(noiseMessage, 0, 8)}" );
                }

                var decrypt = new ECIES.ECIESTunnelDecrypt( decPrivKey, encPubKey );
                var result = decrypt.ProcessShortTunnelBuild( stbm );

                Logging.LogCritical( $"[SELF-TEST] NoiseN: Full pipeline: success={result.Success}, recordIdx={result.RecordIndex}" );

                if ( result.Success )
                {
                    var parsed = result.ShortRequest;
                    Logging.LogCritical( $"[SELF-TEST] NoiseN: Parsed record: recv={parsed.ReceiveTunnelId}, " +
                        $"next={parsed.NextRouterHash?.Id32Short}, flags=0x{parsed.Flags:X2}, msgId={parsed.NextMessageId:X8}" );

                    bool recvMatch = (uint)parsed.ReceiveTunnelId == 12345u;
                    bool nextMatch = parsed.NextRouterHash?.Equals( ourIdentHash ) ?? false;
                    bool flagsMatch = parsed.Flags == (byte)ECIES.ShortBuildRequestRecord.BuildRequestFlags.OutboundEndpoint;
                    bool msgIdMatch = parsed.NextMessageId == 0xDEADBEEF;

                    Logging.LogCritical( $"[SELF-TEST] NoiseN: Field verification: recv={recvMatch}, next={nextMatch}, flags={flagsMatch}, msgId={msgIdMatch}" );

                    if ( recvMatch && nextMatch && flagsMatch && msgIdMatch )
                        Logging.LogCritical( "[SELF-TEST] NoiseN: ALL TESTS PASSED - Noise N crypto is internally consistent" );
                    else
                        Logging.LogCritical( "[SELF-TEST] NoiseN: FAILED - Field values don't match after round-trip!" );
                }
                else
                {
                    Logging.LogCritical( "[SELF-TEST] NoiseN: FAILED - Full pipeline decryption failed!" );
                }
            }
            catch ( Exception ex )
            {
                Logging.LogCritical( $"[SELF-TEST] NoiseN: EXCEPTION - {ex.GetType().Name}: {ex.Message}" );
                Logging.LogCritical( $"[SELF-TEST] NoiseN: Stack: {ex.StackTrace}" );
            }
        }

        /// <summary>
        /// Stop the tunnel provider, terminate worker threads, and clear state.
        /// </summary>
        public static void Stop()
        {
            var inst = Inst;
            if ( inst == null ) return;

            inst.Terminated = true;

            try { Worker?.Join( 5000 ); } catch { }
            try { IncomingMessagePump?.Join( 5000 ); } catch { }

            inst.PendingInbound.Clear();
            inst.PendingOutbound.Clear();
            inst.EstablishedInbound.Clear();
            inst.EstablishedOutbound.Clear();
            inst.IncomingMessageQueue.Clear();

            Worker = null;
            IncomingMessagePump = null;
            Inst = null;
        }

        private PeriodicAction QueueStatusLog = new( TickSpan.Seconds( 30 ) );
        private PeriodicAction TunnelBandwidthLog = new( TickSpan.Minutes( 8 ) );

        private PeriodicAction CheckTunnelTimeouts = new( TickSpan.Seconds( 5 ) );

        private bool Terminated = false;
        private void Run()
        {
            try
            {
                Thread.Sleep( 2000 );

                while ( !Terminated )
                {
                    try
                    {
                        TunnelBandwidthLog.Do( () => ThreadPool.QueueUserWorkItem( cb =>
                        {
                            var tunnels = EstablishedInbound
                                    .Keys
                                    .ToArray()
                                    .Cast<Tunnel>()
                                    .Concat( EstablishedOutbound.Keys )
                                    .ToArray();

                            LogTunnelBandwidth( tunnels );
                        } ) );

                        QueueStatusLog.Do( () =>
                        {
                            Logging.LogInformation(
                                $"TunnelProvider: Established Inbound: {EstablishedInbound.Count}, " +
                                $"Pending Inbound: {PendingInbound.Count}, " +
                                $"Established Outbound: {EstablishedOutbound.Count}, " +
                                $"Pending Outbound: {PendingOutbound.Count}" );

                            var zh = EstablishedInbound.Count( t => t.Key is ZeroHopTunnel );
                            Logging.LogInformation(
                                $"Established 0-hop tunnels     : {zh,2}" );

                            Logging.LogInformation(
                                $"Tunnel data: {Tunnel.BandwidthTotal}" );

                            Logging.LogDebug( string.Format(
                                "Unresolvable routers: {0}. Unresolved routers: {1}. IP addresses with execptions: {2}. SSU blocked IPs: {3}.",
                                TransportProvider.Inst.CurrentlyUnresolvableRoutersCount,
                                TransportProvider.Inst.CurrentlyUnknownRoutersCount,
                                TransportProvider.Inst.AddressesWithExceptionsCount,
                                TransportProvider.Inst.SsuHostBlockedIpCount
                                ) );
                        } );

                        CheckTunnelTimeouts.Do( CheckForTunnelBuildTimeout );

                        ExecuteQueue(
                            PendingOutbound.Select( d => d.Key ),
                            ( t ) => PendingOutbound.TryRemove( (OutboundTunnel)t, out _ ),
                            true );

                        ExecuteQueue(
                            PendingInbound.Select( d => d.Key ),
                            ( t ) => PendingInbound.TryRemove( (InboundTunnel)t, out _ ),
                            true );

                        ExecuteQueue(
                            EstablishedOutbound.Select( d => d.Key ),
                            ( t ) => EstablishedOutbound.TryRemove( (OutboundTunnel)t, out _ ),
                            false );

                        ExecuteQueue(
                            EstablishedInbound.Select( d => d.Key ),
                            ( t ) => EstablishedInbound.TryRemove( (InboundTunnel)t, out _ ),
                            false );

                        Thread.Sleep( 1500 ); // Give data a chance to batch up
                    }
                    catch ( ThreadAbortException ex )
                    {
                        Logging.Log( ex );
                    }
                    catch ( Exception ex )
                    {
#if !LOG_ALL_TUNNEL_TRANSFER
                        if ( ex is IOException || ex is SocketException || ex is EndOfStreamEncounteredException )
                        {
                            Logging.Log( $"TransportProvider: Communication exception {ex.GetType()}" );
                        }
                        else
#endif
                        {
                            Logging.Log( ex );
                        }
                    }
                }
            }
            finally
            {
                Terminated = true;
            }
        }

        private void LogTunnelBandwidth( IEnumerable<Tunnel> tunnels )
        {
            foreach ( var tunnel in tunnels.OrderBy( t => t.TunnelDirection ).ThenBy( t => t.Pool ) )
            {
                if ( tunnel.Config.Direction == TunnelConfig.TunnelDirection.Inbound && tunnel.TunnelMembers.Any() )
                {
                    foreach ( var peer in tunnel.TunnelMembers.Select( id => id.IdentHash ).ToArray() )
                    {
                        NetDb.Inst.Statistics.MaxBandwidth( peer, tunnel.Bandwidth.ReceiveBandwidth );
                    }
                }

                // TODO: Revert when roslyn is fixed
                //Logging.LogInformation( $"Tunnel bandwidth {tunnel,-40} {tunnel.Bandwidth}" );
                Logging.LogInformation( $"Tunnel bandwidth {tunnel,40} {tunnel.Bandwidth}" );
            }
        }

        private void CheckForTunnelBuildTimeout()
        {
            if ( PendingOutbound.Count > 0 )
            {
                CheckForTunnelBuildTimeout( PendingOutbound.Keys.ToArray() );
            }

            if ( PendingInbound.Count > 0 )
            {
                CheckForTunnelBuildTimeout( PendingInbound.Keys.ToArray() );
            }
        }

        private void CheckForTunnelBuildTimeout( IEnumerable<Tunnel> pool )
        {
            var timeout = pool.Where( t => 
                t.CreationTime.DeltaToNow > t.TunnelEstablishmentTimeout )
                    .ToArray();

#if DEBUG
            var removedtunnels = new List<Tunnel>();
#endif
            foreach ( var one in timeout )
            {
                TunnelBuildLogger.Inst.Log( $"Tunnel build timeout: {one.TunnelDebugTrace}", one.TunnelDebugTrace, one.Pool.ToString(), one.TunnelDirection.ToString() );
#if DEBUG
                removedtunnels.Add( one );
#endif
                one.Owner?.TunnelBuildFailed( one, true );

                foreach ( var dest in one.TunnelMembers )
                {
                    NetDb.Inst.Statistics.TunnelBuildTimeout( dest.IdentHash );
                }

                RemoveTunnel( one );
                one.Shutdown();
            }
#if DEBUG
            if ( removedtunnels.Any() )
            {
                var st = new StringBuilder();
                var pools = removedtunnels.GroupBy( t => t.Pool );
                foreach ( var onepool in pools )
                {
                    st.Append( $"{onepool.Key} {onepool.First().TunnelDirection}" );
                    foreach ( var one in pool )
                    {
                        st.Append( $"{one.TunnelDebugTrace} " );
                    }
                }

                Logging.LogDebug( $"TunnelProvider: Removing {st} due to establishment timeout." );
            }
#endif
        }

        private readonly ConcurrentQueue<(Tunnel, bool)> FailedTunnels = new();

        private void ExecuteQueue( IEnumerable<Tunnel> q, Action<Tunnel> remove, bool ispending )
        {
            RunTunnels( q );
            RemoveFailedTunnels( remove, ispending );
        }

        private void RunTunnels( IEnumerable<Tunnel> q )
        {
            foreach ( var tunnel in q )
            {
                try
                {
                    if ( tunnel.Terminated )
                    {
                        FailedTunnels.Enqueue( (tunnel, true) );
                        continue;
                    }

                    var ok = tunnel.Exectue();
                    if ( !ok )
                    {
                        FailedTunnels.Enqueue( (tunnel, true) );
                    }
                    else
                    {
                        if ( tunnel.Expired )
                        {
                            // Normal timeout
                            FailedTunnels.Enqueue( (tunnel, false) );
                            tunnel.Shutdown();
                        }
                    }
                }
                catch ( Exception ex )
                {
                    Logging.LogDebug(
                        $"TunnelProvider: Exception in tunnel {tunnel} [{ex.GetType()}] '{ex.Message}'." );
#if LOG_ALL_TUNNEL_TRANSFER
                    Logging.Log( ex );
#endif
                    FailedTunnels.Enqueue( (tunnel, true) );
                }
            }
        }

        private void RemoveFailedTunnels( Action<Tunnel> remove, bool ispending )
        {
            while ( FailedTunnels.TryDequeue( out var t ) )
            {
                var tunnel = t.Item1;
                var isfailed = t.Item2;

                if ( isfailed )
                {
                    if ( ispending )
                    {
                        Logging.LogDebug( $"TunnelProvider: ExecuteQueue removing failed tunnel {tunnel} during build." );
                        TunnelBuildLogger.Inst.Log( $"Tunnel failed during build: {tunnel.TunnelDebugTrace}", tunnel.TunnelDebugTrace, tunnel.Pool.ToString(), tunnel.TunnelDirection.ToString() );
                        tunnel.Owner?.TunnelBuildFailed( tunnel, false );
                    }
                    else
                    {
                        Logging.LogDebug( $"TunnelProvider: ExecuteQueue removing failed tunnel {tunnel}." );
                        tunnel.Owner?.TunnelFailed( tunnel );
                    }

                    remove?.Invoke( tunnel );
                    RemoveTunnel( tunnel );
                }
                else
                {
                    Logging.LogDebug( $"TunnelProvider: ExecuteQueue removing expired tunnel {tunnel} created {tunnel.CreationTime}." );

                    tunnel.Owner?.TunnelExpired( tunnel );

                    remove?.Invoke( tunnel );
                    RemoveTunnel( tunnel );
                }
            }
        }

        public Tunnel CreateTunnel( ITunnelOwner owner, TunnelConfig config )
        {
            if ( config.Info.Hops.Count == 0 ) return null;

            if ( config.Direction == TunnelConfig.TunnelDirection.Outbound )
            {
                var replytunnel = GetInboundTunnel( TunnelPoolSelection.AllowExploratory );
                Logging.LogDebug( $"TunnelProvider: Using reply tunnel: {replytunnel}, GatewayTunnelId={replytunnel.GatewayTunnelId}, ReceiveTunnelId={replytunnel.ReceiveTunnelId}" );
                var tunnel = new OutboundTunnel( owner, config, replytunnel.Config.Info.Hops.Count );

                var req = tunnel.CreateBuildRequest( replytunnel );

                Logging.LogDebug( $"TunnelProvider: {tunnel} created, build id: {tunnel.TunnelBuildReplyMessageId} {req.MessageId} {req.CreateHeader16.MessageId}." );
                TunnelBuildLogger.Inst.Log( $"Creating outbound tunnel {tunnel.TunnelDebugTrace}: {TunnelBuildLogger.GetHopsString(config.Info.Hops)} via {tunnel.Destination.Id32Short} using reply tunnel {replytunnel.TunnelDebugTrace}", tunnel.TunnelDebugTrace, tunnel.Pool.ToString(), tunnel.TunnelDirection.ToString() );

#if DEBUG
                ReallyOldTunnelBuilds.Set( tunnel.TunnelBuildReplyMessageId,
                    new RefPair<TickCounter, int>( TickCounter.Now, replytunnel.Config.Info.Hops.Count + config.Info.Hops.Count ) );
#endif

                // Register garlic tag for build reply decryption (endpoint hop)
                var endpointHop = config.Info.Hops.Last();
                if (endpointHop.GarlicKey != null && endpointHop.GarlicTag != 0)
                {
                    RegisterBuildReplyGarlicTag(endpointHop.GarlicTag, endpointHop.GarlicKey, tunnel);
                    Logging.LogInformation( $"TunnelProvider: OB build {tunnel.TunnelDebugTrace}: dest={tunnel.Destination.Id32Short}, " +
                        $"replyTunnel={replytunnel.TunnelDebugTrace} (GW={replytunnel.GatewayTunnelId}, Recv={replytunnel.ReceiveTunnelId}), " +
                        $"garlicTag={endpointHop.GarlicTag:X16}, msgType={req.MessageType}, " +
                        $"hops={config.Info.Hops.Count}, replyHops={replytunnel.Config.Info.Hops.Count}, " +
                        $"timeout={tunnel.TunnelEstablishmentTimeout}" );
                }
                else
                {
                    Logging.LogWarning( $"TunnelProvider: OB build {tunnel.TunnelDebugTrace}: NO garlic key/tag! " +
                        $"GarlicKey={endpointHop.GarlicKey != null}, GarlicTag={endpointHop.GarlicTag:X16}" );
                }

                TransportProvider.Send( tunnel.Destination, req );

                return tunnel;
            }
            else
            {
                var outtunnel = GetEstablishedOutboundTunnel( TunnelPoolSelection.AllowExploratory );
                var replytunnel = GetInboundTunnel( TunnelPoolSelection.AllowExploratory );
                var tunnel = new InboundTunnel( owner, config, outtunnel?.Config.Info.Hops.Count ?? 0 );

                Logging.LogDebug( $"TunnelProvider: Inbound tunnel {tunnel} created." );
                TunnelBuildLogger.Inst.Log( $"Creating inbound tunnel {tunnel.TunnelDebugTrace}: {TunnelBuildLogger.GetHopsString(config.Info.Hops)} via gateway {tunnel.Destination.Id32Short}", tunnel.TunnelDebugTrace, tunnel.Pool.ToString(), tunnel.TunnelDirection.ToString() );
#if DEBUG
                ReallyOldTunnelBuilds.Set( tunnel.TunnelBuildReplyMessageId,
                    new RefPair<TickCounter, int>( TickCounter.Now, ( outtunnel?.Config.Info.Hops.Count ?? 0 ) + config.Info.Hops.Count ) );
#endif

                var tunnelbuild = tunnel.CreateBuildRequest( replytunnel );

                if ( outtunnel != null )
                {
                    I2NpMessage finalMsg = tunnelbuild;

                    // Java-like: Garlic wrap the build request to hide it from the OBEP of our outbound tunnel
                    var ri = NetDb.Inst[tunnel.Destination];
                    var x25519pk = ri?.GetECIESPublicKey();

                    if ( x25519pk != null )
                    {
                        var ecies = SessionLayer.Router.EciesRouterProcessor;
                        if ( ecies != null )
                        {
                            try
                            {
                                // Decrypted payload: Block format containing a GarlicCloveBlock
                                var cloveStream = new BufRefStream();
                                cloveStream.Write( (byte)0 ); // Delivery instructions: Local
                                
                                // I2NP message in NTCP2 format (Type + ID + Expiration + Body)
                                cloveStream.Write( (byte)tunnelbuild.MessageType );
                                cloveStream.Write( BufUtils.Flip32Bl( tunnelbuild.MessageId ) );
                                var expirationSeconds = (uint)Math.Round( ( (DateTime)tunnelbuild.Expiration - I2PDate.RefDate ).TotalSeconds );
                                cloveStream.Write( BufUtils.Flip32Bl( expirationSeconds ) );
                                cloveStream.Write( tunnelbuild.Payload );

                                // ECIES Router-to-router Garlic message format (Proposal 144 blocks).
                                // The SKM.SendMessage will handle wrapping this clove data into standard ECIES blocks 
                                // and encrypting it using a Noise N (New Session) message.
                                var garlicPayload = ecies.SendMessage( 
                                    tunnel.Destination, 
                                    x25519pk, 
                                    cloveStream.ToByteArray() );
                                
                                finalMsg = new GarlicMessage( garlicPayload );
                                Logging.LogDebug( $"TunnelProvider: Garlic wrapped inbound build request for {tunnel.TunnelDebugTrace} to gateway {tunnel.Destination.Id32Short}" );
                            }
                            catch ( Exception ex )
                            {
                                Logging.LogWarning( $"TunnelProvider: Failed to Garlic wrap build request: {ex.Message}" );
                            }
                        }
                    }

                    outtunnel.Send(
                        new TunnelMessageRouter( finalMsg, tunnel.Destination ) );
                }
                else
                {
                    Logging.LogInformation( $"TunnelProvider: No established outbound tunnels available for inbound tunnel {tunnel}. Sending directly to gateway {tunnel.Destination}." );
                    TransportProvider.Send( tunnel.Destination, tunnelbuild );
                }

                return tunnel;
            }
        }

        internal OutboundTunnel AddTunnel( OutboundTunnel tunnel )
        {
            if ( tunnel.Established )
            {
                EstablishedOutbound[tunnel] = 1;
            }
            else
            {
                PendingOutbound[tunnel] = 1;
            }
            return tunnel;
        }

        internal InboundTunnel AddTunnel( InboundTunnel tunnel )
        {
            if ( tunnel.Established )
            {
                EstablishedInbound[tunnel] = 1;
            }
            else
            {
                PendingInbound[tunnel] = 1;
            }
            TunnelIds.Add( tunnel.ReceiveTunnelId, tunnel );
            return tunnel;
        }

        private InboundTunnel AddZeroHopTunnel()
        {
            var hops = new List<HopInfo>
            {
                new( RouterContext.Inst.MyRouterIdentity, new I2PTunnelId() )
            };
            var setup = new TunnelInfo( hops );

            var config = new TunnelConfig(
                TunnelConfig.TunnelDirection.Inbound,
                TunnelConfig.TunnelPool.Exploratory,
                setup );

            var tunnel = new ZeroHopTunnel( null, config, RouterContext.Inst.MyRouterIdentity.IdentHash );
            EstablishedInbound[tunnel] = 1;
            TunnelIds.Add( tunnel.ReceiveTunnelId, tunnel );
            Logging.LogDebug($"TunnelProvider: Registered inbound tunnel ReceiveTunnelId={tunnel.ReceiveTunnelId}, GatewayTunnelId={tunnel.GatewayTunnelId}, established={tunnel.Established}");
            return tunnel;
        }

        internal void RemoveTunnel( InboundTunnel tunnel )
        {
            TunnelIds.Remove( tunnel.ReceiveTunnelId, tunnel );
            PendingInbound.TryRemove( tunnel, out _ );
            EstablishedInbound.TryRemove( tunnel, out _ );
        }

        internal void RemoveTunnel( OutboundTunnel tunnel )
        {
            PendingOutbound.TryRemove( tunnel, out _ );
            EstablishedOutbound.TryRemove( tunnel, out _ );
        }

        internal void RemoveTunnel( Tunnel tunnel )
        {
            if ( tunnel is InboundTunnel )
            {
                RemoveTunnel( (InboundTunnel)tunnel );
            }
            else
            {
                RemoveTunnel( (OutboundTunnel)tunnel );
            }
        }

        /// <summary>
        /// Get an inbound tunnel for use as a build reply target.
        /// Falls back to a zero-hop tunnel ONLY during bootstrap when no real
        /// inbound tunnels exist yet. Zero-hop tunnels are never selected for
        /// normal tunnel operations (SelectTunnel hard-excludes them).
        /// </summary>
        public InboundTunnel GetInboundTunnel( TunnelPoolSelection poolsel )
        {
            var result = GetEstablishedInboundTunnel( poolsel );
            if ( result != null ) return result;
            if ( poolsel == TunnelPoolSelection.RejectExploratory ) return null;

            Logging.LogWarning( "TunnelProvider: No established inbound tunnels available, " +
                "creating zero-hop bootstrap reply tunnel" );
            return AddZeroHopTunnel();
        }

        private IEnumerable<T> PoolSelection<T>( IEnumerable<T> tunnels, TunnelPoolSelection poolsel ) where T: Tunnel
        {
            IEnumerable<T> result = null;

            switch ( poolsel )
            {
                case TunnelPoolSelection.AllowExploratory:
                    result = tunnels
                            .Where( t =>
                                    t.Config.Pool == TunnelConfig.TunnelPool.Client
                                    || t.Config.Pool == TunnelConfig.TunnelPool.Exploratory );
                    break;

                case TunnelPoolSelection.RequireExploratory:
                    result = tunnels
                            .Where( t =>
                                    t.Config.Pool == TunnelConfig.TunnelPool.Exploratory );
                    break;

                case TunnelPoolSelection.RejectExploratory:
                    result = tunnels
                            .Where( t =>
                                    t.Config.Pool == TunnelConfig.TunnelPool.Client );
                    break;
            }

            return result;
        }

        public InboundTunnel GetEstablishedInboundTunnel( TunnelPoolSelection poolsel )
        {
            var tunnels = PoolSelection( GetInboundTunnels(), poolsel );
            return SelectTunnel( tunnels );
        }

        public OutboundTunnel GetEstablishedOutboundTunnel( TunnelPoolSelection poolsel )
        {
            var tunnels = PoolSelection( GetOutboundTunnels(), poolsel );
            return SelectTunnel( tunnels );
        }

        public IEnumerable<OutboundTunnel> GetOutboundTunnels()
        {
            return EstablishedOutbound
                .Keys
                .ToArray();
        }

        public IEnumerable<InboundTunnel> GetInboundTunnels()
        {
            return EstablishedInbound
                .Keys
                .ToArray();
        }

        public IEnumerable<OutboundTunnel> GetPendingOutboundTunnels()
        {
            return PendingOutbound
                .Keys
                .ToArray();
        }

        public IEnumerable<InboundTunnel> GetPendingInboundTunnels()
        {
            return PendingInbound
                .Keys
                .ToArray();
        }

        private void RunIncomingMessagePump()
        {
            while ( !Terminated )
            {
                try
                {
                    if ( IncomingMessageQueue.IsEmpty ) IncommingMessageReceived.WaitOne( 500 );

                    while ( !IncomingMessageQueue.IsEmpty )
                    {
                        if ( !IncomingMessageQueue.TryDequeue( out var item ) )
                            continue;

                        HandleIncomingMessage( item.msg, transportFrom: item.transportFrom );
                    }
                }
                catch ( Exception ex )
                {
                    Logging.Log( ex );
                }
            }
        }

        /// <summary>
        /// Decaying bloom filter for duplicate I2NP message detection.
        /// Prevents processing the same message twice within the decay window.
        /// </summary>
        private static readonly DecayingBloomFilter DuplicateMessageFilter = new();

        internal void HandleIncomingMessage( Ii2NpHeader msg, InboundTunnel from = null, I2PIdentHash transportFrom = null )
        {
            if ( msg.MessageType == I2NpMessage.MessageTypes.Garlic )
            {
                Logging.LogInformation( $"TunnelProvider: Received Garlic message from {from?.TunnelDebugTrace ?? "DIRECT"}" );
            }
            // Duplicate message detection using bloom filter
            // Only check for message types that are expensive to process
            if ( msg.MessageType == I2NpMessage.MessageTypes.TunnelData
                || msg.MessageType == I2NpMessage.MessageTypes.DatabaseStore
                || msg.MessageType == I2NpMessage.MessageTypes.Garlic )
            {
                var msgIdBytes = BitConverter.GetBytes( msg.Message?.MessageId ?? 0 );
                if ( DuplicateMessageFilter.AddAndCheck( msgIdBytes ) )
                {
                    Logging.LogDebug( $"TunnelProvider: Duplicate I2NP message dropped: {msg.MessageType} id={msg.Message?.MessageId}" );
                    return;
                }
            }

            switch ( msg.MessageType )
            {
                case I2NpMessage.MessageTypes.VariableTunnelBuild:
                    HandleVariableTunnelBuild( msg, transportFrom );
                    break;

                case I2NpMessage.MessageTypes.TunnelBuild:
                    HandleTunnelBuild( msg, transportFrom );
                    break;

                case I2NpMessage.MessageTypes.ShortTunnelBuild:
                    HandleShortTunnelBuild( msg, transportFrom );
                    break;

                case I2NpMessage.MessageTypes.VariableTunnelBuildReply:
                    HandleVariableTunnelBuildReply( (VariableTunnelBuildReplyMessage)msg.Message );
                    break;

                case I2NpMessage.MessageTypes.ShortTunnelBuildReply:
                    HandleShortTunnelBuildReply( (ShortTunnelBuildReplyMessage)msg.Message );
                    break;

                case I2NpMessage.MessageTypes.TunnelGateway:
                    var tg = (TunnelGatewayMessage)msg.Message;
                    Logging.LogInformation( $"TunnelProvider: TunnelGateway received, TunnelId={tg.TunnelId}" );
                    var tunnels = TunnelIds.FindTunnelFromTunnelId( tg.TunnelId );

                    if ( tunnels?.Any() ?? false )
                    {
                        foreach ( var tunnel in tunnels )
                        {
                            var innerMsg = I2NpMessage.ReadHeader16( (BufRefLen)tg.GatewayMessage );
                            Logging.LogInformation( $"TunnelProvider: TunnelGateway inner message: {innerMsg.MessageType} via tunnel {tunnel}" );

                            // Dispatch inner message based on type:
                            // TunnelData goes to the tunnel for fragment reassembly.
                            // All other I2NP messages (Garlic, ShortTunnelBuildReply,
                            // DatabaseStore, etc.) must be dispatched to the main handler.
                            if ( innerMsg.MessageType == I2NpMessage.MessageTypes.TunnelData )
                            {
                                tunnel.MessageReceived(
                                    innerMsg.Message,
                                    msg.HeaderAndPayload.Length );
                            }
                            else if ( innerMsg.MessageType == I2NpMessage.MessageTypes.Garlic )
                            {
                                // Try as tunnel build reply garlic first
                                var garlicMsg = (GarlicMessage)innerMsg.Message;
                                if ( !TryHandleBuildReplyGarlic( garlicMsg, tunnel as InboundTunnel ) )
                                {
                                    // Not a build reply — dispatch to general handler
                                    HandleIncomingMessage( innerMsg, tunnel as InboundTunnel );
                                }
                            }
                            else
                            {
                                // ShortTunnelBuildReply, DatabaseStore, etc.
                                HandleIncomingMessage( innerMsg, tunnel as InboundTunnel );
                            }
                        }
                    }
                    else if ( (uint)tg.TunnelId == 0 )
                    {
                        // TunnelGateway tunnel ID 0 = deliver inner message directly to this router.
                        // Java I2P/i2pd use this for ECIES inbound tunnel build replies (replyTunnel=0).
                        var innerMsg0 = I2NpMessage.ReadHeader16( (BufRefLen)tg.GatewayMessage );
                        Logging.LogInformation( $"TunnelProvider: TunnelGateway(0) inner message: {innerMsg0.MessageType}" );
                        HandleIncomingMessage( innerMsg0, null );
                    }
                    else
                    {
                        Logging.LogWarning( $"TunnelProvider: TunnelGateway tunnel {tg.TunnelId} NOT FOUND. Registered tunnels: {string.Join(", ", TunnelIds.GetAllTunnelIds())}" );
                    }
                    break;

                case I2NpMessage.MessageTypes.TunnelData:
                    var td = (TunnelDataMessage)msg.Message;
                    tunnels = TunnelIds.FindTunnelFromTunnelId( td.TunnelId );

                    if ( tunnels?.Any() ?? false )
                    {
                        foreach ( var tunnel in tunnels )
                        {
#if LOG_ALL_TUNNEL_TRANSFER
                            Logging.LogDebug( string.Format( "RunIncomingMessagePump: TunnelData ({0}): {1}.",
                                td, tunnel ) );
#endif
                            tunnel.MessageReceived( td, msg.HeaderAndPayload.Length );
                        }
                    }
                    else
                    {
                        Logging.LogDebug( $"RunIncomingMessagePump: Tunnel not found for TunnelData. Dropped. {td}" );
                    }
                    break;

                case I2NpMessage.MessageTypes.DatabaseStore:
                    var dsm = (DatabaseStoreMessage)msg.Message;
                    if (dsm.Content == DatabaseStoreMessage.MessageContent.RouterInfo)
                    {
                        NetDb.Inst.AddRouterInfo(dsm.RouterInfo);
                    }
                    else if (dsm.LeaseSet != null)
                    {
                        Logging.LogInformation($"TunnelProvider: Received LeaseSet for {dsm.Key?.Id32Short}");
                        NetDb.Inst.AddLeaseSet(dsm.LeaseSet);
                    }
                    // Also fire event so IdentResolver can pick up responses
                    I2NpMessageReceived?.Invoke( msg, from );
                    break;

                case I2NpMessage.MessageTypes.DatabaseSearchReply:
                    // Forward to NetDb/IdentResolver for processing
                    // These are responses to exploration queries and RI lookups
                    Logging.LogDebug( $"TunnelProvider: DatabaseSearchReply received via tunnel" );
                    I2NpMessageReceived?.Invoke( msg, from );
                    break;

                case I2NpMessage.MessageTypes.DeliveryStatus:
                    // Forward delivery status for floodfill update confirmations
                    I2NpMessageReceived?.Invoke( msg, from );
                    break;

                case I2NpMessage.MessageTypes.Garlic:
                    // For ECIES inbound tunnel builds, the reply arrives as a session-tagged
                    // Garlic message sent directly by the endpoint hop (Java I2P: replyTunnel=0).
                    // Try build-reply decryption first; fall back to Router's garlic handler.
                    var directGarlic = (GarlicMessage)msg.Message;
                    if ( !TryHandleBuildReplyGarlic( directGarlic, from ) )
                    {
                        I2NpMessageReceived?.Invoke( msg, from );
                    }
                    break;

                default:
                    Logging.LogDebugData( () => $"TunnelProvider.RunIncomingMessagePump: Unhandled message ({msg.Message})" );
                    I2NpMessageReceived?.Invoke( msg, from );
                    break;
            }
        }

        private AutoResetEvent IncommingMessageReceived = new( false );

        public void DistributeIncomingMessage( ITransport transp, Ii2NpHeader msg )
        {
            if ( msg.MessageType == I2NpMessage.MessageTypes.ShortTunnelBuildReply )
            {
                Logging.LogInformation( $"[DEBUG_LOG] DistributeIncomingMessage: Received ShortTunnelBuildReply from {transp?.RemoteRouterIdentity?.IdentHash?.Id32Short ?? "Tunnel"}" );
            }
            if ( msg.MessageType == I2NpMessage.MessageTypes.VariableTunnelBuildReply )
            {
                Logging.LogInformation( $"[DEBUG_LOG] DistributeIncomingMessage: Received VariableTunnelBuildReply from {transp?.RemoteRouterIdentity?.IdentHash?.Id32Short ?? "Tunnel"}" );
            }
            // Global inbound bandwidth enforcement
            if ( SessionLayer.RouterContext.Inst.ShouldDropInbound() )
            {
                Logging.LogDebug( "TunnelProvider: Global inbound bandwidth limit reached, dropping message" );
                return;
            }

            IncomingMessageQueue.Enqueue( (msg, transp?.RemoteRouterIdentity?.IdentHash) );
            IncommingMessageReceived.Set();
        }

        private void HandleTunnelBuild( Ii2NpHeader msg, I2PIdentHash from )
        {
            var trmsg = (TunnelBuildMessage)msg.Message;
#if LOG_ALL_TUNNEL_TRANSFER
            Logging.Log( $"HandleTunnelBuild: {trmsg}" );
#endif
            HandleTunnelBuildRecords( msg, trmsg.Records, from );
        }

        private void HandleVariableTunnelBuild( Ii2NpHeader msg, I2PIdentHash from )
        {
            var trmsg = (VariableTunnelBuildMessage)msg.Message;
#if LOG_ALL_TUNNEL_TRANSFER
            Logging.Log( $"HandleVariableTunnelBuild: {trmsg}" );
#endif
            HandleTunnelBuildRecords( msg, trmsg.Records, from );
        }

        private void HandleShortTunnelBuild( Ii2NpHeader msg, I2PIdentHash from )
        {
            Logging.LogInformation( $"[DEBUG_LOG] HandleShortTunnelBuild: Received request MessageId={msg.Message.MessageId:X8}" );
            var stbm = (ShortTunnelBuildMessage)msg.Message;
#if LOG_ALL_TUNNEL_TRANSFER
            Logging.Log( $"HandleShortTunnelBuild: {stbm}" );
#endif
            // Java I2P BuildHandler: FIRST check if this message matches a pending
            // inbound tunnel build (by replyMessageId). The STBM arrives back at the
            // builder after all transit hops forwarded it through the tunnel chain.
            var matchingInbound = PendingInbound
                .Where( pi => pi.Key.TunnelBuildReplyMessageId == stbm.MessageId )
                .Select( pi => pi.Key )
                .FirstOrDefault();

            if ( matchingInbound != null )
            {
                Logging.LogInformation( $"HandleShortTunnelBuild: Matched pending inbound tunnel {matchingInbound.TunnelDebugTrace} by msgId={stbm.MessageId:X8}" );
                // Convert STBM → STBRM (same records, different message type) per Java BuildHandler.handleRequestAsInboundEndpoint
                var replyMsg = new ShortTunnelBuildReplyMessage( stbm.Records );
                replyMsg.MessageId = stbm.MessageId;
                HandleReceivedShortInboundTunnelBuildReply( matchingInbound, replyMsg );
                return;
            }

            HandleShortTunnelBuildRecords( msg, stbm, from );
        }

        private void HandleShortTunnelBuildRecords( Ii2NpHeader msg, ShortTunnelBuildMessage stbm, I2PIdentHash from )
        {
            // Java I2P BuildHandler uses ctx.keyManager().getPublicKey() = identity key.
            // Tunnel build records are encrypted to the router's IDENTITY key, not the NTCP2 transport key.
            // Use identity key as primary, fall back to NTCP2 key for compatibility.
            var privateKey = RouterContext.Inst.X25519PrivateKey;
            var publicKey = RouterContext.Inst.X25519PublicKey;

            var decrypt = new TunnelLayer.ECIES.ECIESTunnelDecrypt( privateKey, publicKey );
            var result = decrypt.ProcessShortTunnelBuild( stbm );

            if (!result.Success)
            {
                // Fallback to NTCP2 transport key in case some implementations encrypt to the transport key
                var ntcp2Private = TransportLayer.TransportProvider.Inst?.GetNTCP2StaticPrivateKey();
                var ntcp2Public = TransportLayer.TransportProvider.Inst?.GetNTCP2StaticPublicKey();
                if (ntcp2Private != null && ntcp2Public != null && ntcp2Private != privateKey)
                {
                    Logging.LogDebug( "HandleShortTunnelBuildRecords: Identity key failed, trying NTCP2 key" );
                    decrypt = new TunnelLayer.ECIES.ECIESTunnelDecrypt( ntcp2Private, ntcp2Public );
                    result = decrypt.ProcessShortTunnelBuild( stbm );
                }
            }

            if (!result.Success)
            {
                Logging.LogDebug( "HandleShortTunnelBuildRecords: No record addressed to this router" );
                return;
            }

            var request = result.ShortRequest;
            var isGateway = (request.Flags & 0x80) != 0;
            var isEndpoint = (request.Flags & 0x40) != 0;

            Logging.LogInformation( $"HandleShortTunnelBuildRecords: Decrypted ECIES request: recv={request.ReceiveTunnelId}, " +
                $"next={request.NextRouterHash?.Id32Short}, flags=0x{request.Flags:X2}, gw={isGateway}, ep={isEndpoint}" );

            // Validate NextHop RouterInfo exists in our NetDb (like Java I2P BuildHandler)
            // Without it we can't establish a transport connection to forward tunnel data
            if ( !isEndpoint && request.NextRouterHash != null && !NetDb.Inst.Contains( request.NextRouterHash ) )
            {
                Logging.LogDebug( $"HandleShortTunnelBuildRecords: Dropping - NextHop {request.NextRouterHash.Id32Short} not in NetDb" );
                return;
            }

            // Check if we should accept this transit tunnel
            var replyStatus = Router.TransitTunnelMgr.AcceptingTunnels( request.NextRouterHash )
                ? TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.Accept
                : TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.RejectBandwidth;

            // Hidden mode: reject
            if ( RouterContext.Inst.IsHidden )
                replyStatus = TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.RejectBandwidth;

            // Create AEAD-encrypted reply and derive tunnel keys
            var (encryptedReply, replyKey, layerKey, ivKey, garlicKey, garlicTag) =
                decrypt.CreateShortReply( request, replyStatus, result.RecordIndex );

            // Place our encrypted reply into our record slot
            stbm.SetRecord( result.RecordIndex, encryptedReply );

            // ChaCha20-encrypt ALL OTHER records using our reply key
            // This is the layered encryption that each transit hop applies
            // (per Java BuildMessageProcessor / i2pd ShortECIESTunnelHopConfig::DecryptRecord)
            for (int i = 0; i < stbm.Records.Count; i++)
            {
                if (i == result.RecordIndex) continue;

                var nonce = TransportLayer.Crypto.ChaCha20Poly1305.CreateNonce( (ulong)i );

                var recordData = stbm.Records[i];
                var cipher = new Org.BouncyCastle.Crypto.Engines.ChaCha7539Engine();
                var parameters = new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                    new Org.BouncyCastle.Crypto.Parameters.KeyParameter(replyKey), nonce);
                cipher.Init(true, parameters);

                // Java I2P ChaCha20.java starts with counter = 1.
                // We skip 64 bytes (1 block) to match Java.
                var dummy = new byte[64];
                cipher.ProcessBytes(dummy, 0, 64, dummy, 0);

                cipher.ProcessBytes(recordData.BaseArray, recordData.BaseArrayOffset, recordData.Length, recordData.BaseArray, recordData.BaseArrayOffset);
            }

            if ( replyStatus == TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.Accept )
            {
                Logging.LogInformation( $"HandleShortTunnelBuildRecords: Accepted ECIES tunnel " +
                    $"recv={request.ReceiveTunnelId}, gw={isGateway}, ep={isEndpoint}, " +
                    $"next={request.NextRouterHash?.Id32Short}:{request.NextTunnelId}" );

                // Create a proper transit tunnel with the derived layer/IV keys
                if ( request.ReceiveTunnelId != null )
                {
                    var config = new TunnelConfig(
                        TunnelConfig.TunnelDirection.Inbound,
                        TunnelConfig.TunnelPool.External,
                        new TunnelInfo( new List<I2NP.Data.HopInfo>
                            {
                                new( RouterContext.Inst.MyRouterIdentity, new I2PTunnelId() )
                            }
                        ) );

                    // Create an ECIES transit tunnel using the HKDF-derived keys
                    var brrec = new I2NP.Data.BuildRequestRecord();
                    brrec.ReceiveTunnel = request.ReceiveTunnelId;
                    brrec.NextIdent = request.NextRouterHash;
                    brrec.NextTunnel = request.NextTunnelId;
                    // Write layer/IV keys into the record's data buffer at the correct offsets
                    brrec.LayerKey.Poke( new BufLen( layerKey ), 0 );
                    brrec.IvKey.Poke( new BufLen( ivKey ), 0 );

                    InboundTunnel tunnel;
                    if ( isGateway )
                    {
                        tunnel = new GatewayTunnel( Router.TransitTunnelMgr, config, brrec );
                    }
                    else if ( isEndpoint )
                    {
                        tunnel = new EndpointTunnel( Router.TransitTunnelMgr, config, brrec );
                    }
                    else
                    {
                        tunnel = new TransitTunnel( Router.TransitTunnelMgr, config, brrec );
                    }

                    tunnel.EstablishedTime.SetNow();

                    // Store the previous hop identity (transport-level sender of the build request)
                    if ( tunnel is TransitTunnel tt ) tt.ReceiveFrom = from;
                    else if ( tunnel is EndpointTunnel et ) et.ReceiveFrom = from;
                    // GatewayTunnel.ReceiveFrom stays null — gateways accept from any peer

                    AddTunnel( tunnel );
                    Router.TransitTunnelMgr.RegisterTransitTunnel( tunnel );
                }
            }

            // Forward the STBM (if transit) or send Garlic-wrapped STBRM (if OBEP).
            if ( isEndpoint )
            {
                // Outbound Endpoint (OBEP) role: wrap the STBRM in a Garlic message and send back.
                if ( request.NextRouterHash != null )
                {
                    try
                    {
                        // Convert STBM (type 25) to STBRM (type 26): same records, correct reply type
                        var stbrm = new ShortTunnelBuildReplyMessage( stbm.Records );
                        stbrm.MessageId = stbm.MessageId;
                        var garlic = CreateECIESGarlicMessage( stbrm, garlicKey, garlicTag );
                        if ( request.NextTunnelId != 0 )
                        {
                            // Send through the IBGW's tunnel
                            TransportProvider.Send( request.NextRouterHash, 
                                new TunnelGatewayMessage( garlic, request.NextTunnelId ) );
                            Logging.LogDebug( $"TunnelProvider: ECIES OBEP: Sent Garlic-wrapped build reply to IBGW {request.NextRouterHash.Id32Short}:{request.NextTunnelId}" );
                        }
                        else
                        {
                            // Send directly to the IBGW
                            TransportProvider.Send( request.NextRouterHash, garlic );
                            Logging.LogDebug( $"TunnelProvider: ECIES OBEP: Sent Garlic-wrapped build reply directly to IBGW {request.NextRouterHash.Id32Short}" );
                        }
                    }
                    catch ( Exception ex )
                    {
                        Logging.LogWarning( $"HandleShortTunnelBuildRecords: OBEP failed: {ex.Message}" );
                    }
                }
            }
            else if ( request.NextRouterHash != null )
            {
                // Transit hop role: forward the STBM to the next hop.
                // Per Java BuildHandler line 1121-1128: transit hops forward the STBM
                // DIRECTLY to the next peer (not via TunnelGateway), setting the message
                // UniqueId to the reply message ID from the record.
                try
                {
                    stbm.MessageId = request.NextMessageId;
                    TransportProvider.Send( request.NextRouterHash, stbm );
                    Logging.LogDebug( $"HandleShortTunnelBuildRecords: Forwarded to {request.NextRouterHash.Id32Short} msgId={request.NextMessageId:X8}" );
                }
                catch ( Exception ex )
                {
                    Logging.LogWarning( $"HandleShortTunnelBuildRecords: Failed to forward: {ex.Message}" );
                }
            }
        }

        private void HandleTunnelBuildRecords( Ii2NpHeader msg, IList<AesEgBuildRequestRecord> records, I2PIdentHash from )
        {
            var decrypt = new TunnelBuildRequestDecrypt(
                records,
                RouterContext.Inst.MyRouterIdentity.IdentHash,
                RouterContext.Inst.PrivateKey );

            if ( decrypt.ToMe() == null || decrypt.Decrypted == null )
            {
                Logging.LogDebug( $"HandleTunnelBuildRecords: Failed to find or decrypt a ToPeer16 record." );
                return;
            }

            if ( decrypt.Decrypted.OurIdent != RouterContext.Inst.MyRouterIdentity.IdentHash )
            {
                Logging.LogDebug( $"HandleTunnelBuildRecords: Failed to full id hash match {decrypt.Decrypted}" );
                return;
            }

            if ( decrypt.Decrypted.ToAnyone
                    || decrypt.Decrypted.FromAnyone
                    || decrypt.Decrypted.NextIdent != RouterContext.Inst.MyRouterIdentity.IdentHash )
            {
                TunnelBuildRequestEvents?.Invoke( msg, decrypt, from );
                return;
            }

            // Inbound tunnel build for me
            HandleIncomingTunnelBuildRecords( decrypt );
        }

#if DEBUG
        private TimeWindowDictionary<uint, RefPair<TickCounter, int>> ReallyOldTunnelBuilds =
            new( TickSpan.Minutes( 10 ) );

#endif

        private class TunnelBuildRepliesInfo
        {
            public int Count;
        }

        private static ConcurrentDictionary<BuildResponseRecord.RequestResponse,TunnelBuildRepliesInfo> _tunnelBuildReplies = 
                new();

        private static PeriodicAction _logTunnelBuildStatistics = new( TickSpan.Minutes( 1 ) );

        [Conditional( "DEBUG" )]
        public static void TunnelBuildStatistics( BuildResponseRecord.RequestResponse response )
        {
            var rs = _tunnelBuildReplies.GetOrAdd( response, rr => new TunnelBuildRepliesInfo() );
            ++rs.Count;

            _logTunnelBuildStatistics.Do( () =>
            {
                var items = _tunnelBuildReplies
                                .OrderBy( p => (byte)p.Key )
                                .ToArray();

                var sum = items.Sum( p => p.Value.Count ) / 100.0;

                var sta = items.Select( p => $" {p.Key}: {p.Value.Count} ({p.Value.Count / sum:F1}%)" );
                var line = $"TunnelProvider: TunnelBuildStatistics:{string.Join( ',', sta )}";
                Logging.LogDebug( line );
            } );
        }

        private void HandleIncomingTunnelBuildRecords( 
                TunnelBuildRequestDecrypt decrypt )
        {
            InboundTunnel[] tunnels;
            tunnels = PendingInbound
                .Where( t => t.Key.ReceiveTunnelId == decrypt.Decrypted.ReceiveTunnel )
                .Select( t => t.Key )
                .ToArray();

            if ( tunnels.Length == 0 )
            {
#if DEBUG
                ReallyOldTunnelBuilds.ProcessItem( decrypt.Decrypted.NextTunnel, ( k, p ) =>
                {
                    Logging.LogDebug( $"Tunnel build req failed {decrypt.Decrypted.NextTunnel} age {p.Left.DeltaToNowMilliseconds / p.Right} msec / hop. Unknown tunnel id." );
                } );
#endif
                return;
            }

            var myident = RouterContext.Inst.MyRouterIdentity.IdentHash;

            var cipher = new CbcBlockCipher( new AesEngine() );

            foreach ( var tunnel in tunnels )
            {
                var setup = tunnel.Config.Info;

                var decrypted = new List<BuildResponseRecord>();

                var recordcopies = new List<AesEgBuildRequestRecord>();
                foreach ( var one in decrypt.Records )
                {
                    recordcopies.Add( new AesEgBuildRequestRecord( new BufRef( one.Data.Clone() ) ) );
                }

                for ( int i = setup.Hops.Count - 1; i >= 0; --i )
                {
                    var hop = setup.Hops[i];
                    var proc = hop.ReplyProcessing;
                    cipher.Init( false, proc.ReplyKey.Key.ToParametersWithIv( proc.ReplyIv ) );

                    var rec = recordcopies[proc.BuildRequestIndex];
                    if ( myident.Hash16 == rec.ToPeer16 ) continue;

                    for ( int j = 0; j <= i; ++j )
                    {
                        cipher.Reset();
                        recordcopies[setup.Hops[j].ReplyProcessing.BuildRequestIndex].Process( cipher );
                    }

                    var newrec = new BuildResponseRecord( new BufRefLen( rec.Data ) );

                    decrypted.Add( newrec );

                    TunnelBuildStatistics( newrec.Reply );

                    if ( newrec.Reply == BuildResponseRecord.RequestResponse.Accept )
                    {
                        Logging.LogDebug( $"HandleTunnelBuildRecords: {tunnel} {tunnel.TunnelDebugTrace} " +
                            $"member: {hop.Peer.IdentHash.Id32Short}. Hop {i}. Reply: {newrec.Reply}" );

                        NetDb.Inst.Statistics.SuccessfulTunnelMember( hop.Peer.IdentHash );
                    }
                    else
                    {
                        Logging.LogDebug( $"HandleTunnelBuildRecords: {tunnel} {tunnel.TunnelDebugTrace} " +
                            $"member: {hop.Peer.IdentHash.Id32Short}. Hop {i}. Reply: {newrec.Reply}" );

                        NetDb.Inst.Statistics.DeclinedTunnelMember( hop.Peer.IdentHash );
                    }
                }

#if LOG_ALL_TUNNEL_TRANSFER
                Logging.LogDebug( $"HandleIncomingTunnelBuildRecords: {tunnel.Destination.Id32Short} " +
                    $"My inbound tunnel {tunnel.TunnelDebugTrace} request for tunnel id {tunnel.ReceiveTunnelId}" );
#endif

                if ( decrypted.All( r => r.Reply == BuildResponseRecord.RequestResponse.Accept ) )
                {
                    InboundTunnelEstablished( tunnel );
                }
                else
                {
                    Logging.LogDebug( $"HandleIncomingTunnelBuildRecords: Tunnel {tunnel.TunnelDebugTrace} build rejected." );

                    tunnel.Owner?.TunnelBuildFailed( tunnel, false );
                    tunnel.Shutdown();
                }
            }
        }

        internal void HandleVariableTunnelBuildReply( VariableTunnelBuildReplyMessage msg )
        {
            var matchingOut = PendingOutbound
                .Where( po => po.Key.TunnelBuildReplyMessageId == msg.MessageId )
                .Select( po => po.Key )
                .ToArray();

            foreach ( var obtunnel in matchingOut )
            {
                HandleReceivedTunnelBuildReply( obtunnel, msg );

#if LOG_ALL_TUNNEL_TRANSFER
                Logging.LogDebug( () => $"HandleVariableTunnelBuildReply: Outbound MsgId match {msg.MessageId:X8} for {obtunnel.TunnelDebugTrace}." );
#endif
            }

            var matchingIn = PendingInbound
                .Where( pi => pi.Key.TunnelBuildReplyMessageId == msg.MessageId )
                .Select( pi => pi.Key )
                .ToArray();

            foreach ( var intunnel in matchingIn )
            {
                HandleReceivedInboundTunnelBuildReply( intunnel, msg );

#if LOG_ALL_TUNNEL_TRANSFER
                Logging.LogDebug( () => $"HandleVariableTunnelBuildReply: Inbound MsgId match {msg.MessageId:X8} for {intunnel.TunnelDebugTrace}." );
#endif
            }

#if DEBUG
            if ( !matchingOut.Any() && !matchingIn.Any() )
            {
                ReallyOldTunnelBuilds.ProcessItem( msg.MessageId, ( k, p ) =>
                    Logging.LogDebug( $"Tunnel build req failed {msg.MessageId} age {p.Left.DeltaToNowMilliseconds / p.Right} msec / hop. MessageId unknown." )
                );
            }
#endif
        }

        internal void HandleShortTunnelBuildReply( ShortTunnelBuildReplyMessage msg )
        {
            Console.WriteLine( $"[DEBUG_LOG] HandleShortTunnelBuildReply: Received reply MessageId={msg.MessageId:X8}, Records={msg.Records?.Count}" );
            Logging.LogInformation( $"HandleShortTunnelBuildReply: Received reply MessageId={msg.MessageId:X8}, Records={msg.Records?.Count}" );

            // Check outbound tunnels first
            var matchingOut = PendingOutbound
                .Where( po => po.Key.TunnelBuildReplyMessageId == msg.MessageId )
                .Select( po => po.Key )
                .ToArray();

            foreach ( var obtunnel in matchingOut )
            {
                HandleReceivedShortTunnelBuildReply( obtunnel, msg );
                Logging.LogInformation( $"HandleShortTunnelBuildReply: MsgId match {msg.MessageId:X8} for outbound {obtunnel.TunnelDebugTrace}." );
                return;
            }

            // Check inbound tunnels
            var matchingIn = PendingInbound
                .Where( pi => pi.Key.TunnelBuildReplyMessageId == msg.MessageId )
                .Select( pi => pi.Key )
                .ToArray();

            foreach ( var intunnel in matchingIn )
            {
                HandleReceivedShortInboundTunnelBuildReply( intunnel, msg );
                Logging.LogInformation( $"HandleShortTunnelBuildReply: MsgId match {msg.MessageId:X8} for inbound {intunnel.TunnelDebugTrace}." );
                return;
            }

            Logging.LogWarning( $"HandleShortTunnelBuildReply: NO MATCH for MessageId={msg.MessageId:X8}." );
#if DEBUG
            ReallyOldTunnelBuilds.ProcessItem( msg.MessageId, ( k, p ) =>
                Logging.LogDebug( $"ECIES Tunnel build req failed {msg.MessageId} age {p.Left.DeltaToNowMilliseconds / p.Right} msec / hop. MessageId unknown." )
            );
#endif
        }

        /// <summary>
        /// Process ShortTunnelBuildReply for outbound tunnel.
        /// Matches Java I2P's BuildReplyHandler: peel layers per-record from LAST to targetHop + 1.
        /// </summary>
        private bool HandleReceivedShortTunnelBuildReply( OutboundTunnel obtunnel, ShortTunnelBuildReplyMessage msg )
        {
            var hops = obtunnel.Config.Info.Hops;
            Logging.LogInformation( $"HandleReceivedShortTunnelBuildReply: Processing ECIES reply for {obtunnel.TunnelDebugTrace} with {hops.Count} hops, {msg.Records.Count} records" );

            // Step 1: Peel off ChaCha20 layers from each record individually.
            // Record p (owned by hop p) was encrypted by all hops j > p in reverse order.
            for ( int p = 0; p < hops.Count; ++p )
            {
                var targetHop = hops[p];
                var recordIdx = targetHop.RecordIndex;
                if ( recordIdx < 0 || recordIdx >= msg.Records.Count ) continue;

                // Peel hops from last hop backwards to targetHop + 1
                for ( int j = hops.Count - 1; j > p; --j )
                {
                    var peelingHop = hops[j];
                    if ( peelingHop.ReplyKey != null )
                    {
                        ChaCha20DecryptRecord( msg, recordIdx, peelingHop.ReplyKey );
                    }
                }
            }

            // Check all hops accepted
            bool ok = true;

            // Step 2: AEAD-decrypt each record using its hop's own keys.
            for ( int h = 0; h < hops.Count; ++h )
            {
                var hop = hops[h];
                var recordIdx = hop.RecordIndex;
                if ( recordIdx < 0 || recordIdx >= msg.Records.Count ) continue;

                if ( hop.ReplyKey != null && hop.HandshakeHash != null )
                {
                    var nonce = TransportLayer.Crypto.ChaCha20Poly1305.CreateNonce( (ulong)recordIdx );

                    var recordData = msg.Records[recordIdx].ToByteArray();
                    var decrypted = TransportLayer.Crypto.ChaCha20Poly1305.Decrypt(
                        hop.ReplyKey, nonce, recordData, hop.HandshakeHash );
                    
                    if ( decrypted != null )
                    {
                        var fullRecord = new byte[218];
                        Array.Copy( decrypted, 0, fullRecord, 0, decrypted.Length );
                        msg.SetRecord( recordIdx, fullRecord );
                    }
                    else
                    {
                        Logging.LogWarning( $"HandleReceivedShortTunnelBuildReply: [{h}] AEAD decryption failed for record {recordIdx}" );
                        ok = false;
                    }
                }
            }

            for ( int i = 0; i < hops.Count; ++i )
            {
                var hop = hops[i];
                var recordIdx = hop.RecordIndex;
                if ( recordIdx < 0 || recordIdx >= msg.Records.Count ) { ok = false; continue; }

                var replyRecord = msg.Records[recordIdx];
                // Status byte at offset 201 (SHORT_RESPONSE_RECORD_RET_OFFSET in i2pd)
                var status = replyRecord.Length >= 202
                    ? (TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus)replyRecord[201]
                    : TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.RejectBandwidth;

                Logging.LogInformation( $"HandleReceivedShortTunnelBuildReply: hop[{i}] record[{recordIdx}] from {hop.Peer.IdentHash.Id32Short} status={status}" );
                Logging.LogInformation( $"[DEBUG_LOG] ShortTunnelBuildReply: hop[{i}] {hop.Peer.IdentHash.Id32Short} status={status}" );
                TunnelBuildLogger.Inst.Log( $"ShortTunnelBuildReply: hop[{i}] {hop.Peer.IdentHash.Id32Short} status={status}", obtunnel.TunnelDebugTrace, obtunnel.Pool.ToString(), obtunnel.TunnelDirection.ToString() );

                var accept = status == TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.Accept;
                if ( accept ) NetDb.Inst.Statistics.SuccessfulTunnelMember( hop.Peer.IdentHash );
                else NetDb.Inst.Statistics.DeclinedTunnelMember( hop.Peer.IdentHash );
                ok &= accept;
            }

            if ( ok )
            {
                OutboundTunnelEstablished( obtunnel );
                foreach ( var one in hops ) one.ReplyProcessing = null;
            }
            else
            {
                obtunnel.Owner?.TunnelBuildFailed( obtunnel, false );
                obtunnel.Shutdown();
            }
            return ok;
        }

        /// <summary>
        /// Process ShortTunnelBuildReply for inbound tunnel (external hops only).
        /// Matches Java I2P's BuildReplyHandler: peel layers per-record from LAST to targetHop + 1.
        /// </summary>
        private bool HandleReceivedShortInboundTunnelBuildReply( InboundTunnel intunnel, ShortTunnelBuildReplyMessage msg )
        {
            var hops = intunnel.Config.Info.Hops;
            var externalHopCount = hops.Count - 1;
            Logging.LogInformation( $"HandleReceivedShortInboundTunnelBuildReply: Processing for {intunnel.TunnelDebugTrace} with {externalHopCount} external hops, {msg.Records.Count} records" );

            // Step 1: Peel off ChaCha20 layers from each record individually.
            // Record p (owned by hop p) was encrypted by all hops j > p in reverse order.
            for ( int p = 0; p < externalHopCount; ++p )
            {
                var targetHop = hops[p];
                var recordIdx = targetHop.RecordIndex;
                if ( recordIdx < 0 || recordIdx >= msg.Records.Count ) continue;

                // Peel hops from last external hop backwards to targetHop + 1
                for ( int j = externalHopCount - 1; j > p; --j )
                {
                    var peelingHop = hops[j];
                    if ( peelingHop.ReplyKey != null )
                    {
                        ChaCha20DecryptRecord( msg, recordIdx, peelingHop.ReplyKey );
                    }
                }
            }

            // Check all hops accepted
            bool ok = true;

            // Step 2: AEAD-decrypt each record using its hop's own keys.
            for ( int h = 0; h < externalHopCount; ++h )
            {
                var hop = hops[h];
                var recordIdx = hop.RecordIndex;
                if ( recordIdx < 0 || recordIdx >= msg.Records.Count ) continue;

                if ( hop.ReplyKey != null && hop.HandshakeHash != null )
                {
                    var nonce = TransportLayer.Crypto.ChaCha20Poly1305.CreateNonce( (ulong)recordIdx );

                    var recordData = msg.Records[recordIdx].ToByteArray();
                    var decrypted = TransportLayer.Crypto.ChaCha20Poly1305.Decrypt(
                        hop.ReplyKey, nonce, recordData, hop.HandshakeHash );
                    
                    if ( decrypted != null )
                    {
                        var fullRecord = new byte[218];
                        Array.Copy( decrypted, 0, fullRecord, 0, decrypted.Length );
                        msg.SetRecord( recordIdx, fullRecord );
                    }
                    else
                    {
                        Logging.LogWarning( $"HandleReceivedShortInboundTunnelBuildReply: [{h}] AEAD decryption failed" );
                        ok = false;
                    }
                }
            }

            for ( int i = 0; i < externalHopCount; ++i )
            {
                var hop = hops[i];
                var recordIdx = hop.RecordIndex;
                if ( recordIdx < 0 || recordIdx >= msg.Records.Count ) { ok = false; continue; }

                var replyRecord = msg.Records[recordIdx];
                var status = replyRecord.Length >= 202
                    ? (TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus)replyRecord[201]
                    : TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.RejectBandwidth;

                Logging.LogInformation( $"HandleReceivedShortInboundTunnelBuildReply: hop[{i}] record[{recordIdx}] status={status}" );
                TunnelBuildLogger.Inst.Log( $"ShortInboundTunnelBuildReply: hop[{i}] {hop.Peer.IdentHash.Id32Short} status={status}", intunnel.TunnelDebugTrace, intunnel.Pool.ToString(), intunnel.TunnelDirection.ToString() );

                var accept = status == TunnelLayer.ECIES.ShortBuildReplyRecord.TunnelBuildReplyStatus.Accept;
                if ( accept ) NetDb.Inst.Statistics.SuccessfulTunnelMember( hop.Peer.IdentHash );
                else NetDb.Inst.Statistics.DeclinedTunnelMember( hop.Peer.IdentHash );
                ok &= accept;
            }

            if ( ok )
            {
                InboundTunnelEstablished( intunnel );
                foreach ( var one in hops ) one.ReplyProcessing = null;
            }
            else
            {
                intunnel.Owner?.TunnelBuildFailed( intunnel, false );
                intunnel.Shutdown();
            }
            return ok;
        }

        private static void ChaCha20DecryptRecord(ShortTunnelBuildReplyMessage msg, int recordIndex, byte[] replyKey)
        {
            var nonce = TransportLayer.Crypto.ChaCha20Poly1305.CreateNonce( (ulong)recordIndex );

            var cipher = new Org.BouncyCastle.Crypto.Engines.ChaCha7539Engine();
            var parameters = new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(replyKey), nonce);
            cipher.Init(false, parameters);

            // Java I2P ChaCha20.java starts with counter = 1.
            // BouncyCastle ChaCha7539Engine starts with counter = 0.
            // We skip 64 bytes (1 block) to match Java.
            var dummy = new byte[64];
            cipher.ProcessBytes(dummy, 0, 64, dummy, 0);

            var recordData = msg.Records[recordIndex];
            cipher.ProcessBytes(recordData.BaseArray, recordData.BaseArrayOffset, recordData.Length, recordData.BaseArray, recordData.BaseArrayOffset);
        }

        private bool HandleReceivedInboundTunnelBuildReply( InboundTunnel intunnel, VariableTunnelBuildReplyMessage msg )
        {
            var cipher = new CbcBlockCipher( new AesEngine() );

            var hops = intunnel.Config.Info.Hops;
            var extHopsCount = hops.Count - 1;

            // Decrypt the reply layered encryption (from last hop back to first)
            for ( int i = extHopsCount - 1; i >= 0; --i )
            {
                var proc = hops[i].ReplyProcessing;
                if ( proc == null ) continue;

                cipher.Init( false, proc.ReplyKey.Key.ToParametersWithIv( proc.ReplyIv ) );

                for ( int j = 0; j <= i; ++j )
                {
                    cipher.Reset();
                    var pl = msg.ResponseRecords[hops[j].ReplyProcessing.BuildRequestIndex].Payload;
                    cipher.ProcessBytes( pl );
                }
            }

            bool ok = true;
            for ( int i = 0; i < extHopsCount; ++i )
            {
                var hop = hops[i];
                if ( hop.ReplyProcessing == null ) continue;

                var ix = hop.ReplyProcessing.BuildRequestIndex;
                var onerecord = msg.ResponseRecords[ix];

                var okhash = onerecord.CheckHash();
                if ( !okhash )
                {
                    Logging.LogDebug( $"InboundTunnel {intunnel.TunnelDebugTrace}: Inbound tunnel build reply, hash check failed from {hop.Peer.IdentHash.Id32Short}" );
                    NetDb.Inst.Statistics.DestinationInformationFaulty( hop.Peer.IdentHash );
                }

                TunnelBuildStatistics( onerecord.Reply );

                var accept = onerecord.Reply == BuildResponseRecord.RequestResponse.Accept;
                if ( accept )
                {
                    NetDb.Inst.Statistics.SuccessfulTunnelMember( hop.Peer.IdentHash );
                }
                else
                {
                    NetDb.Inst.Statistics.DeclinedTunnelMember( hop.Peer.IdentHash );
                }

                ok &= accept && okhash;
                Logging.LogDebug( $"HandleReceivedInboundTunnelBuild: {intunnel.TunnelDebugTrace}: [{ix}] " +
                    $"from {hop.Peer.IdentHash.Id32Short}. {extHopsCount} hops, " +
                    $"Reply: {onerecord.Reply}" );
            }

            if ( ok )
            {
                intunnel.EstablishedTime.SetNow();
                intunnel.Established = true;
                TunnelBuildLogger.Inst.Log( $"Inbound tunnel established (ElGamal): {intunnel.TunnelDebugTrace}", intunnel.TunnelDebugTrace, intunnel.Pool.ToString(), intunnel.TunnelDirection.ToString() );

                InboundTunnelEstablished( intunnel );

                foreach ( var one in hops )
                {
                    if ( one.ReplyProcessing != null )
                    {
                        NetDb.Inst.Statistics.SuccessfulTunnelMember( one.Peer.IdentHash );
                        one.ReplyProcessing = null;
                    }
                }
            }
            else
            {
                intunnel.Owner?.TunnelBuildFailed( intunnel, false );

                foreach ( var one in hops )
                {
                    if ( one.ReplyProcessing != null )
                    {
                        NetDb.Inst.Statistics.DeclinedTunnelMember( one.Peer.IdentHash );
                        one.ReplyProcessing = null;
                    }
                }
                intunnel.Shutdown();
            }

            return ok;
        }

        private bool HandleReceivedTunnelBuildReply( OutboundTunnel obtunnel, VariableTunnelBuildReplyMessage msg )
        {
            var cipher = new CbcBlockCipher( new AesEngine() );

            var hops = obtunnel.Config.Info.Hops;

            for ( int i = hops.Count - 1; i >= 0; --i )
            {
                var proc = hops[i].ReplyProcessing;
                cipher.Init( false, proc.ReplyKey.Key.ToParametersWithIv( proc.ReplyIv ) );

                for ( int j = 0; j <= i; ++j )
                {
                    cipher.Reset();
                    var pl = msg.ResponseRecords[hops[j].ReplyProcessing.BuildRequestIndex].Payload;
                    cipher.ProcessBytes( pl );
                }
            }

            bool ok = true;
            for ( int i = 0; i < hops.Count; ++i )
            {
                var hop = hops[i];

                var ix = hop.ReplyProcessing.BuildRequestIndex;
                var onerecord = msg.ResponseRecords[ix];

                var okhash = onerecord.CheckHash();
                if ( !okhash )
                {
                    Logging.LogDebug( $"OutboundTunnel {obtunnel.TunnelDebugTrace}: Outbound tunnel build reply, hash check failed from {hop.Peer.IdentHash.Id32Short}" );
                    NetDb.Inst.Statistics.DestinationInformationFaulty( hop.Peer.IdentHash );
                }

                TunnelBuildStatistics( onerecord.Reply );

                var accept = onerecord.Reply == BuildResponseRecord.RequestResponse.Accept;
                if ( accept )
                {
                    NetDb.Inst.Statistics.SuccessfulTunnelMember( hop.Peer.IdentHash );
                }
                else
                {
                    NetDb.Inst.Statistics.DeclinedTunnelMember( hop.Peer.IdentHash );
                }

                ok &= accept && okhash;
                Logging.LogDebug( $"HandleReceivedTunnelBuild: {this}: [{ix}] " +
                    $"from {hop.Peer.IdentHash.Id32Short}. {hops.Count} hops, " +
                    $"Reply: {onerecord.Reply}" );
            }

            if ( ok )
            {
                TunnelProvider.Inst.OutboundTunnelEstablished( obtunnel );
                foreach ( var one in hops )
                {
                    NetDb.Inst.Statistics.SuccessfulTunnelMember( one.Peer.IdentHash );
                    one.ReplyProcessing = null; // We dont need this anymore
                }
            }
            else
            {
                obtunnel.Owner?.TunnelBuildFailed( obtunnel, false );

                foreach ( var one in hops )
                {
                    NetDb.Inst.Statistics.DeclinedTunnelMember( one.Peer.IdentHash );
                    one.ReplyProcessing = null; // We dont need this anymore
                }
                obtunnel.Shutdown();
            }

            return ok;
        }

        private void OutboundTunnelEstablished( OutboundTunnel tunnel )
        {
            tunnel.EstablishedTime.SetNow();
            tunnel.Established = true;
            TunnelBuildLogger.Inst.Log( $"Outbound tunnel established: {tunnel.TunnelDebugTrace}", tunnel.TunnelDebugTrace, tunnel.Pool.ToString(), tunnel.TunnelDirection.ToString() );

            if ( tunnel.Pool == TunnelConfig.TunnelPool.Client || tunnel.Pool == TunnelConfig.TunnelPool.Exploratory )
            {
                var members = tunnel.TunnelMembers.ToArray();
                if ( members != null )
                {
                    var delta = ( tunnel.EstablishedTime - tunnel.CreationTime ).ToMilliseconds;
                    var hops = members.Length + tunnel.ReplyTunnelHops;
                    var deltaperhop = delta / hops;
                    tunnel.Metrics.BuildTimePerHop = TickSpan.Milliseconds( deltaperhop );
                    try
                    {
                        foreach ( var member in members ) NetDb.Inst.Statistics.TunnelBuildTimeMsPerHop( member.IdentHash, deltaperhop );
                    }
                    catch ( Exception ex )
                    {
                        Logging.Log( ex );
                    }
                }

#if RUN_TUNNEL_TESTS
                if ( !tunnel?.Terminated ?? false ) TunnelTester.Inst.Test( tunnel );
#endif
            }

            PendingOutbound.TryRemove( tunnel, out _ );
            EstablishedOutbound[tunnel] = 1;

            // Self-test AES layer encryption for each hop
            foreach (var hop in tunnel.Config.Info.Hops)
            {
                if (hop.LayerKey != null && hop.IvKey != null)
                    OutboundTunnel.SelfTestEncryption(hop);
            }

            tunnel.Owner?.TunnelEstablished( tunnel );
        }

        private void InboundTunnelEstablished( InboundTunnel tunnel )
        {
            tunnel.EstablishedTime.SetNow();
            tunnel.Established = true;
            TunnelBuildLogger.Inst.Log( $"Inbound tunnel established: {tunnel.TunnelDebugTrace}", tunnel.TunnelDebugTrace, tunnel.Pool.ToString(), tunnel.TunnelDirection.ToString() );

            if ( tunnel.Pool == TunnelConfig.TunnelPool.Client || tunnel.Pool == TunnelConfig.TunnelPool.Exploratory )
            {
                var members = tunnel.TunnelMembers.ToArray();
                if ( members != null )
                {
                    var delta = ( tunnel.EstablishedTime - tunnel.CreationTime ).ToMilliseconds;
                    var hops = members.Length + tunnel.OutTunnelHops - 1;
                    var deltaperhop = delta / hops;
                    tunnel.Metrics.BuildTimePerHop = TickSpan.Milliseconds( deltaperhop );
                    try
                    {
                        foreach ( var member in members ) NetDb.Inst.Statistics.TunnelBuildTimeMsPerHop( member.IdentHash, deltaperhop );
                    }
                    catch ( Exception ex )
                    {
                        Logging.Log( ex );
                    }
                }

#if RUN_TUNNEL_TESTS
                if ( !tunnel?.Terminated ?? false ) TunnelTester.Inst.Test( tunnel );
#endif
            }

            PendingInbound.TryRemove( tunnel, out _ );
            EstablishedInbound[tunnel] = 1;

            tunnel.Owner?.TunnelEstablished( tunnel );
        }

        internal void TunnelTestFailed( Tunnel tunnel )
        {
            tunnel.Owner?.TunnelFailed( tunnel );

            // If inbound, it might receieve something. Let it expire normally.
            if ( tunnel is OutboundTunnel )
            {
                RemoveTunnel( tunnel );
                tunnel.Shutdown();
            }
        }

        public static T SelectTunnel<T>( IEnumerable<T> tunnels, double elitism = TunnelSelectionElitism ) where T : Tunnel
        {
            var available = tunnels
                    .Where( t => !t.Terminated
                                    && !t.Expired );

            var real = available.Where( t => !( t is ZeroHopTunnel || t is ZeroHopOutboundTunnel ) );
            if ( real.Any() )
            {
                available = real;
            }

            if ( available.Any() )
            {
                var result = (T)available.RandomWeighted(
                    GenerateTunnelWeight, elitism );

#if LOG_TUNNEL_SELECTION
                var logAvailable = string.Join( ", ", available.Select( t => $"{t.TunnelDebugTrace} {t.CreationTime.DeltaToNow:MS}" ) );
                Logging.LogDebug( $"TunnelProvider: SelectTunnel {result}, ( {logAvailable} )" );
#endif
                return result;
            }

            return null;
        }

        public static T SelectTunnel<T>( IEnumerable<T> tunnels, I2PIdentHash closestTo ) where T : Tunnel
        {
            var available = tunnels
                    .Where( t => !t.Terminated
                                    && !t.Expired );

            var real = available.Where( t => !( t is ZeroHopTunnel || t is ZeroHopOutboundTunnel ) );
            if ( real.Any() )
            {
                available = real;
            }

            if ( available.Any() )
            {
                // XOR locality: find tunnels whose remote gateway/endpoint is XOR closest to closestTo
                var sorted = available
                    .OrderBy( t => t.FarEnd ^ closestTo )
                    .Take( 3 ) // Take 3 closest
                    .ToArray();

                var result = sorted[BufUtils.RandomInt( sorted.Length )];

#if LOG_TUNNEL_SELECTION
                Logging.LogDebug( $"TunnelProvider: SelectTunnel (XOR) {result} closest to {closestTo}" );
#endif
                return result;
            }

            return null;
        }

        public static double GenerateTunnelWeight( Tunnel t )
        {
            var penalty = Tunnel.ExpectedTunnelBuildTimePerHop.ToMilliseconds * 2.0;

            var result = t.Metrics.MinLatencyMeasured?.ToMilliseconds ?? penalty;
            result += t.Metrics.BuildTimePerHop?.ToMilliseconds ?? penalty;
            result += t.CreationTime.DeltaToNow.ToMilliseconds / 60;
            result += t.CreationTime.DeltaToNow < TickSpan.Seconds( 30 ) ? penalty : 0;
            if ( t.NeedsRecreation ) result += penalty;
            if ( t.Pool == TunnelConfig.TunnelPool.Exploratory ) result += penalty / 2.0;
            if ( !t.Metrics.PassedTunnelTest ) result += penalty;
            if ( t.Expired ) result += 10 * penalty;
            if ( t.Terminated ) result += 10 * penalty;

            return -result;
        }

        public override string ToString()
        {
            return GetType().Name;
        }
    }
}
