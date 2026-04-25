using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.ECIES;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class VariableTunnelBuildMessage : I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.VariableTunnelBuild; } }

        public List<AesEgBuildRequestRecord> Records = new();

        public VariableTunnelBuildMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );
            var records = reader.ReadByte();

            for ( int i = 0; i < records; ++i )
            {
                var r = new AesEgBuildRequestRecord( reader );
                Records.Add( r );
            }
            SetBuffer( start, reader );
        }

        private VariableTunnelBuildMessage( byte hops )
        {
            AllocateBuffer( 1 + hops * AesEgBuildRequestRecord.Length );
            var writer = new I2PBufferCursor( Payload );
            writer.WriteByte( hops );
            for ( int i = 0; i < hops; ++i ) Records.Add( new AesEgBuildRequestRecord( writer ) );
        }

        // Clones records
        public VariableTunnelBuildMessage( IEnumerable<AesEgBuildRequestRecord> records )
        {
            var hops = (byte)records.Count();
            AllocateBuffer( 1 + hops * AesEgBuildRequestRecord.Length );
            var writer = new I2PBufferCursor( Payload );
            writer.WriteByte( hops );
            foreach ( var rec in records )
            {
                Records.Add( rec );
                writer.WriteBlock( rec.Data );
            }
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "VariableTunnelBuild" );
            for ( int i = 0; i < Records.Count; ++i )
            {
                result.Append( Records[i].ToString() );
            }

            return result.ToString();
        }

        public static I2NpMessage BuildOutboundTunnel(
            TunnelInfo setup,
            I2PIdentHash replyaddr, I2PTunnelId replytunnel,
            uint replymessageid )
        {
            Console.WriteLine($"[DEBUG_LOG] BuildOutboundTunnel: {setup.Hops.Count} hops");
            // Check if all hops are ECIES routers
            bool allECIES = setup.Hops.All(hop => IsECIESRouter(hop.Peer));
            Console.WriteLine($"[DEBUG_LOG] BuildOutboundTunnel: allECIES={allECIES}");

            // Use ECIES-only tunnel if all routers support it
            if (allECIES && setup.Hops.Count <= 8)
            {
                try
                {
                    var eciesMessage = BuildECIESOutboundTunnel(setup, replyaddr, replytunnel, replymessageid);
                    Logging.LogInformation($"VariableTunnelBuildMessage: Building ECIES-only tunnel with {setup.Hops.Count} hops");
                    return eciesMessage;
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"VariableTunnelBuildMessage: ECIES tunnel build failed, falling back to ElGamal: {ex.Message}");
                }
            }
            else if (allECIES)
            {
                Logging.LogInformation("VariableTunnelBuildMessage: All ECIES routers but > 8 hops, using ElGamal");
            }

            // Fall back to ElGamal for mixed or failed tunnels
            byte usehops = (byte)( setup.Hops.Count > 5 ? 8 : 5 );
            //byte usehops = 7; // 8 makes the response "TunnelBuildReply"
            var result = new VariableTunnelBuildMessage( usehops );

            // Hop sort order
            var requests = new List<BuildRequestRecord>();

            for ( int i = 0; i < setup.Hops.Count; ++i )
            {
                // Hop order: Our out dest -> Endpoint
                var endpoint = i == setup.Hops.Count - 1;
                var gateway = i == 0;

                var rec = new BuildRequestRecord();

                rec.Data.Randomize();
                rec.Flag = 0;

                var hop = setup.Hops[i];

                rec.OurIdent = hop.Peer.IdentHash;
                rec.ReceiveTunnel = hop.TunnelId;

                if ( !endpoint )
                {
                    var nexthop = setup.Hops[i + 1];

                    rec.NextIdent = nexthop.Peer.IdentHash;
                    rec.NextTunnel = nexthop.TunnelId;
                }
                else
                {
                    rec.SendMessageId = replymessageid;

                    rec.NextIdent = replyaddr;
                    rec.NextTunnel = replytunnel;
                }

                rec.RequestTime = DateTime.UtcNow;
                rec.ToAnyone = endpoint;

                hop.LayerKey = new I2PSessionKey( rec.LayerKey.Clone() );
                hop.IvKey = new I2PSessionKey( rec.IvKey.Clone() );

                requests.Add( rec );

#if LOG_ALL_TUNNEL_TRANSFER
                Logging.Log( rec.ToString() );
#endif
            }

            // Physical record sort order
            var order = BufUtils.Shuffle( result.Records ).ToList();

            // Scramble the rest
            for ( int i = setup.Hops.Count; i < usehops; ++i )
            {
                order[i].Data.Randomize();
            }

            // ElGamal encrypt all of the non random records
            // and place them in shuffled order.
            for ( int i = 0; i < setup.Hops.Count; ++i )
            {
                var hop = setup.Hops[i];
                var egrec = new EgBuildRequestRecord( order[i].Data, requests[i], hop.Peer.IdentHash, hop.Peer.PublicKey );
            }

            var cipher = new CbcBlockCipher( new AesEngine() );

            // Dont Aes the first destination
            for ( int i = setup.Hops.Count - 2; i >= 0 ; --i )
            {
                var prevhop = requests[i];

                cipher.Init( false, prevhop.ReplyKeyBuf.ToParametersWithIv( prevhop.ReplyIv ) );

                for ( int j = i + 1; j < usehops; ++j )
                {
                    cipher.Reset();
                    order[j].Process( cipher );
                }
            }

            for ( int i = 0; i < setup.Hops.Count; ++i )
            {
                setup.Hops[i].ReplyProcessing = new ReplyProcessingInfo()
                {
                    BuildRequestIndex = result.Records.IndexOf( order[i] ),
                    ReplyIv = requests[i].ReplyIv.Clone(),
                    ReplyKey = new I2PSessionKey( requests[i].ReplyKeyBuf.Clone() )
                };
            }

            return result;
        }

        public static I2NpMessage BuildInboundTunnel(
            TunnelInfo setup,
            I2PIdentHash replyaddr,
            I2PTunnelId replytunnel,
            uint replymessageid )
        {
            Logging.LogCritical($"[DEBUG_LOG] BuildInboundTunnel: {setup.Hops.Count} hops");
            // Check if all hops are ECIES routers
            bool allECIES = setup.Hops.All(hop => IsECIESRouter(hop.Peer));

            if (allECIES && setup.Hops.Count <= 8)
            {
                try
                {
                    var eciesMessage = BuildECIESInboundTunnel(setup, replyaddr, replytunnel, replymessageid);
                    Logging.LogInformation($"VariableTunnelBuildMessage: Building ECIES-only INBOUND tunnel with {setup.Hops.Count} hops");
                    return eciesMessage;
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"VariableTunnelBuildMessage: ECIES inbound tunnel build failed, falling back: {ex.Message}");
                }
            }

            // Fall back to ElGamal
            byte usehops = (byte)( setup.Hops.Count > 5 ? 8 : 5 );
            var result = new VariableTunnelBuildMessage( usehops );

            // Hop sort order
            var requests = new List<BuildRequestRecord>();

            for ( int i = 0; i < setup.Hops.Count; ++i )
            {
                // Hop order: GW -> us
                var endpoint = i == setup.Hops.Count - 1;
                var gateway = i == 0;

                var rec = new BuildRequestRecord();

                rec.Data.Randomize();
                rec.Flag = 0;

                var hop = setup.Hops[i];

                rec.OurIdent = hop.Peer.IdentHash;
                rec.ReceiveTunnel = hop.TunnelId;

                if ( !endpoint )
                {
                    var nexthop = setup.Hops[i + 1];

                    rec.NextIdent = nexthop.Peer.IdentHash;
                    rec.NextTunnel = nexthop.TunnelId;
                }
                else
                {
                    // Used to identify the record as the last in an inbound tunnel to us
                    rec.NextIdent = hop.Peer.IdentHash;
                    rec.NextTunnel = hop.TunnelId;
                }

                if ( endpoint || ( i + 2 >= setup.Hops.Count ) )
                {
                    rec.SendMessageId = replymessageid;
                }

                rec.RequestTime = DateTime.UtcNow;
                rec.FromAnyone = gateway;

                hop.LayerKey = new I2PSessionKey( rec.LayerKey.Clone() );
                hop.IvKey = new I2PSessionKey( rec.IvKey.Clone() );

                requests.Add( rec );

#if LOG_ALL_TUNNEL_TRANSFER
                Logging.Log( rec.ToString() );
#endif
            }

            // Physical record sort order
            var order = BufUtils.Shuffle( result.Records ).ToList();

            // Scramble the rest
            for ( int i = setup.Hops.Count; i < usehops; ++i )
            {
                order[i].Data.Randomize();
            }

            // ElGamal encrypt all of the non random records
            // and place them in shuffled order.
            for ( int i = 0; i < setup.Hops.Count; ++i )
            {
                var hop = setup.Hops[i];
                var egrec = new EgBuildRequestRecord( order[i].Data, requests[i], hop.Peer.IdentHash, hop.Peer.PublicKey );
            }

            var cipher = new BufferedBlockCipher( new CbcBlockCipher( new AesEngine() ) );

            // Dont Aes the first block
            for ( int i = setup.Hops.Count - 2; i >= 0; --i )
            {
                var prevhop = requests[i];

                cipher.Init( false, new ParametersWithIV( new KeyParameter( prevhop.ReplyKey.ToByteArray() ), prevhop.ReplyIv.ToByteArray() ) );

                for ( int j = i + 1; j < usehops; ++j )
                {
                    cipher.Reset();
                    order[j].Process( cipher );
                }
            }

            for ( int i = 0; i < setup.Hops.Count; ++i )
            {
                setup.Hops[i].ReplyProcessing = new ReplyProcessingInfo()
                {
                    BuildRequestIndex = result.Records.IndexOf( order[i] ),
                    ReplyIv = requests[i].ReplyIv.Clone(),
                    ReplyKey = new I2PSessionKey( requests[i].ReplyKeyBuf.Clone() )
                };
            }

            return result;
        }

        private const int STANDARD_NUM_RECORDS = 8;

        /// <summary>
        /// Build ECIES-only outbound tunnel using ShortTunnelBuildMessage.
        /// Matches i2pd's Tunnel::Build flow: create records, shuffle, layer-encrypt.
        /// </summary>
        private static ShortTunnelBuildMessage BuildECIESOutboundTunnel(
            TunnelInfo setup,
            I2PIdentHash replyaddr,
            I2PTunnelId replytunnel,
            uint replymessageid)
        {
            if (setup.Hops.Count > 8)
                throw new ArgumentException("Short tunnel build supports max 8 hops");

            var numHops = setup.Hops.Count;
            var numRecords = Math.Max(STANDARD_NUM_RECORDS, numHops);

            // Create ECIES build hops and encrypt each record independently (Noise N)
            var eciesHops = new List<TunnelBuildHop>();

            for (int i = 0; i < numHops; ++i)
            {
                var endpoint = i == numHops - 1;
                var hop = setup.Hops[i];
                var hopPubKey = GetECIESPublicKey(hop.Peer);
                // Also get the NTCP2 's' key for comparison (should be DIFFERENT from identity key)
                var ri = NetDb.Inst?[hop.Peer.IdentHash];
                var ntcp2Key = ri?.GetECIESPublicKey();
                var ntcp2Hex = ntcp2Key != null ? BitConverter.ToString(ntcp2Key, 0, Math.Min(8, ntcp2Key.Length)) : "null";
                var hashPrefix = BitConverter.ToString(hop.Peer.IdentHash.Hash.ToByteArray(), 0, 8);
                Logging.LogCritical($"[DEBUG_LOG] BuildECIESOutboundTunnel: hop={i}/{numHops} endpoint={endpoint} router={hop.Peer.IdentHash.Id32Short} identityPubKey({hopPubKey.Length}b)={BitConverter.ToString(hopPubKey, 0, Math.Min(8, hopPubKey.Length))}... ntcp2Key={ntcp2Hex}... hashPrefix={hashPrefix}...");

                var shortRecord = new ShortBuildRequestRecord
                {
                    ReceiveTunnelId = hop.TunnelId,
                    NextRouterHash = endpoint ? replyaddr : setup.Hops[i + 1].Peer.IdentHash,
                    NextTunnelId = endpoint ? replytunnel : setup.Hops[i + 1].TunnelId,
                    Flags = (byte)(endpoint ? ShortBuildRequestRecord.BuildRequestFlags.OutboundEndpoint : 0),
                    RequestTime = (uint)((DateTime.UtcNow - I2PDate.RefDate).TotalMinutes),
                    NextMessageId = endpoint ? replymessageid : 0,
                };

                var buildHop = new TunnelBuildHop(
                    hop.Peer.IdentHash,
                    GetECIESPublicKey(hop.Peer),
                    isECIES: true)
                {
                    ShortRequest = shortRecord
                };

                eciesHops.Add(buildHop);
            }

            // Encrypt each hop's record with Noise N
            var stbmReal = ECIESTunnelBuilder.BuildShortTunnel(eciesHops);

            // Build full record array: real records + random fake records, then shuffle
            var allRecords = new byte[numRecords][];
            var recordIndices = Enumerable.Range(0, numRecords).ToList();
            recordIndices.ShuffleList();

            // Place real records at shuffled positions
            for (int i = 0; i < numHops; ++i)
            {
                allRecords[recordIndices[i]] = stbmReal.Records[i].ToByteArray();
                setup.Hops[i].RecordIndex = recordIndices[i];
            }

            // Fill remaining positions with random data (fake/phony records)
            for (int i = numHops; i < numRecords; ++i)
            {
                allRecords[recordIndices[i]] = BufUtils.RandomBytes(ShortTunnelBuildMessage.RecordSize);
            }

            // Derive keys from Noise handshake (already derived in BuildShortTunnel)
            for (int i = 0; i < numHops; ++i)
            {
                var hop = setup.Hops[i];
                var eciesHop = eciesHops[i];
                var isEndpoint = i == numHops - 1;

                hop.ReplyKey = eciesHop.ReplyKey;
                hop.LayerKey = new I2PSessionKey(eciesHop.LayerKey);
                hop.IvKey = new I2PSessionKey(eciesHop.IvKey);
                hop.HandshakeHash = eciesHop.HandshakeHash;

                // Step 4: RGarlic key and tag (endpoint only)
                if (isEndpoint)
                {
                    hop.GarlicTag = eciesHop.GarlicTag;
                    hop.GarlicKey = eciesHop.GarlicKey;
                    Logging.LogDebug($"BuildECIESOutboundTunnel: Endpoint garlic tag={hop.GarlicTag:X16}");
                }
            }

            // Inter-record ChaCha20 layered encryption (i2pd Tunnel::Build lines 84-96).
            // For each hop from second-to-last backwards, ChaCha20-encrypt all subsequent records
            // using that hop's reply key. This creates the layered encryption that each hop peels.
            ApplyLayeredEncryption(allRecords, setup.Hops, numHops, numRecords);

            var stbm = new ShortTunnelBuildMessage(allRecords.ToList());
            stbm.MessageId = replymessageid;

            Logging.LogInformation($"BuildECIESOutboundTunnel: {numHops} hops, {numRecords} records");
            return stbm;
        }

        /// <summary>
        /// Build ECIES-only inbound tunnel using ShortTunnelBuildMessage.
        /// Inbound tunnel: gateway (first hop) receives from outside, endpoint (last hop before us) sends to us.
        /// </summary>
        private static ShortTunnelBuildMessage BuildECIESInboundTunnel(
            TunnelInfo setup,
            I2PIdentHash replyaddr,
            I2PTunnelId replytunnel,
            uint replymessageid)
        {
            var externalHopCount = setup.Hops.Count - 1;
            if (externalHopCount < 1)
                throw new ArgumentException("Inbound tunnel must have at least one external hop");
            if (externalHopCount > 8)
                throw new ArgumentException("Short tunnel build supports max 8 hops");

            // i2pd adds a phony record for inbound tunnels when numHops < MAX_NUM_RECORDS
            var numRecords = Math.Max(STANDARD_NUM_RECORDS, externalHopCount);

            var eciesHops = new List<ECIES.TunnelBuildHop>();

            for (int i = 0; i < externalHopCount; ++i)
            {
                var gateway = i == 0;
                var endpoint = i == externalHopCount - 1;
                var hop = setup.Hops[i];

                // Per Java BuildMessageGenerator: isInGW = inbound && hop==0, isOutEnd = !inbound && ...
                // For inbound tunnels, isOutEnd is ALWAYS false. Only IBGW gets a flag.
                byte flags = 0;
                if (gateway) flags |= (byte)ECIES.ShortBuildRequestRecord.BuildRequestFlags.InboundGateway;
                // Do NOT set OutboundEndpoint for inbound tunnels (Java never does)

                // For ALL hops including endpoint: next hop is setup.Hops[i+1]
                // For the endpoint (i == externalHopCount - 1), Hops[i+1] is our own router (IBEP)
                var shortRecord = new ECIES.ShortBuildRequestRecord
                {
                    ReceiveTunnelId = hop.TunnelId,
                    NextRouterHash = setup.Hops[i + 1].Peer.IdentHash,
                    NextTunnelId = setup.Hops[i + 1].TunnelId,
                    Flags = flags,
                    RequestTime = (uint)((DateTime.UtcNow - I2PDate.RefDate).TotalMinutes),
                    NextMessageId = endpoint ? replymessageid : 0,
                };

                var buildHop = new ECIES.TunnelBuildHop(
                    hop.Peer.IdentHash,
                    GetECIESPublicKey(hop.Peer),
                    isECIES: true)
                {
                    ShortRequest = shortRecord
                };

                eciesHops.Add(buildHop);
            }

            var stbmReal = ECIES.ECIESTunnelBuilder.BuildShortTunnel(eciesHops);

            // Build full record array: real + fake, shuffled
            var allRecords = new byte[numRecords][];
            var recordIndices = Enumerable.Range(0, numRecords).ToList();
            recordIndices.ShuffleList();

            for (int i = 0; i < externalHopCount; ++i)
            {
                allRecords[recordIndices[i]] = stbmReal.Records[i].ToByteArray();
                setup.Hops[i].RecordIndex = recordIndices[i];
            }
            for (int i = externalHopCount; i < numRecords; ++i)
            {
                allRecords[recordIndices[i]] = BufUtils.RandomBytes(ShortTunnelBuildMessage.RecordSize);
            }

            // Derive keys for external hops (already derived in BuildShortTunnel)
            for (int i = 0; i < externalHopCount; ++i)
            {
                var hop = setup.Hops[i];
                var eciesHop = eciesHops[i];

                hop.ReplyKey = eciesHop.ReplyKey;
                hop.LayerKey = new I2PSessionKey(eciesHop.LayerKey);
                hop.IvKey = new I2PSessionKey(eciesHop.IvKey);
                hop.HandshakeHash = eciesHop.HandshakeHash;
                
                // Copy Garlic keys/tags even for inbound (Noise context)
                hop.GarlicKey = eciesHop.GarlicKey;
                hop.GarlicTag = eciesHop.GarlicTag;
            }

            // Apply layered ChaCha20 encryption
            ApplyLayeredEncryption(allRecords, setup.Hops, externalHopCount, numRecords);

            var stbm = new ShortTunnelBuildMessage(allRecords.ToList());
            stbm.MessageId = replymessageid;

            // Log inbound tunnel details for debugging
            var lastExtHop = setup.Hops[externalHopCount - 1];
            var ourHop = setup.Hops[externalHopCount];
            Logging.LogInformation($"BuildECIESInboundTunnel: {externalHopCount} external hops, {numRecords} records, " +
                $"endpoint={lastExtHop.Peer.IdentHash.Id32Short}:{lastExtHop.TunnelId}, " +
                $"IBEP(us)={ourHop.Peer.IdentHash.Id32Short}:{ourHop.TunnelId}, " +
                $"replyMsgId={replymessageid:X8}");
            return stbm;
        }


        /// <summary>
        /// Apply inter-record ChaCha20 layered encryption (i2pd Tunnel::Build lines 84-96).
        /// For each hop from second-to-last backwards, ChaCha20-encrypt all subsequent hop records
        /// using that hop's reply key.
        /// </summary>
        private static void ApplyLayeredEncryption(byte[][] allRecords, List<I2NP.Data.HopInfo> hops, int realHopCount, int numRecords)
        {
            if (realHopCount <= 1) return; // No layering needed for 1-hop

            // Process from second-to-last hop backwards to first
            for (int h = realHopCount - 2; h >= 0; --h)
            {
                var hop = hops[h];
                if (hop.ReplyKey == null) continue;

                // Encrypt all records of subsequent hops (and fake records)
                for (int s = h + 1; s < realHopCount; ++s)
                {
                    var targetIdx = hops[s].RecordIndex;
                    ChaCha20EncryptRecord(allRecords, targetIdx, hop.ReplyKey);
                }
                // Also encrypt fake records
                var realIndices = new HashSet<int>();
                for (int i = 0; i < realHopCount; ++i) realIndices.Add(hops[i].RecordIndex);
                for (int idx = 0; idx < numRecords; ++idx)
                {
                    if (!realIndices.Contains(idx) && idx != hops[h].RecordIndex)
                    {
                        ChaCha20EncryptRecord(allRecords, idx, hop.ReplyKey);
                    }
                }
            }
        }

        /// <summary>
        /// ChaCha20 encrypt a single record in-place (not AEAD, just stream cipher).
        /// Nonce[4] = recordIndex, matching i2pd's ShortECIESTunnelHopConfig::DecryptRecord.
        /// </summary>
        private static void ChaCha20EncryptRecord(byte[][] allRecords, int recordIndex, byte[] replyKey)
        {
            var nonce = new byte[12];
            // Java I2P BuildReplyHandler: iv[4] = (byte) recordNum;
            nonce[4] = (byte)(recordIndex & 0xFF);

            var cipher = new Org.BouncyCastle.Crypto.Engines.ChaCha7539Engine();
            var parameters = new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
                new Org.BouncyCastle.Crypto.Parameters.KeyParameter(replyKey), nonce);
            cipher.Init(true, parameters);

            // Java I2P ChaCha20.java starts with counter = 1.
            // BouncyCastle ChaCha7539Engine starts with counter = 0.
            // We skip 64 bytes (1 block) to match Java's counter = 1.
            var dummy = new byte[64];
            cipher.ProcessBytes(dummy, 0, 64, dummy, 0);

            cipher.ProcessBytes(allRecords[recordIndex], 0, allRecords[recordIndex].Length, allRecords[recordIndex], 0);
        }

        public class ReplyProcessingInfo
        {
            public int BuildRequestIndex;
            public I2PSessionKey ReplyKey;
            public I2PByteBlock ReplyIv;
        }

        /// <summary>
        /// Check if a router supports ECIES short tunnel builds.
        /// Per Java I2P BuildRequestor.supportsShortTBM(): the router's identity
        /// key type must be ECIES_X25519 (or a hybrid PQ variant).
        /// </summary>
        private static bool IsECIESRouter(I2PKeysAndCert peer)
        {
            var keyType = peer.Certificate.PublicKeyType;
            return keyType == I2PKeyType.KeyTypes.X25519 ||
                   keyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
                   keyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
                   keyType == I2PKeyType.KeyTypes.MLKEM1024_X25519;
        }

        /// <summary>
        /// Get the X25519 public key for ECIES tunnel build encryption.
        /// </summary>
        private static byte[] GetECIESPublicKey(I2PKeysAndCert peer)
        {
            var pubkey = peer.PublicKey.ToByteArray();
            var keyType = peer.Certificate.PublicKeyType;

            // For X25519 identity keys, use directly
            if (pubkey.Length == 32 && keyType == I2PKeyType.KeyTypes.X25519) return pubkey;

            // For hybrid PQ keys (ML-KEM + X25519), extract the X25519 component (last 32 bytes)
            if (keyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
                keyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
                keyType == I2PKeyType.KeyTypes.MLKEM1024_X25519)
            {
                return pubkey.Skip(pubkey.Length - 32).Take(32).ToArray();
            }

            throw new InvalidOperationException(
                $"ECIES public key must be 32 bytes, got {pubkey.Length} for type {keyType} " +
                $"for {peer.IdentHash.Id32Short}");
        }
    }
}
