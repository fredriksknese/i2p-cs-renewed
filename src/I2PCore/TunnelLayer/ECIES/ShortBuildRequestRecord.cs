using System;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.ECIES
{
    /// <summary>
    /// Short ECIES Tunnel Build Request Record
    ///
    /// Per i2pd I2NPProtocol.h:
    ///   SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE = 154
    ///   SHORT_TUNNEL_BUILD_RECORD_SIZE = 218 (on-wire size)
    ///   SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET = 16
    ///
    /// On-wire record layout (218 bytes total):
    ///   bytes 0-15:    first 16 bytes of receiving router's ident hash (for routing)
    ///   bytes 16-217:  Noise N encrypted section (202 bytes)
    ///                  = ephemeral key (32) + encrypted cleartext (154) + MAC (16)
    ///
    /// Cleartext layout (154 bytes - what gets encrypted):
    ///   bytes 0-3:     receive tunnel ID (4 bytes)
    ///   bytes 4-7:     next tunnel ID (4 bytes)
    ///   bytes 8-39:    next router hash (32 bytes - full hash)
    ///   byte  40:      flags (1 byte)
    ///   bytes 41-42:   more flags (2 bytes, reserved)
    ///   byte  43:      layer encryption type (1 byte, 0=AES)
    ///   bytes 44-47:   request time (4 bytes, minutes since epoch)
    ///   bytes 48-51:   request expiration (4 bytes, seconds)
    ///   bytes 52-55:   send message ID (4 bytes)
    ///   bytes 56-153:  padding (zeroed)
    /// </summary>
    public class ShortBuildRequestRecord
    {
        public const int ClearTextSize = 154;
        public const int OnWireRecordSize = 218;
        public const int EncryptedOffset = 16;

        // Keep for backward compat but point to correct size
        public const int UnencryptedRecordSize = ClearTextSize;
        public const int EncryptedRecordSize = OnWireRecordSize;

        // Fields
        public I2PTunnelId ReceiveTunnelId { get; set; }
        public I2PIdentHash NextRouterHash { get; set; }
        public I2PTunnelId NextTunnelId { get; set; }
        public uint LayerKeyIndex { get; set; }
        public uint IVKeyIndex { get; set; }
        public uint ReplyKeyIndex { get; set; }
        public uint ReplyIVIndex { get; set; }
        public byte Flags { get; set; }
        public uint RequestTime { get; set; }
        public uint RequestExpiration { get; set; }
        public uint NextMessageId { get; set; }
        public I2PMapping Options { get; set; }

        /// <summary>
        /// Flags field bits
        /// </summary>
        [Flags]
        public enum BuildRequestFlags : byte
        {
            None = 0,
            InboundGateway = 0x80,   // bit 7: IBGW
            OutboundEndpoint = 0x40,  // bit 6: OBEP
            // bits 5-0: reserved
        }

        public ShortBuildRequestRecord()
        {
            Options = new I2PMapping();
            RequestExpiration = 600; // Default 10 minutes
        }

        /// <summary>
        /// Create a new short build request record
        /// </summary>
        public ShortBuildRequestRecord(
            I2PTunnelId receiveTunnelId,
            I2PIdentHash nextRouterHash,
            I2PTunnelId nextTunnelId,
            byte flags,
            uint requestTime,
            uint nextMessageId)
        {
            ReceiveTunnelId = receiveTunnelId;
            NextRouterHash = nextRouterHash;
            NextTunnelId = nextTunnelId;
            Flags = flags;
            RequestTime = requestTime;
            RequestExpiration = 600;
            NextMessageId = nextMessageId;
            Options = new I2PMapping();

            // Key indices will be derived from KDF, set to 0 for now
            LayerKeyIndex = 0;
            IVKeyIndex = 0;
            ReplyKeyIndex = 0;
            ReplyIVIndex = 0;
        }

        /// <summary>
        /// Parse an unencrypted short build request record (154 bytes).
        /// Field order must match Write() and the spec cleartext layout.
        /// </summary>
        public ShortBuildRequestRecord(BufRef reader)
        {
            var start = new BufRef(reader);
            // offset 0: receive tunnel ID (4 bytes)
            ReceiveTunnelId = new I2PTunnelId(reader);
            // offset 4: next tunnel ID (4 bytes)
            NextTunnelId = new I2PTunnelId(reader);
            
            // offset 8: next ident (32 bytes)
            NextRouterHash = new I2PIdentHash(reader);

            // offset 40: flags (1 byte)
            Flags = reader.Read8();
            // offset 41: more flags (2 bytes)
            reader.Read(2);
            // offset 43: layer encryption type (1 byte)
            reader.Read8();
            // offset 44: request time (4 bytes)
            RequestTime = reader.ReadFlip32();
            // offset 48: request expiration (4 bytes)
            RequestExpiration = reader.ReadFlip32();
            // offset 52: send message ID (4 bytes)
            NextMessageId = reader.ReadFlip32();

            // Skip padding to 154 bytes
            var read = reader - start;
            if (read < ClearTextSize)
                reader.Read(ClearTextSize - (int)read);

            // Short records derive all keys via HKDF; no key index fields
            LayerKeyIndex = 0;
            IVKeyIndex = 0;
            ReplyKeyIndex = 0;
            ReplyIVIndex = 0;
        }

        /// <summary>
        /// Write the cleartext record (154 bytes) matching i2pd layout.
        /// This is what gets Noise N encrypted.
        /// </summary>
        public void Write(BufRefStream dest)
        {
            var start = dest.Length;

            // Per i2pd TunnelConfig.cpp ShortECIESTunnelHopConfig::CreateBuildRequestRecord:
            // offset 0:  receiveTunnelID (4 bytes)
            ReceiveTunnelId.Write(dest);
            // offset 4:  nextTunnelID (4 bytes)
            NextTunnelId.Write(dest);
            // offset 8:  nextIdent (32 bytes)
            NextRouterHash.Write(dest);
            // offset 40: flag (1 byte)
            dest.Write(Flags);
            // offset 41: more flags (2 bytes, reserved = 0)
            dest.Write((byte)0);
            dest.Write((byte)0);
            // offset 43: layer encryption type (1 byte, 0 = AES)
            dest.Write((byte)0);
            // offset 44: request time (4 bytes, minutes since epoch)
            dest.Write(BufUtils.Flip32Bl(RequestTime));
            // offset 48: request expiration (4 bytes, seconds)
            dest.Write(BufUtils.Flip32Bl(RequestExpiration));
            // offset 52: send message ID (4 bytes)
            dest.Write(BufUtils.Flip32Bl(NextMessageId));
            // offset 56: options mapping
            var written = (int)(dest.Length - start);
            if (written < ClearTextSize)
            {
                var optionsStream = new BufRefStream();
                Options.Write(optionsStream);
                var optionsBytes = optionsStream.ToByteArray();
                
                var remaining = ClearTextSize - written;
                var toCopy = Math.Min(optionsBytes.Length, remaining);
                dest.Write(optionsBytes, 0, toCopy);
                
                if (toCopy < remaining)
                {
                    dest.Write(new byte[remaining - toCopy]);
                }
            }
        }

        /// <summary>
        /// Convert to byte array
        /// </summary>
        public byte[] ToByteArray()
        {
            var stream = new BufRefStream();
            Write(stream);
            return stream.ToByteArray();
        }

        /// <summary>
        /// Check if this is an inbound gateway
        /// </summary>
        public bool IsInboundGateway()
        {
            return (Flags & (byte)BuildRequestFlags.InboundGateway) != 0;
        }

        /// <summary>
        /// Check if this is an outbound endpoint
        /// </summary>
        public bool IsOutboundEndpoint()
        {
            return (Flags & (byte)BuildRequestFlags.OutboundEndpoint) != 0;
        }

        /// <summary>
        /// Derive all tunnel keys from the handshake in one pass
        /// Match Java BuildRequestRecord.java
        /// </summary>
        public static (byte[] layerKey, byte[] ivKey, byte[] replyKey, byte[] replyAD, byte[] garlicKey, ulong garlicTag) DeriveAllKeys(
            byte[] chainingKey,
            byte[] handshakeHash,
            bool isOutboundEndpoint)
        {
            var ck = new byte[32];
            Array.Copy(chainingKey, 0, ck, 0, 32);

            // Step 1: Reply key - HKDF(CK, null, "SMTunnelReplyKey") -> newCK, replyKey
            var derived1 = TransportLayer.Crypto.NoiseKDF.HKDF(ck, null, System.Text.Encoding.ASCII.GetBytes("SMTunnelReplyKey"), 64);
            var replyKey = new byte[32];
            Array.Copy(derived1, 32, replyKey, 0, 32);
            Array.Copy(derived1, 0, ck, 0, 32); // CK is now CK_after_step1

            // Step 2: Layer key - HKDF(CK, [], "SMTunnelLayerKey") -> newCK, layerKey
            var derived2 = TransportLayer.Crypto.NoiseKDF.HKDF(ck, null, System.Text.Encoding.ASCII.GetBytes("SMTunnelLayerKey"), 64);
            var layerKey = new byte[32];
            Array.Copy(derived2, 32, layerKey, 0, 32);
            // DO NOT update ck yet - Java updates it only if isOBEP

            // Step 3: IV key
            byte[] ivKey = new byte[32];
            byte[] garlicKey = null;
            ulong garlicTag = 0;

            if (isOutboundEndpoint)
            {
                // Update ck to CK_after_step2
                Array.Copy(derived2, 0, ck, 0, 32);
                Utils.Logging.LogCritical($"[DEBUG_LOG] DeriveAllKeys: Step 2 OBEP CK={BitConverter.ToString(ck, 0, 4)}");

                // Step 3: HKDF(CK, [], "TunnelLayerIVKey") -> newCK, ivKey
                var derived3 = TransportLayer.Crypto.NoiseKDF.HKDF(ck, null, System.Text.Encoding.ASCII.GetBytes("TunnelLayerIVKey"), 64);
                Array.Copy(derived3, 32, ivKey, 0, 32);
                Array.Copy(derived3, 0, ck, 0, 32); // CK is now CK_after_step3
                Utils.Logging.LogCritical($"[DEBUG_LOG] DeriveAllKeys: Step 3 CK={BitConverter.ToString(ck, 0, 4)}, ivKey={BitConverter.ToString(ivKey, 0, 4)}");

                // Step 4: HKDF(CK, [], "RGarlicKeyAndTag") -> newCK(32) + key(32) = 64 bytes
                // Per Java I2P BuildRequestRecord.java:
                //   newck[0..31]  = derived4[0..31]
                //   dgk[0..31]    = derived4[32..63]
                //   garlicTag is first 8 bytes of newck
                var derived4 = TransportLayer.Crypto.NoiseKDF.HKDF(ck, null, System.Text.Encoding.ASCII.GetBytes("RGarlicKeyAndTag"), 64);
                
                // Update CK with newck
                Array.Copy(derived4, 0, ck, 0, 32);
                
                // Garlic tag is first 8 bytes of newck (derived4[0..7])
                garlicTag = BufUtils.Flip64(BitConverter.ToUInt64(derived4, 0));
                Utils.Logging.LogCritical($"[DEBUG_LOG] DeriveAllKeys: Step 4 OBEP garlicTag={garlicTag:X16}, derived4[0..7]={BitConverter.ToString(derived4, 0, 8)}");
                
                // Garlic key is dgk (derived4[32..63])
                garlicKey = new byte[32];
                Array.Copy(derived4, 32, garlicKey, 0, 32);
                
                Utils.Logging.LogCritical($"[DEBUG_LOG] DeriveAllKeys: Step 4 garlicTag={garlicTag:X16}, key={BitConverter.ToString(garlicKey, 0, 4)}");
            }
            else
            {
                // non-OBEP matches Java: _derivedIVKey = new SessionKey(newck) (where newck is derived2[0..31])
                Array.Copy(derived2, 0, ivKey, 0, 32);
            }

            return (layerKey, ivKey, replyKey, (byte[])handshakeHash.Clone(), garlicKey, garlicTag);
        }

        public static void DeriveNextKey(byte[] ck, string info)
        {
            var salt = new byte[32];
            Array.Copy(ck, 0, salt, 0, 32);
            var derived = TransportLayer.Crypto.NoiseKDF.HKDF(salt,
                null, System.Text.Encoding.ASCII.GetBytes(info), 64);
            Array.Copy(derived, 0, ck, 0, 64);
        }

        public override string ToString()
        {
            return $"ShortBuildRequestRecord: Recv={ReceiveTunnelId}, Next={NextRouterHash.Id32Short}, " +
                   $"NextTunnel={NextTunnelId}, Flags=0x{Flags:X2}, Time={RequestTime}, MsgId={NextMessageId}";
        }
    }
}
