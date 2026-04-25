using System;
using System.Buffers;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.ECIES
{
    /// <summary>
    /// Long ECIES Tunnel Build Request Record
    ///
    /// Unencrypted size: 528 bytes
    /// Used for mixed tunnels with ElGamal/ECIES routers
    /// Contains same fields as short record but with more padding
    /// </summary>
    public class LongBuildRequestRecord
    {
        // Record structure matches ShortBuildRequestRecord but padded to 528 bytes
        // bytes 0-3:     receive tunnel ID (4 bytes)
        // bytes 4-35:    next router hash (32 bytes)
        // bytes 36-39:   next tunnel ID (4 bytes)
        // bytes 40-43:   layer key (4 byte integer, derived from KDF)
        // bytes 44-47:   IV key (4 byte integer, derived from KDF)
        // bytes 48-51:   reply key (4 byte integer, derived from KDF)
        // bytes 52-55:   reply IV (4 byte integer, derived from KDF)
        // byte  56:      flags (1 byte)
        // bytes 57-60:   request time (4 bytes, minutes since epoch)
        // bytes 61-64:   request expiration (4 bytes, seconds)
        // bytes 65-68:   next message ID (4 bytes)
        // bytes 69-x:    tunnel build options (Mapping)
        // bytes x-527:   random padding

        public const int UnencryptedRecordSize = 528;
        public const int EncryptedRecordSize = 528;

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

        public LongBuildRequestRecord()
        {
            Options = new I2PMapping();
            RequestExpiration = 600; // Default 10 minutes
        }

        /// <summary>
        /// Create a new long build request record
        /// </summary>
        public LongBuildRequestRecord(
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
        /// Parse an unencrypted long build request record
        /// </summary>
        public LongBuildRequestRecord(I2PBufferCursor reader)
        {
            ReceiveTunnelId = new I2PTunnelId(reader);
            NextRouterHash = new I2PIdentHash(reader);
            NextTunnelId = new I2PTunnelId(reader);
            LayerKeyIndex = reader.ReadUInt32BigEndian();
            IVKeyIndex = reader.ReadUInt32BigEndian();
            ReplyKeyIndex = reader.ReadUInt32BigEndian();
            ReplyIVIndex = reader.ReadUInt32BigEndian();
            Flags = reader.ReadByte();
            RequestTime = reader.ReadUInt32BigEndian();
            RequestExpiration = reader.ReadUInt32BigEndian();
            NextMessageId = reader.ReadUInt32BigEndian();

            // Parse options mapping
            Options = new I2PMapping(reader);

            // Remaining bytes are padding (ignore)
        }

        /// <summary>
        /// Write the unencrypted record to a buffer
        /// </summary>
        public void Write(IBufferWriter<byte> dest)
        {
            var startCount = (dest as ArrayBufferWriter<byte>)?.WrittenCount ?? 0;

            ReceiveTunnelId.Write(dest);
            NextRouterHash.Write(dest);
            NextTunnelId.Write(dest);
            dest.WriteUInt32BigEndian(LayerKeyIndex);
            dest.WriteUInt32BigEndian(IVKeyIndex);
            dest.WriteUInt32BigEndian(ReplyKeyIndex);
            dest.WriteUInt32BigEndian(ReplyIVIndex);
            dest.WriteByte(Flags);
            dest.WriteUInt32BigEndian(RequestTime);
            dest.WriteUInt32BigEndian(RequestExpiration);
            dest.WriteUInt32BigEndian(NextMessageId);
            Options.Write(dest);

            // Pad to 528 bytes with random data
            var written = (int)((dest as ArrayBufferWriter<byte>)?.WrittenCount ?? 0) - (int)startCount;
            if (written < UnencryptedRecordSize)
            {
                var paddingSize = UnencryptedRecordSize - written;
                var padding = BufUtils.RandomBytes(paddingSize);
                dest.WriteBytes(padding);
            }
        }

        /// <summary>
        /// Convert to byte array
        /// </summary>
        public byte[] ToByteArray()
        {
            var stream = new ArrayBufferWriter<byte>();
            Write(stream);
            return stream.WrittenSpan.ToArray();
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
        /// Derive tunnel layer keys from the handshake
        /// Uses HKDF to derive keys from the Noise N shared secret
        /// </summary>
        public static (byte[] layerKey, byte[] ivKey) DeriveLayerKeys(
            byte[] chainingKey,
            uint layerKeyIndex,
            uint ivKeyIndex)
        {
            // Use HKDF to derive layer encryption keys
            // These are used for tunnel data encryption (AES-256)
            var layerKeyMaterial = HKDF.DeriveKey(
                chainingKey,
                BitConverter.GetBytes(layerKeyIndex),
                System.Text.Encoding.ASCII.GetBytes("layer-key"),
                32);

            var ivKeyMaterial = HKDF.DeriveKey(
                chainingKey,
                BitConverter.GetBytes(ivKeyIndex),
                System.Text.Encoding.ASCII.GetBytes("iv-key"),
                32);

            return (layerKeyMaterial, ivKeyMaterial);
        }

        /// <summary>
        /// Derive reply keys from the handshake
        /// </summary>
        public static (byte[] replyKey, byte[] replyIV) DeriveReplyKeys(
            byte[] chainingKey,
            uint replyKeyIndex,
            uint replyIVIndex)
        {
            // Use HKDF to derive ChaCha20 reply encryption keys
            var replyKeyMaterial = HKDF.DeriveKey(
                chainingKey,
                BitConverter.GetBytes(replyKeyIndex),
                System.Text.Encoding.ASCII.GetBytes("reply-key"),
                32);

            var replyIVMaterial = HKDF.DeriveKey(
                chainingKey,
                BitConverter.GetBytes(replyIVIndex),
                System.Text.Encoding.ASCII.GetBytes("reply-iv"),
                32);

            return (replyKeyMaterial, replyIVMaterial);
        }

        public override string ToString()
        {
            return $"LongBuildRequestRecord: Recv={ReceiveTunnelId}, Next={NextRouterHash.Id32Short}, " +
                   $"NextTunnel={NextTunnelId}, Flags=0x{Flags:X2}, Time={RequestTime}, MsgId={NextMessageId}";
        }
    }
}
