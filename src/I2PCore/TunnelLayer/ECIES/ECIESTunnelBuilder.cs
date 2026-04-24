using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TransportLayer.Crypto;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TunnelLayer.ECIES
{
    /// <summary>
    /// ECIES Tunnel Builder
    /// Creates encrypted tunnel build messages using ECIES (Noise N pattern)
    /// Supports both short (218 byte) and long (528 byte) record formats
    /// </summary>
    public class ECIESTunnelBuilder
    {
        /// <summary>
        /// Build a short format tunnel build message
        /// </summary>
        /// <param name="hops">List of tunnel hops with their public keys and request records</param>
        /// <returns>ShortTunnelBuildMessage with encrypted records</returns>
        public static ShortTunnelBuildMessage BuildShortTunnel(List<TunnelBuildHop> hops)
        {
            if (hops == null || hops.Count == 0)
                throw new ArgumentException("At least one hop is required", nameof(hops));

            if (hops.Count > ShortTunnelBuildMessage.MaxRecords)
                throw new ArgumentException($"Maximum {ShortTunnelBuildMessage.MaxRecords} hops allowed", nameof(hops));

            var encryptedRecords = new List<byte[]>();

            foreach (var hop in hops)
            {
                // Validate hop
                if (hop.RouterPublicKey == null)
                    throw new ArgumentException("Router public key is required", nameof(hops));

                // Extract X25519 part from Hybrid keys if needed
                var hopPubKey = hop.RouterPublicKey;
                if (hopPubKey.Length != 32)
                {
                    hopPubKey = hopPubKey.Skip(hopPubKey.Length - 32).Take(32).ToArray();
                }

                if (hop.ShortRequest == null)
                    throw new ArgumentException("Short request record is required", nameof(hops));

                // Serialize the cleartext record (154 bytes per i2pd spec)
                var plaintextRecord = hop.ShortRequest.ToByteArray();
                if (plaintextRecord.Length != ShortBuildRequestRecord.ClearTextSize)
                    throw new InvalidOperationException(
                        $"Short request cleartext must be {ShortBuildRequestRecord.ClearTextSize} bytes, got {plaintextRecord.Length}");

                // Encrypt using Noise N pattern and get chaining key
                // Noise N produces: ephemeralKey(32) + encrypted(154) + MAC(16) = 202 bytes
                Utils.Logging.LogCritical($"[DEBUG_LOG] BuildShortTunnel: Encrypting for {hop.RouterHash.Id32Short} using hopPubKey={BitConverter.ToString(hopPubKey, 0, 4)}");
                var (noiseMessage, chainingKey, handshakeHash) = EncryptShortRecordWithKeys(hopPubKey, plaintextRecord);

                // Build the on-wire record (218 bytes):
                // bytes 0-15:   first 16 bytes of router's ident hash (for routing)
                // bytes 16-217: Noise N encrypted message (202 bytes)
                var record = new byte[ShortBuildRequestRecord.OnWireRecordSize];
                var routerHashBytes = hop.RouterHash.Hash.ToByteArray();
                Array.Copy(routerHashBytes, 0, record, 0, 16);
                Array.Copy(noiseMessage, 0, record, ShortBuildRequestRecord.EncryptedOffset,
                    noiseMessage.Length);

                // Derive all keys immediately (Step 1-4 from BuildRequestRecord.java)
                var (layerKey, ivKey, replyKey, replyAD, garlicKey, garlicTag) = ShortBuildRequestRecord.DeriveAllKeys(
                    chainingKey, 
                    handshakeHash, 
                    hop.ShortRequest.IsOutboundEndpoint());

                hop.LayerKey = layerKey;
                hop.IvKey = ivKey;
                hop.ReplyKey = replyKey;
                hop.HandshakeHash = replyAD;
                hop.GarlicKey = garlicKey;
                hop.GarlicTag = garlicTag;

                encryptedRecords.Add(record);
            }

            return new ShortTunnelBuildMessage(encryptedRecords);
        }

        /// <summary>
        /// Encrypt long build request records for mixed tunnels
        /// Returns list of encrypted records that can be used with existing tunnel building code
        /// Note: VariableTunnelBuildMessage uses ElGamal format, so this is for ECIES records only
        /// </summary>
        public static List<byte[]> EncryptLongRecords(List<TunnelBuildHop> hops)
        {
            if (hops == null || hops.Count == 0)
                throw new ArgumentException("At least one hop is required", nameof(hops));

            var encryptedRecords = new List<byte[]>();

            foreach (var hop in hops)
            {
                if (!hop.IsECIES)
                    throw new ArgumentException("All hops must be ECIES routers for this method", nameof(hops));

                if (hop.RouterPublicKey == null)
                    throw new ArgumentException("ECIES router public key is required", nameof(hops));

                var hopPubKey = hop.RouterPublicKey;
                if (hopPubKey.Length != 32)
                {
                    hopPubKey = hopPubKey.Skip(hopPubKey.Length - 32).Take(32).ToArray();
                }

                if (hop.LongRequest == null)
                    throw new ArgumentException("Long request record is required for ECIES hop", nameof(hops));

                var plaintextRecord = hop.LongRequest.ToByteArray();
                if (plaintextRecord.Length != LongBuildRequestRecord.UnencryptedRecordSize)
                    throw new InvalidOperationException($"Long request record must be {LongBuildRequestRecord.UnencryptedRecordSize} bytes");

                var encryptedRecord = EncryptLongRecord(hopPubKey, plaintextRecord);
                encryptedRecords.Add(encryptedRecord);
            }

            return encryptedRecords;
        }

        /// <summary>
        /// Encrypt a short build request record using Noise N pattern
        /// Returns encrypted record and chaining key for key derivation
        /// </summary>
        private static (byte[] encryptedRecord, byte[] chainingKey, byte[] handshakeHash) EncryptShortRecordWithKeys(
            byte[] hopPublicKey,
            byte[] plaintextRecord)
        {
            if (hopPublicKey == null || hopPublicKey.Length != 32)
                throw new ArgumentException("Hop public key must be 32 bytes", nameof(hopPublicKey));

            if (plaintextRecord == null || plaintextRecord.Length != ShortBuildRequestRecord.ClearTextSize)
                throw new ArgumentException($"Plaintext record must be {ShortBuildRequestRecord.ClearTextSize} bytes, got {plaintextRecord?.Length}", nameof(plaintextRecord));

            // Create Noise N initiator
            var noiseN = NoiseN.CreateInitiator(hopPublicKey);

            // Encrypt the record
            // Result format: ephemeralKey (32) || encryptedPayload (218 + 16 MAC) = 266 bytes total
            var encryptedMessage = noiseN.CreateMessage(plaintextRecord);

            // Get chaining key and hash for key derivation
            var chainingKey = noiseN.GetChainingKey();
            var handshakeHash = noiseN.GetHash();

            // Dispose Noise state
            noiseN.Dispose();

            return (encryptedMessage, chainingKey, handshakeHash);
        }

        /// <summary>
        /// Encrypt a short build request record using Noise N pattern
        /// </summary>
        private static byte[] EncryptShortRecord(byte[] hopPublicKey, byte[] plaintextRecord)
        {
            var (encryptedRecord, _, _) = EncryptShortRecordWithKeys(hopPublicKey, plaintextRecord);
            return encryptedRecord;
        }

        /// <summary>
        /// Encrypt a long build request record using Noise N pattern
        /// </summary>
        private static byte[] EncryptLongRecord(byte[] hopPublicKey, byte[] plaintextRecord)
        {
            if (hopPublicKey == null || hopPublicKey.Length != 32)
                throw new ArgumentException("Hop public key must be 32 bytes", nameof(hopPublicKey));

            if (plaintextRecord == null || plaintextRecord.Length != LongBuildRequestRecord.UnencryptedRecordSize)
                throw new ArgumentException($"Plaintext record must be {LongBuildRequestRecord.UnencryptedRecordSize} bytes", nameof(plaintextRecord));

            // For long records, we use the full Noise N message format
            // Create Noise N initiator
            var noiseN = NoiseN.CreateInitiator(hopPublicKey);

            // Encrypt the record
            // Result format: ephemeralKey (32) || encryptedPayload (528 + 16 MAC) = 576 bytes total
            var encryptedMessage = noiseN.CreateMessage(plaintextRecord);

            // Dispose Noise state
            noiseN.Dispose();

            return encryptedMessage;
        }

    }

    /// <summary>
    /// Represents a single hop in a tunnel being built
    /// </summary>
    public class TunnelBuildHop
    {
        /// <summary>
        /// Router identity hash
        /// </summary>
        public I2PIdentHash RouterHash { get; set; }

        /// <summary>
        /// Router's X25519 public key (for ECIES routers)
        /// </summary>
        public byte[] RouterPublicKey { get; set; }

        /// <summary>
        /// Is this an ECIES router (vs ElGamal)?
        /// </summary>
        public bool IsECIES { get; set; }

        /// <summary>
        /// Short format build request (for ECIES-only tunnels)
        /// </summary>
        public ShortBuildRequestRecord ShortRequest { get; set; }

        /// <summary>
        /// Long format build request (for mixed tunnels)
        /// </summary>
        public LongBuildRequestRecord LongRequest { get; set; }

        /// <summary>
        /// Ephemeral private key used for this hop (saved for reply decryption)
        /// </summary>
        public byte[] EphemeralPrivateKey { get; set; }

        /// <summary>
        /// Chaining key from Noise handshake (for key derivation)
        /// </summary>
        public byte[] ChainingKey { get; set; }

        /// <summary>
        /// Handshake hash from Noise N (for AEAD reply decryption)
        /// </summary>
        public byte[] HandshakeHash { get; set; }

        /// <summary>
        /// Derived tunnel layer encryption key (32 bytes).
        /// For ECIES: derived from ChainingKey via HKDF after tunnel build.
        /// For ElGamal: randomly generated and stored in the build request record.
        /// </summary>
        public byte[] LayerKey { get; set; }

        /// <summary>
        /// Derived tunnel IV key (32 bytes).
        /// </summary>
        public byte[] IvKey { get; set; }

        /// <summary>
        /// Reply key for decrypting the build response.
        /// </summary>
        public byte[] ReplyKey { get; set; }

        /// <summary>
        /// Garlic tag for ECIES outbound tunnel build reply (endpoint only)
        /// </summary>
        public ulong GarlicTag { get; set; }

        /// <summary>
        /// Garlic key for ECIES outbound tunnel build reply (endpoint only)
        /// </summary>
        public byte[] GarlicKey { get; set; }

        public TunnelBuildHop(I2PIdentHash routerHash, byte[] routerPublicKey, bool isECIES = true)
        {
            RouterHash = routerHash ?? throw new ArgumentNullException(nameof(routerHash));
            RouterPublicKey = routerPublicKey;
            IsECIES = isECIES;
        }
    }
}
