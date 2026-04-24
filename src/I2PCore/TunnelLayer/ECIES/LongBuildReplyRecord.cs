using System;
using I2PCore.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.TunnelLayer.ECIES
{
    /// <summary>
    /// Long ECIES Tunnel Build Reply Record
    ///
    /// Unencrypted size: 528 bytes
    /// Used for replies in mixed tunnels with ElGamal/ECIES routers
    ///
    /// Structure:
    /// - bytes 0-526: options (Mapping) + padding
    /// - byte 527: reply status
    /// </summary>
    public class LongBuildReplyRecord
    {
        public const int UnencryptedRecordSize = 528;
        public const int EncryptedRecordSize = 528;

        public I2PMapping Options { get; set; }
        public TunnelBuildReplyStatus Status { get; set; }

        /// <summary>
        /// Reply status codes
        /// </summary>
        public enum TunnelBuildReplyStatus : byte
        {
            Accept = 0x00,
            RejectBandwidth = 30,
            RejectTransitTunnels = 50,
            RejectCongestion = 60,
            RejectProbabilistic = 70
        }

        public LongBuildReplyRecord()
        {
            Options = new I2PMapping();
            Status = TunnelBuildReplyStatus.Accept;
        }

        public LongBuildReplyRecord(I2PMapping options, TunnelBuildReplyStatus status)
        {
            Options = options ?? new I2PMapping();
            Status = status;
        }

        /// <summary>
        /// Parse an unencrypted long build reply record
        /// </summary>
        public LongBuildReplyRecord(BufRef reader)
        {
            // Parse options mapping
            Options = new I2PMapping(reader);

            // Skip to the reply byte at position 527
            var currentPos = reader.BaseArrayOffset;
            var statusPos = UnencryptedRecordSize - 1; // Last byte

            if (currentPos < statusPos)
            {
                // Skip padding
                reader.Seek(statusPos - currentPos);
            }

            // Read reply status
            Status = (TunnelBuildReplyStatus)reader.Read8();
        }

        /// <summary>
        /// Parse from byte array
        /// </summary>
        public static LongBuildReplyRecord FromBytes(byte[] data)
        {
            if (data == null || data.Length < UnencryptedRecordSize)
                throw new ArgumentException($"Data too short for long build reply record");

            return new LongBuildReplyRecord(new BufRef(data));
        }

        /// <summary>
        /// Write the unencrypted record to a buffer
        /// </summary>
        public void Write(BufRefStream dest)
        {
            var start = dest.Length;

            // Write options
            Options.Write(dest);

            // Pad to 527 bytes with random data
            var written = (int)(dest.Length - start);
            var paddingSize = (UnencryptedRecordSize - 1) - written; // -1 for reply byte

            if (paddingSize > 0)
            {
                var padding = BufUtils.RandomBytes(paddingSize);
                dest.Write(padding);
            }

            // Write reply status at byte 527
            dest.Write((byte)Status);
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
        /// Encrypt the reply record using ChaCha20 (no authentication for replies)
        /// </summary>
        public byte[] Encrypt(byte[] replyKey, byte[] replyIV)
        {
            if (replyKey == null || replyKey.Length != 32)
                throw new ArgumentException("Reply key must be 32 bytes", nameof(replyKey));

            if (replyIV == null || replyIV.Length < 12)
                throw new ArgumentException("Reply IV must be at least 12 bytes", nameof(replyIV));

            // Get plaintext
            var plaintext = ToByteArray();
            if (plaintext.Length != UnencryptedRecordSize)
                throw new InvalidOperationException($"Plaintext must be exactly {UnencryptedRecordSize} bytes");

            // Encrypt with ChaCha20 (stream cipher, no authentication for replies)
            var cipher = new ChaCha7539Engine();
            var parameters = new ParametersWithIV(new KeyParameter(replyKey), replyIV, 0, 12);
            cipher.Init(true, parameters);

            var ciphertext = new byte[UnencryptedRecordSize];
            cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

            return ciphertext;
        }

        /// <summary>
        /// Decrypt a reply record using ChaCha20
        /// </summary>
        public static LongBuildReplyRecord Decrypt(byte[] ciphertext, byte[] replyKey, byte[] replyIV)
        {
            if (ciphertext == null || ciphertext.Length != EncryptedRecordSize)
                throw new ArgumentException($"Ciphertext must be exactly {EncryptedRecordSize} bytes", nameof(ciphertext));

            if (replyKey == null || replyKey.Length != 32)
                throw new ArgumentException("Reply key must be 32 bytes", nameof(replyKey));

            if (replyIV == null || replyIV.Length < 12)
                throw new ArgumentException("Reply IV must be at least 12 bytes", nameof(replyIV));

            // Decrypt with ChaCha20
            var cipher = new ChaCha7539Engine();
            var parameters = new ParametersWithIV(new KeyParameter(replyKey), replyIV, 0, 12);
            cipher.Init(false, parameters);

            var plaintext = new byte[UnencryptedRecordSize];
            cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, plaintext, 0);

            return FromBytes(plaintext);
        }

        public override string ToString()
        {
            return $"LongBuildReplyRecord: Status={Status}, Options={Options.Mappings.Count} entries";
        }
    }
}
