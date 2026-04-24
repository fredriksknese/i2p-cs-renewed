using System;
using System.Collections.Generic;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    /// <summary>
    /// Short Tunnel Build Reply Message (STBRM)
    /// I2NP message type 26
    /// Contains encrypted build replies from each hop in the tunnel
    /// </summary>
    public class ShortTunnelBuildReplyMessage : I2NpMessage
    {
        public override MessageTypes MessageType => MessageTypes.ShortTunnelBuildReply;

        /// <summary>
        /// Maximum number of records (hops) in a tunnel
        /// </summary>
        public const int MaxRecords = 8;

        /// <summary>
        /// Size of each reply record in bytes (same as request: 218 bytes)
        /// Reply records are ChaCha20-encrypted (stream cipher, no separate MAC)
        /// </summary>
        public const int RecordSize = 218;

        /// <summary>
        /// Encrypted reply records from each hop
        /// Each record is 217 bytes (201 plaintext + 16 MAC)
        /// </summary>
        public List<BufLen> Records { get; set; }

        /// <summary>
        /// Create a new ShortTunnelBuildReplyMessage with encrypted records
        /// </summary>
        /// <param name="encryptedRecords">List of encrypted reply records (each 218 bytes)</param>
        public ShortTunnelBuildReplyMessage(List<byte[]> encryptedRecords)
        {
            if (encryptedRecords == null)
                throw new ArgumentNullException(nameof(encryptedRecords));

            if (encryptedRecords.Count == 0 || encryptedRecords.Count > MaxRecords)
                throw new ArgumentException($"Number of records must be between 1 and {MaxRecords}", nameof(encryptedRecords));

            foreach (var record in encryptedRecords)
            {
                if (record.Length != RecordSize)
                    throw new ArgumentException($"Each record must be exactly {RecordSize} bytes", nameof(encryptedRecords));
            }

            // Calculate total size: 1 byte count + N * 218 bytes records
            var totalSize = 1 + (encryptedRecords.Count * RecordSize);
            AllocateBuffer(totalSize);

            var writer = new BufRefLen(Payload);
            writer.Write8((byte)encryptedRecords.Count);

            Records = new List<BufLen>(encryptedRecords.Count);
            foreach (var record in encryptedRecords)
            {
                var start = new BufRefLen(writer);
                writer.Write(record);
                Records.Add(new BufLen(start, 0, RecordSize));
            }
        }

        /// <summary>
        /// Parse a ShortTunnelBuildReplyMessage from the network
        /// </summary>
        public ShortTunnelBuildReplyMessage(BufRef reader)
        {
            var start = new BufRef(reader);

            var recordCount = reader.Read8();
            if (recordCount == 0 || recordCount > MaxRecords)
                throw new InvalidOperationException($"Invalid record count: {recordCount}. Must be between 1 and {MaxRecords}");

            Records = new List<BufLen>(recordCount);

            for (int i = 0; i < recordCount; i++)
            {
                var record = new BufLen(reader, 0, RecordSize);
                reader.Read(RecordSize);
                Records.Add(record);
            }

            SetBuffer(start, reader);
        }

        public ShortTunnelBuildReplyMessage(List<BufLen> records)
        {
            if (records == null)
                throw new ArgumentNullException(nameof(records));

            if (records.Count == 0 || records.Count > MaxRecords)
                throw new ArgumentException($"Number of records must be between 1 and {MaxRecords}", nameof(records));

            // Calculate total size: 1 byte count + N * 218 bytes records
            var totalSize = 1 + (records.Count * RecordSize);
            AllocateBuffer(totalSize);

            var writer = new BufRefLen(Payload);
            writer.Write8((byte)records.Count);

            Records = new List<BufLen>(records.Count);
            foreach (var record in records)
            {
                var start = new BufRefLen(writer);
                writer.Write(record);
                Records.Add(new BufLen(start, 0, RecordSize));
            }
        }
        public BufLen GetRecord(int index)
        {
            if (index < 0 || index >= Records.Count)
                throw new ArgumentOutOfRangeException(nameof(index));

            return Records[index];
        }

        /// <summary>
        /// Set encrypted reply record at the specified index
        /// </summary>
        public void SetRecord(int index, byte[] record)
        {
            if (index < 0 || index >= Records.Count)
                throw new ArgumentOutOfRangeException(nameof(index));

            if (record.Length != RecordSize)
                throw new ArgumentException($"Record must be exactly {RecordSize} bytes", nameof(record));

            var dest = (BufRefLen)Records[index];
            dest.Write(record);
        }

        public override string ToString()
        {
            return $"ShortTunnelBuildReply: {Records.Count} records";
        }
    }
}
