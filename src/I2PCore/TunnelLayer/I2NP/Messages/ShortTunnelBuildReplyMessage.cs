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
        public List<byte[]> Records { get; set; }

        /// <summary>
        /// Create a new ShortTunnelBuildReplyMessage with encrypted records
        /// </summary>
        /// <param name="encryptedRecords">List of encrypted reply records (each 217 bytes)</param>
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

            Records = new List<byte[]>(encryptedRecords);

            // Calculate total size: 1 byte count + N * 217 bytes records
            var totalSize = 1 + (Records.Count * RecordSize);
            AllocateBuffer(totalSize);

            var writer = new BufRefLen(Payload);
            writer.Write8((byte)Records.Count);

            foreach (var record in Records)
            {
                writer.Write(record);
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

            Records = new List<byte[]>(recordCount);

            for (int i = 0; i < recordCount; i++)
            {
                var record = reader.Read(RecordSize);
                Records.Add(record);
            }

            SetBuffer(start, reader);
        }

        /// <summary>
        /// Get encrypted reply record at the specified index
        /// </summary>
        public byte[] GetRecord(int index)
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

            Records[index] = record;

            // Update the payload buffer
            var writer = new BufRefLen(Payload);
            writer.Seek(1 + (index * RecordSize)); // Skip count byte and previous records
            writer.Write(record);
        }

        public override string ToString()
        {
            return $"ShortTunnelBuildReply: {Records.Count} records";
        }
    }
}
