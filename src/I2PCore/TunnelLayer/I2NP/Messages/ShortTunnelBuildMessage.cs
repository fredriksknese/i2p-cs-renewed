using System;
using System.Collections.Generic;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    /// <summary>
    /// Short Tunnel Build Message (STBM) - I2NP message type 25
    /// Contains Short Build Request Records for ECIES-only tunnels
    /// 
    /// Format:
    /// - 1 byte: number of records (1-8)
    /// - N records: each 218 bytes (encrypted)
    /// 
    /// Total size: 1 + (N * 218) bytes
    /// Supported as of 0.9.51
    /// </summary>
    public class ShortTunnelBuildMessage : I2NpMessage
    {
        public override MessageTypes MessageType => MessageTypes.ShortTunnelBuild;

        public const int MaxRecords = 8;
        public const int RecordSize = 218; // Encrypted short record size

        public List<BufLen> Records { get; set; }

        /// <summary>
        /// Create an empty STBM
        /// </summary>
        public ShortTunnelBuildMessage()
        {
            Records = new List<BufLen>();
        }

        /// <summary>
        /// Create STBM with encrypted records
        /// </summary>
        /// <param name="encryptedRecords">List of encrypted reply records (each 218 bytes)</param>
        public ShortTunnelBuildMessage(List<byte[]> encryptedRecords)
        {
            if (encryptedRecords == null)
                throw new ArgumentNullException(nameof(encryptedRecords));
            
            if (encryptedRecords.Count < 1 || encryptedRecords.Count > MaxRecords)
                throw new ArgumentException($"Record count must be 1-{MaxRecords}");

            foreach (var record in encryptedRecords)
            {
                if (record == null || record.Length != RecordSize)
                    throw new ArgumentException($"Each record must be exactly {RecordSize} bytes");
            }

            // Allocate buffer for the message
            var totalSize = 1 + (encryptedRecords.Count * RecordSize);
            AllocateBuffer(totalSize);
            
            var writer = new BufRefLen(Payload);
            writer.Write8((byte)encryptedRecords.Count);
            
            Records = new List<BufLen>(encryptedRecords.Count);
            for (int i = 0; i < encryptedRecords.Count; i++)
            {
                var start = new BufRefLen(writer);
                writer.Write(encryptedRecords[i]);
                Records.Add(new BufLen(start, 0, RecordSize));
            }
        }

        /// <summary>
        /// Parse STBM from buffer
        /// </summary>
        public ShortTunnelBuildMessage(BufRef reader)
        {
            var start = new BufRef(reader);
            
            var recordCount = reader.Read8();
            
            if (recordCount < 1 || recordCount > MaxRecords)
                throw new InvalidOperationException($"Invalid record count: {recordCount}");

            Records = new List<BufLen>(recordCount);
            
            for (int i = 0; i < recordCount; i++)
            {
                var record = new BufLen(reader, 0, RecordSize);
                reader.Read(RecordSize);
                Records.Add(record);
            }

            SetBuffer(start, reader);
        }

        public ShortTunnelBuildMessage(List<BufLen> records)
        {
            if (records == null)
                throw new ArgumentNullException(nameof(records));

            if (records.Count < 1 || records.Count > MaxRecords)
                throw new ArgumentException($"Record count must be 1-{MaxRecords}");

            // Allocate buffer for the message
            var totalSize = 1 + (records.Count * RecordSize);
            AllocateBuffer(totalSize);

            var writer = new BufRefLen(Payload);
            writer.Write8((byte)records.Count);

            Records = new List<BufLen>(records.Count);
            for (int i = 0; i < records.Count; i++)
            {
                var start = new BufRefLen(writer);
                writer.Write(records[i]);
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
        /// Replace a record at a specific index (for reply processing)
        /// </summary>
        public void SetRecord(int index, byte[] record)
        {
            if (index < 0 || index >= Records.Count)
                throw new ArgumentOutOfRangeException(nameof(index));
            
            if (record == null || record.Length != RecordSize)
                throw new ArgumentException($"Record must be exactly {RecordSize} bytes");

            var dest = (BufRefLen)Records[index];
            dest.Write(record);
        }

        /// <summary>
        /// Get the number of records
        /// </summary>
        public int RecordCount => Records.Count;

        public override string ToString()
        {
            return $"ShortTunnelBuildMessage: {Records.Count} records ({Records.Count * RecordSize} bytes)";
        }
    }
}
