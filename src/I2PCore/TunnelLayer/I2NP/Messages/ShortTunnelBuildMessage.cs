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

        public List<byte[]> Records { get; set; }

        /// <summary>
        /// Create an empty STBM
        /// </summary>
        public ShortTunnelBuildMessage()
        {
            Records = new List<byte[]>();
        }

        /// <summary>
        /// Create STBM with encrypted records
        /// </summary>
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

            Records = new List<byte[]>(encryptedRecords);
            
            // Allocate buffer for the message
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
        /// Parse STBM from buffer
        /// </summary>
        public ShortTunnelBuildMessage(BufRef reader)
        {
            var start = new BufRef(reader);
            
            var recordCount = reader.Read8();
            
            if (recordCount < 1 || recordCount > MaxRecords)
                throw new InvalidOperationException($"Invalid record count: {recordCount}");

            Records = new List<byte[]>(recordCount);
            
            for (int i = 0; i < recordCount; i++)
            {
                var record = new byte[RecordSize];
                reader.Read(record, 0, RecordSize);
                Records.Add(record);
            }

            SetBuffer(start, reader);
        }

        /// <summary>
        /// Get the record at a specific index
        /// </summary>
        public byte[] GetRecord(int index)
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

            Records[index] = record;
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
