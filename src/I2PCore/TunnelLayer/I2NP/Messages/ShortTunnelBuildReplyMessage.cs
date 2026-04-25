using System;
using System.Collections.Generic;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

/// <summary>
///     Short Tunnel Build Reply Message (STBRM) - I2NP message type 26
/// </summary>
public class ShortTunnelBuildReplyMessage : I2NpMessage
{
    public const int MaxRecords = 8;
    public const int RecordSize = 218;

    public ShortTunnelBuildReplyMessage(List<byte[]> encryptedRecords)
    {
        if (encryptedRecords == null)
            throw new ArgumentNullException(nameof(encryptedRecords));

        if (encryptedRecords.Count == 0 || encryptedRecords.Count > MaxRecords)
            throw new ArgumentException($"Number of records must be between 1 and {MaxRecords}",
                nameof(encryptedRecords));

        foreach (var record in encryptedRecords)
            if (record.Length != RecordSize)
                throw new ArgumentException($"Each record must be exactly {RecordSize} bytes",
                    nameof(encryptedRecords));

        var totalSize = 1 + encryptedRecords.Count * RecordSize;
        AllocateBuffer(totalSize);

        var writer = new I2PBufferCursor(Payload);
        writer.WriteByte((byte)encryptedRecords.Count);

        Records = new List<I2PByteBlock>(encryptedRecords.Count);
        foreach (var record in encryptedRecords)
        {
            var startBlock = new I2PByteBlock(writer.BaseArray, writer.BaseArrayOffset, RecordSize);
            writer.WriteBytes(record);
            Records.Add(startBlock);
        }
    }

    public ShortTunnelBuildReplyMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);

        var recordCount = reader.ReadByte();
        if (recordCount == 0 || recordCount > MaxRecords)
            throw new InvalidOperationException(
                $"Invalid record count: {recordCount}. Must be between 1 and {MaxRecords}");

        Records = new List<I2PByteBlock>(recordCount);

        for (var i = 0; i < recordCount; i++)
        {
            var record = new I2PByteBlock(reader.BaseArray, reader.BaseArrayOffset, RecordSize);
            reader.Seek(RecordSize);
            Records.Add(record);
        }

        SetBuffer(start, reader);
    }

    public ShortTunnelBuildReplyMessage(List<I2PByteBlock> records)
    {
        if (records == null)
            throw new ArgumentNullException(nameof(records));

        if (records.Count == 0 || records.Count > MaxRecords)
            throw new ArgumentException($"Number of records must be between 1 and {MaxRecords}", nameof(records));

        var totalSize = 1 + records.Count * RecordSize;
        AllocateBuffer(totalSize);

        var writer = new I2PBufferCursor(Payload);
        writer.WriteByte((byte)records.Count);

        Records = new List<I2PByteBlock>(records.Count);
        foreach (var record in records)
        {
            var startBlock = new I2PByteBlock(writer.BaseArray, writer.BaseArrayOffset, RecordSize);
            writer.WriteBlock(record);
            Records.Add(startBlock);
        }
    }

    public override MessageTypes MessageType => MessageTypes.ShortTunnelBuildReply;

    public List<I2PByteBlock> Records { get; set; }

    public I2PByteBlock GetRecord(int index)
    {
        if (index < 0 || index >= Records.Count)
            throw new ArgumentOutOfRangeException(nameof(index));

        return Records[index];
    }

    public void SetRecord(int index, byte[] record)
    {
        if (index < 0 || index >= Records.Count)
            throw new ArgumentOutOfRangeException(nameof(index));

        if (record.Length != RecordSize)
            throw new ArgumentException($"Record must be exactly {RecordSize} bytes", nameof(record));

        Records[index].CopyFrom(new ReadOnlySpan<byte>(record), 0);
    }

    public override string ToString()
    {
        return $"ShortTunnelBuildReply: {Records.Count} records";
    }
}