using System;
using System.Collections.Generic;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

/// <summary>
///     Short Tunnel Build Message (STBM) - I2NP message type 25
/// </summary>
public class ShortTunnelBuildMessage : I2NpMessage
{
    public const int MaxRecords = 8;
    public const int RecordSize = 218;

    public ShortTunnelBuildMessage()
    {
        Records = new List<I2PByteBlock>();
    }

    public ShortTunnelBuildMessage(List<byte[]> encryptedRecords)
    {
        if (encryptedRecords == null)
            throw new ArgumentNullException(nameof(encryptedRecords));

        if (encryptedRecords.Count < 1 || encryptedRecords.Count > MaxRecords)
            throw new ArgumentException($"Record count must be 1-{MaxRecords}");

        foreach (var record in encryptedRecords)
            if (record == null || record.Length != RecordSize)
                throw new ArgumentException($"Each record must be exactly {RecordSize} bytes");

        var totalSize = 1 + encryptedRecords.Count * RecordSize;
        AllocateBuffer(totalSize);

        var writer = new I2PBufferCursor(Payload);
        writer.WriteByte((byte)encryptedRecords.Count);

        Records = new List<I2PByteBlock>(encryptedRecords.Count);
        for (var i = 0; i < encryptedRecords.Count; i++)
        {
            var startBlock = new I2PByteBlock(writer.BaseArray, writer.BaseArrayOffset, RecordSize);
            writer.WriteBytes(encryptedRecords[i]);
            Records.Add(startBlock);
        }
    }

    public ShortTunnelBuildMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);

        var recordCount = reader.ReadByte();

        if (recordCount < 1 || recordCount > MaxRecords)
            throw new InvalidOperationException($"Invalid record count: {recordCount}");

        Records = new List<I2PByteBlock>(recordCount);

        for (var i = 0; i < recordCount; i++)
        {
            var record = new I2PByteBlock(reader.BaseArray, reader.BaseArrayOffset, RecordSize);
            reader.Seek(RecordSize);
            Records.Add(record);
        }

        SetBuffer(start, reader);
    }

    public ShortTunnelBuildMessage(List<I2PByteBlock> records)
    {
        if (records == null)
            throw new ArgumentNullException(nameof(records));

        if (records.Count < 1 || records.Count > MaxRecords)
            throw new ArgumentException($"Record count must be 1-{MaxRecords}");

        var totalSize = 1 + records.Count * RecordSize;
        AllocateBuffer(totalSize);

        var writer = new I2PBufferCursor(Payload);
        writer.WriteByte((byte)records.Count);

        Records = new List<I2PByteBlock>(records.Count);
        for (var i = 0; i < records.Count; i++)
        {
            var startBlock = new I2PByteBlock(writer.BaseArray, writer.BaseArrayOffset, RecordSize);
            writer.WriteBlock(records[i]);
            Records.Add(startBlock);
        }
    }

    public override MessageTypes MessageType => MessageTypes.ShortTunnelBuild;

    public List<I2PByteBlock> Records { get; set; }

    public int RecordCount => Records.Count;

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

        if (record == null || record.Length != RecordSize)
            throw new ArgumentException($"Record must be exactly {RecordSize} bytes");

        Records[index].CopyFrom(new ReadOnlySpan<byte>(record), 0);
    }

    public override string ToString()
    {
        return $"ShortTunnelBuildMessage: {Records.Count} records ({Records.Count * RecordSize} bytes)";
    }
}