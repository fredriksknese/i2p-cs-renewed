using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages;

/// <summary>
///     SSU2 Session Confirmed (Handshake Message 3)
///     Noise XK pattern: -> s, se
///     SSU2 spec lines 1632-1871:
///     - SHORT header (16 bytes) - NOT long header!
///     - Packet number = 0 always
///     - Encrypted static key S (48 bytes: 32 key + 16 MAC) - Part 1
///     - Encrypted RouterInfo blocks (variable) - Part 2
///     - May be fragmented across multiple packets if RouterInfo is large
/// </summary>
public class SessionConfirmed
{
    public SessionConfirmed()
    {
        Header = new SSU2Header
        {
            IsLongHeader = false, // SHORT header per spec lines 1676-1680
            Type = SSU2Header.TYPE_SESSION_CONFIRMED,
            PacketNumber = 0 // Always 0 per spec line 1702
        };
    }

    public SSU2Header Header { get; set; }
    public byte[] StaticKey { get; set; } // Alice's static key, 32 bytes
    public byte[] EncryptedStaticKey { get; set; } // Part 1: 48 bytes (32 + 16 MAC)
    public byte[] EncryptedPayload { get; set; } // Part 2: variable
    public I2PRouterInfo RouterInfo { get; set; }
    public byte[] Padding { get; set; }

    // Fragmentation support
    public byte FragmentNumber { get; set; }
    public byte TotalFragments { get; set; }

    public static SessionConfirmed Parse(I2PBufferCursor data)
    {
        var confirmed = new SessionConfirmed();

        // Parse SHORT header (16 bytes) - SSU2 spec lines 1676-1680
        confirmed.Header = SSU2Header.ParseShortHeader(data);

        // Read encrypted static key frame (48 bytes: 32 key + 16 MAC)
        confirmed.EncryptedStaticKey = data.ReadBlock(48).ToByteArray();

        // Read encrypted payload frame (rest of packet)
        var remaining = data.Remaining;
        confirmed.EncryptedPayload = data.ReadBlock(remaining).ToByteArray();

        return confirmed;
    }

    public byte[] ToByteArray(byte[] encryptedPart1, byte[] encryptedPart2)
    {
        var result = new I2PByteBlock(new byte[4096]);
        var writer = new I2PBufferCursor(result);

        // Write header
        writer.WriteBytes(Header.ToByteArray());

        // Write encrypted static key (Part 1 from Noise)
        writer.WriteBytes(encryptedPart1);

        // Write encrypted payload (Part 2 from Noise)
        writer.WriteBytes(encryptedPart2);

        return result.ToByteArray();
    }

    public byte[] BuildPart2Payload()
    {
        // Build Part 2 payload: RouterInfo block + optional padding block
        var result = new I2PByteBlock(new byte[4096]);
        var writer = new I2PBufferCursor(result);

        // Write RouterInfo block (SSU2 spec lines 2697-2777)
        if (RouterInfo != null)
        {
            // Serialize RouterInfo
            var riStream = new ArrayBufferWriter<byte>();
            RouterInfo.Write(riStream);
            var riBytes = riStream.WrittenSpan.ToArray();

            // Try gzip compression if it would save space (spec lines 2741-2750)
            // Compression recommended if it allows fitting in single packet
            byte flags = 0; // bit 0 = flood (0 = local store), bit 1 = gzipped
            var finalRiBytes = riBytes;

            if (riBytes.Length > 1000) // Only compress if large enough to benefit
                try
                {
                    var compressedBuf = LzUtils.BcgZipCompressNew(new I2PByteBlock(riBytes));
                    var compressed = compressedBuf.ToByteArray();
                    if (compressed.Length < riBytes.Length)
                    {
                        finalRiBytes = compressed;
                        flags = 0x02; // Set gzip flag (bit 1)
                        Logging.LogDebug(
                            $"SessionConfirmed: Compressed RouterInfo from {riBytes.Length} to {compressed.Length} bytes");
                    }
                }
                catch (Exception ex)
                {
                    // Falling back to the uncompressed RouterInfo is always wire-valid, so this
                    // is recoverable — but it is not expected, and it is not free: compression is
                    // what keeps a large RouterInfo inside one packet. A handshake that starts
                    // failing on oversized SessionConfirmed would otherwise show no cause here.
                    Logging.LogWarning(
                        $"SessionConfirmed: RouterInfo compression failed, sending "
                        + $"{riBytes.Length} bytes uncompressed: {ex}");
                }

            // RouterInfo block header:
            // - Block type (1 byte): 2
            // - Size (2 bytes): 2 + fragment size
            // - Flags (1 byte): bit 0 = flood, bit 1 = gzipped
            // - Frag (1 byte): always 0x01 (fragment 0, total 1)

            writer.WriteByte(2); // Block type = RouterInfo
            writer.WriteUInt16BigEndian((ushort)(2 + finalRiBytes.Length)); // Size = 2 + RI data
            writer.WriteByte(flags); // Flags: bit 1 = gzipped if compressed
            writer.WriteByte(0x01); // Frag: 0x01 = fragment 0 of 1
            writer.WriteBytes(finalRiBytes); // RouterInfo data (compressed or not)
        }

        // Add padding block if specified (SSU2 spec lines 2650-2664)
        if (Padding != null && Padding.Length > 0)
        {
            writer.WriteByte(254); // Block type = Padding
            writer.WriteUInt16BigEndian((ushort)Padding.Length);
            writer.WriteBytes(Padding);
        }

        return result.ToByteArray();
    }

    public void ParsePart2Payload(byte[] payload)
    {
        // Parse decrypted Part 2 payload - contains blocks
        var reader = new I2PBufferCursor(payload);

        while (reader.Remaining > 0)
        {
            var remaining = reader.Remaining;
            if (remaining < 3)
                // Not enough data for block header
                break;

            var blockType = reader.ReadByte();
            var blockSize = reader.ReadUInt16BigEndian();

            if (blockSize > remaining - 3)
                throw new Exception($"Invalid block size: {blockSize} exceeds remaining data {remaining - 3}");

            switch (blockType)
            {
                case 2: // RouterInfo block
                    // Declared outside the try so the catch below can report whether we thought
                    // the block was compressed — the first thing worth knowing when it fails.
                    byte flags = 0;

                    try
                    {
                        // Parse flags and frag
                        flags = reader.ReadByte();
                        var frag = reader.ReadByte();

                        // Read RouterInfo data (blockSize - 2 for flags/frag)
                        var riData = reader.ReadBlock(blockSize - 2);

                        // Check if gzipped (flag bit 1)
                        var isGzipped = (flags & 0x02) != 0;

                        if (isGzipped)
                        {
                            // Decompress with gzip (spec lines 2741-2750)
                            var compressedData = riData.ToByteArray();
                            var decompressedData = LzUtils.BcgZipDecompressNew(new I2PByteBlock(compressedData));

                            // Parse decompressed RouterInfo
                            var riReader = new I2PBufferCursor(decompressedData);
                            RouterInfo = new I2PRouterInfo(riReader, false);
                        }
                        else
                        {
                            // Parse RouterInfo from block data
                            var riReader = new I2PBufferCursor(riData.ToByteArray());
                            RouterInfo = new I2PRouterInfo(riReader, false);
                        }
                    }
                    catch (Exception ex)
                    {
                        // RouterInfo stays null and the handshake carries on without ever
                        // learning who the peer is. At Debug that reads downstream as "the peer
                        // never sent one" rather than "we could not read the one it sent" —
                        // which is exactly the ambiguity the integration suite's missing-peer
                        // RouterInfo failure leaves open.
                        Logging.LogWarning(
                            $"SessionConfirmed: failed to parse the peer's RouterInfo block "
                            + $"(gzipped={(flags & 0x02) != 0}, {blockSize - 2} bytes): {ex}");
                    }

                    break;

                case 254: // Padding block
                    Padding = reader.ReadBlock(blockSize).ToByteArray();
                    break;

                default:
                    // Unknown block type - skip
                    reader.ReadBlock(blockSize);
                    Logging.LogDebug($"SessionConfirmed: Unknown block type {blockType}, skipping {blockSize} bytes");
                    break;
            }
        }
    }
}