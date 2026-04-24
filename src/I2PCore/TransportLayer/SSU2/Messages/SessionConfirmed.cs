using System;
using System.IO;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages
{
    /// <summary>
    /// SSU2 Session Confirmed (Handshake Message 3)
    ///
    /// Noise XK pattern: -> s, se
    ///
    /// SSU2 spec lines 1632-1871:
    /// - SHORT header (16 bytes) - NOT long header!
    /// - Packet number = 0 always
    /// - Encrypted static key S (48 bytes: 32 key + 16 MAC) - Part 1
    /// - Encrypted RouterInfo blocks (variable) - Part 2
    /// - May be fragmented across multiple packets if RouterInfo is large
    /// </summary>
    public class SessionConfirmed
    {
        public SSU2Header Header { get; set; }
        public byte[] StaticKey { get; set; }  // Alice's static key, 32 bytes
        public byte[] EncryptedStaticKey { get; set; }  // Part 1: 48 bytes (32 + 16 MAC)
        public byte[] EncryptedPayload { get; set; }  // Part 2: variable
        public I2PRouterInfo RouterInfo { get; set; }
        public byte[] Padding { get; set; }

        // Fragmentation support
        public byte FragmentNumber { get; set; }
        public byte TotalFragments { get; set; }

        public SessionConfirmed()
        {
            Header = new SSU2Header
            {
                IsLongHeader = false,  // SHORT header per spec lines 1676-1680
                Type = SSU2Header.TYPE_SESSION_CONFIRMED,
                PacketNumber = 0  // Always 0 per spec line 1702
            };
        }

        public static SessionConfirmed Parse(BufRef data)
        {
            var confirmed = new SessionConfirmed();

            // Parse SHORT header (16 bytes) - SSU2 spec lines 1676-1680
            confirmed.Header = SSU2Header.ParseShortHeader(data);

            // Read encrypted static key frame (48 bytes: 32 key + 16 MAC)
            confirmed.EncryptedStaticKey = data.ReadBufLen(48).ToByteArray();

            // Read encrypted payload frame (rest of packet)
            var remaining = data.BaseArray.Length - data.BaseArrayOffset;
            confirmed.EncryptedPayload = data.ReadBufLen(remaining).ToByteArray();

            return confirmed;
        }

        public byte[] ToByteArray(byte[] encryptedPart1, byte[] encryptedPart2)
        {
            var result = new BufLen(new byte[4096]);
            var writer = new BufRefLen(result);

            // Write header
            writer.Write(Header.ToByteArray());

            // Write encrypted static key (Part 1 from Noise)
            writer.Write(encryptedPart1);

            // Write encrypted payload (Part 2 from Noise)
            writer.Write(encryptedPart2);

            return result.ToByteArray();
        }

        public byte[] BuildPart2Payload()
        {
            // Build Part 2 payload: RouterInfo block + optional padding block
            var result = new BufLen(new byte[4096]);
            var writer = new BufRefLen(result);

            // Write RouterInfo block (SSU2 spec lines 2697-2777)
            if (RouterInfo != null)
            {
                // Serialize RouterInfo
                var riStream = new BufRefStream();
                RouterInfo.Write(riStream);
                var riBytes = riStream.ToArray();

                // Try gzip compression if it would save space (spec lines 2741-2750)
                // Compression recommended if it allows fitting in single packet
                byte flags = 0; // bit 0 = flood (0 = local store), bit 1 = gzipped
                byte[] finalRiBytes = riBytes;

                if (riBytes.Length > 1000) // Only compress if large enough to benefit
                {
                    try
                    {
                        var compressedBuf = LzUtils.BcgZipCompressNew(new BufLen(riBytes));
                        var compressed = compressedBuf.ToByteArray();
                        if (compressed.Length < riBytes.Length)
                        {
                            finalRiBytes = compressed;
                            flags = 0x02; // Set gzip flag (bit 1)
                            Logging.LogDebug($"SessionConfirmed: Compressed RouterInfo from {riBytes.Length} to {compressed.Length} bytes");
                        }
                    }
                    catch
                    {
                        // Compression failed, use uncompressed
                    }
                }

                // RouterInfo block header:
                // - Block type (1 byte): 2
                // - Size (2 bytes): 2 + fragment size
                // - Flags (1 byte): bit 0 = flood, bit 1 = gzipped
                // - Frag (1 byte): always 0x01 (fragment 0, total 1)

                writer.Write8(2);  // Block type = RouterInfo
                writer.WriteFlip16((ushort)(2 + finalRiBytes.Length));  // Size = 2 + RI data
                writer.Write8(flags);  // Flags: bit 1 = gzipped if compressed
                writer.Write8(0x01);  // Frag: 0x01 = fragment 0 of 1
                writer.Write(finalRiBytes);  // RouterInfo data (compressed or not)
            }

            // Add padding block if specified (SSU2 spec lines 2650-2664)
            if (Padding != null && Padding.Length > 0)
            {
                writer.Write8(254);  // Block type = Padding
                writer.WriteFlip16((ushort)Padding.Length);
                writer.Write(Padding);
            }

            return result.ToByteArray();
        }

        public void ParsePart2Payload(byte[] payload)
        {
            // Parse decrypted Part 2 payload - contains blocks
            var reader = new BufRef(payload);

            while (reader.BaseArrayOffset < payload.Length)
            {
                int remaining = payload.Length - reader.BaseArrayOffset;
                if (remaining < 3)
                {
                    // Not enough data for block header
                    break;
                }

                byte blockType = reader.Read8();
                ushort blockSize = reader.ReadFlip16();

                if (blockSize > remaining - 3)
                {
                    throw new Exception($"Invalid block size: {blockSize} exceeds remaining data {remaining - 3}");
                }

                switch (blockType)
                {
                    case 2:  // RouterInfo block
                        try
                        {
                            // Parse flags and frag
                            byte flags = reader.Read8();
                            byte frag = reader.Read8();

                            // Read RouterInfo data (blockSize - 2 for flags/frag)
                            var riData = reader.ReadBufLen(blockSize - 2);

                            // Check if gzipped (flag bit 1)
                            bool isGzipped = (flags & 0x02) != 0;

                            if (isGzipped)
                            {
                                // Decompress with gzip (spec lines 2741-2750)
                                var compressedData = riData.ToByteArray();
                                var decompressedData = LzUtils.BcgZipDecompressNew(new BufLen(compressedData));

                                // Parse decompressed RouterInfo
                                var riReader = new BufRef(decompressedData);
                                RouterInfo = new I2PRouterInfo(riReader, false);
                            }
                            else
                            {
                                // Convert BufLen to BufRef for I2PRouterInfo constructor
                                var riReader = new BufRef(riData.ToByteArray());
                                RouterInfo = new I2PRouterInfo(riReader, false);
                            }
                        }
                        catch (Exception ex)
                        {
                            Logging.LogDebug($"SessionConfirmed: Failed to parse RouterInfo block: {ex.Message}");
                        }
                        break;

                    case 254:  // Padding block
                        Padding = reader.ReadBufLen(blockSize).ToByteArray();
                        break;

                    default:
                        // Unknown block type - skip
                        reader.ReadBufLen(blockSize);
                        Logging.LogDebug($"SessionConfirmed: Unknown block type {blockType}, skipping {blockSize} bytes");
                        break;
                }
            }
        }
    }
}
