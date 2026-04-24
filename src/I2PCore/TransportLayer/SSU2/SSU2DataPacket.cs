using System;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TransportLayer.Crypto;
using I2PCore.TransportLayer.SSU2.Messages;

namespace I2PCore.TransportLayer.SSU2
{
    /// <summary>
    /// SSU2 Data Phase Packet
    /// Contains blocks of data encrypted with Noise transport encryption
    /// </summary>
    public class SSU2DataPacket
    {
        public SSU2Header Header { get; set; }
        public List<SSU2BlockWrapper> Blocks { get; set; } = new List<SSU2BlockWrapper>();

        public static SSU2DataPacket BuildWithI2NPMessage(I2NpMessage msg, ulong destConnId, uint packetNum)
        {
            var packet = new SSU2DataPacket
            {
                Header = new SSU2Header
                {
                    IsLongHeader = false,
                    DestinationConnectionId = destConnId,
                    PacketNumber = packetNum  // Already uint now
                }
            };

            // Create I2NP block
            // Get header and payload as a single buffer
            var headerAndPayload = msg.CreateHeader16.HeaderAndPayload;
            var msgBytes = headerAndPayload.ToByteArray();
            var i2npBlock = new SSU2BlockWrapper
            {
                BlockType = SSU2BlockType.I2NP,
                Data = msgBytes
            };
            packet.Blocks.Add(i2npBlock);

            // Add DateTime block
            var timeMs = (uint)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds / 1000);
            var timeBytes = BufUtils.Flip32B(timeMs);

            var timeBlock = new SSU2BlockWrapper
            {
                BlockType = SSU2BlockType.DateTime,
                Data = timeBytes
            };
            packet.Blocks.Add(timeBlock);

            return packet;
        }

        /// <summary>
        /// Build a data packet containing a single block (for control messages like RelayTagRequest).
        /// </summary>
        public static byte[] BuildWithBlock(
            SSU2BlockType blockType, byte[] blockData,
            ulong destConnId, uint packetNum,
            byte[] dataKey, byte[] headerKey2)
        {
            var packet = new SSU2DataPacket
            {
                Header = new SSU2Header
                {
                    IsLongHeader = false,
                    DestinationConnectionId = destConnId,
                    PacketNumber = packetNum
                }
            };

            packet.Blocks.Add(new SSU2BlockWrapper
            {
                BlockType = blockType,
                Data = blockData ?? Array.Empty<byte>()
            });

            return packet.ToByteArray();
        }

        public byte[] ToByteArray()
        {
            var result = new BufLen(new byte[8192]);
            var writer = new BufRefLen(result);

            // Write blocks
            foreach (var block in Blocks)
            {
                writer.Write8((byte)block.BlockType);
                writer.WriteFlip16((ushort)block.Data.Length);
                writer.Write(block.Data);
            }

            return result.BaseArray.Copy(0, writer.BaseArrayOffset);
        }

        public byte[] BuildEncryptedPacket(byte[] dataKey, byte[] headerKey1, byte[] headerKey2)
        {
            var payload = ToByteArray();

            // Build unencrypted header (16 bytes)
            var headerBytes = new byte[16];
            headerBytes[0] = (byte)((Header.DestinationConnectionId >> 56) & 0xFF);
            headerBytes[1] = (byte)((Header.DestinationConnectionId >> 48) & 0xFF);
            headerBytes[2] = 0; // Type field (0 for short header)
            headerBytes[3] = 0; // Version/NetID
            // Packet number at offset 4-7
            var pnBytes = BufUtils.Flip32B(Header.PacketNumber);
            Array.Copy(pnBytes, 0, headerBytes, 4, 4);
            // Rest of header is padding/reserved

            // Encrypt payload with ChaCha20-Poly1305 using header as AD
            // Per spec line 1901: ad = 16 byte header, before header encryption
            var nonce = ChaCha20Poly1305.CreateNonce(Header.PacketNumber);
            var encryptedPayload = ChaCha20Poly1305.Encrypt(dataKey, nonce, payload, headerBytes);

            // Build packet with unencrypted header + encrypted payload
            var packetLen = 16 + encryptedPayload.Length;
            var packet = new byte[packetLen];
            Array.Copy(headerBytes, 0, packet, 0, 16);
            Array.Copy(encryptedPayload, 0, packet, 16, encryptedPayload.Length);

            // Encrypt header in place using two-stage ChaCha20
            SSU2HeaderEncryption.EncryptShortHeaderInPacket(packet, 0, headerKey1, headerKey2);

            return packet;
        }

        public static SSU2DataPacket Parse(byte[] packetData, byte[] dataKey, byte[] headerKey1, byte[] headerKey2)
        {
            var packet = new SSU2DataPacket();

            // Decrypt header in place
            var packetCopy = new byte[packetData.Length];
            Array.Copy(packetData, packetCopy, packetData.Length);
            SSU2HeaderEncryption.DecryptShortHeaderInPacket(packetCopy, 0, headerKey1, headerKey2);

            // Parse short header (now decrypted)
            var reader = new BufRef(packetCopy);
            var connIdHigh = reader.Read8();
            var connIdLow = reader.Read8();
            reader.Seek(2); // Skip type/version
            var packetNum = reader.ReadFlip32();
            reader.Seek(8); // Skip rest of header (total 16 bytes)

            packet.Header = new SSU2Header
            {
                IsLongHeader = false,
                DestinationConnectionId = ((ulong)connIdHigh << 56) | ((ulong)connIdLow << 48),
                PacketNumber = packetNum
            };

            // Build header bytes for AD (use decrypted header)
            var headerBytes = new byte[16];
            Array.Copy(packetCopy, 0, headerBytes, 0, 16);

            // Read encrypted payload (rest of packet after 16-byte header)
            var encryptedPayload = new byte[packetCopy.Length - 16];
            Array.Copy(packetCopy, 16, encryptedPayload, 0, encryptedPayload.Length);

            // Decrypt payload with ChaCha20-Poly1305 using header as AD
            var nonce = ChaCha20Poly1305.CreateNonce(packetNum);
            var decrypted = ChaCha20Poly1305.Decrypt(dataKey, nonce, encryptedPayload, headerBytes);

            if (decrypted == null)
                throw new Exception("Data packet AEAD verification failed");

            // Parse blocks
            var blockReader = new BufRef(decrypted);
            while (blockReader.BaseArrayOffset < decrypted.Length)
            {
                var blockType = (SSU2BlockType)blockReader.Read8();
                var blockLen = blockReader.ReadFlip16();
                var blockData = blockReader.Read(blockLen);

                packet.Blocks.Add(new SSU2BlockWrapper
                {
                    BlockType = blockType,
                    Data = blockData
                });
            }

            return packet;
        }
    }

    // Block types moved to SSU2Blocks.cs - using simple wrapper here for compatibility
    public class SSU2BlockWrapper
    {
        public SSU2BlockType BlockType { get; set; }
        public byte[] Data { get; set; }
    }
}
