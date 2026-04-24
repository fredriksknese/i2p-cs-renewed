using System;
using System.Collections.Generic;
using System.Net;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP;
using I2PCore.TransportLayer.Crypto;

namespace I2PCore.TransportLayer.NTCP2
{
    /// <summary>
    /// NTCP2 Data Phase Frame
    /// Contains blocks of data with SipHash length obfuscation
    /// </summary>
    public class NTCP2DataFrame
    {
        public ushort Length { get; set; }
        public List<NTCP2BlockWrapper> Blocks { get; set; } = new List<NTCP2BlockWrapper>();

        public static NTCP2DataFrame BuildWithI2NPMessage(I2NpMessage msg, bool isFirstFrame = false)
        {
            var frame = new NTCP2DataFrame();

            if (isFirstFrame)
            {
                frame.AddBlock(new NTCP2DateTimeBlock());
            }

            // Create I2NP block (Type 3)
            var i2npBlock = new NTCP2I2NPBlock
            {
                MessageType = (byte)msg.MessageType,
                MessageId = msg.MessageId,
                Expiration = (uint)((ulong)msg.Expiration / 1000), // ms to seconds
                Message = msg.Payload.ToByteArray()
            };
            
            frame.AddBlock(i2npBlock);

            return frame;
        }

        public static NTCP2DataFrame BuildWithRouterInfo(I2PRouterInfo ri, bool includeDateTime = true)
        {
            var frame = new NTCP2DataFrame();

            if (includeDateTime)
            {
                frame.AddBlock(new NTCP2DateTimeBlock());
            }

            // RouterInfo block (Type 2)
            var riBlock = new NTCP2RouterInfoBlock { RouterInfo = ri, Flags = 0 };
            frame.AddBlock(riBlock);

            return frame;
        }

        public void AddBlock(NTCP2Block block)
        {
            Blocks.Add(new NTCP2BlockWrapper
            {
                BlockType = block.BlockType,
                Data = block.Serialize()
            });
        }

        public byte[] ToByteArray()
        {
            // Max unencrypted data in a ChaChaPoly frame is 65535 - 16 = 65519 bytes
            var result = new BufLen(new byte[65519]);
            var writer = new BufRefLen(result);

            // Write blocks
            foreach (var block in Blocks)
            {
                if (3 + block.Data.Length > writer.Length)
                {
                    // Block too large for current frame.
                    // Should be handled by splitting/multiple frames.
                    // For now we just log a warning.
                    I2PCore.Utils.Logging.LogWarning($"NTCP2DataFrame: Block of size {block.Data.Length} cannot fit in remaining {writer.Length} bytes.");
                    break;
                }

                writer.Write8((byte)block.BlockType);
                writer.WriteFlip16((ushort)block.Data.Length);
                writer.Write(block.Data);
            }

            var len = writer.BaseArrayOffset - result.BaseArrayOffset;
            return result.BaseArray.Copy(result.BaseArrayOffset, len);
        }

        public byte[] BuildEncryptedFrame(NoiseXK noiseState, NTCP2SipHash sipHash)
        {
            var payload = ToByteArray();
            var encrypted = noiseState.EncryptData(payload);

            ushort frameLength = (ushort)encrypted.Length;
            Length = frameLength;

            // Obfuscate length with SipHash
            var obfuscatedLength = sipHash.ObfuscateLength(frameLength);

            I2PCore.Utils.Logging.LogDebug($"NTCP2DataFrame: plaintext={payload.Length}B, encrypted={encrypted.Length}B, frameLen={frameLength}, obfLen=0x{obfuscatedLength:X4}");

            var result = new BufLen(new byte[65535 + 2 + 16]); // Max frame + len + MAC
            var writer = new BufRefLen(result);

            writer.WriteFlip16(obfuscatedLength);
            writer.Write(encrypted);

            var len = writer.BaseArrayOffset - result.BaseArrayOffset;
            return result.BaseArray.Copy(result.BaseArrayOffset, len);
        }

        public static NTCP2DataFrame Parse(BufRef reader, NoiseXK noiseState, ushort frameLength)
        {
            var frame = new NTCP2DataFrame();
            frame.Length = frameLength;

            // Read encrypted payload
            var encryptedPayload = reader.Read(frameLength);

            // Decrypt
            var decrypted = noiseState.DecryptData(encryptedPayload);

            if (decrypted == null)
                throw new Exception("AEAD decryption failed");

            // Parse blocks with ordering validation
            ParseAndValidateBlocks(decrypted, frame);

            return frame;
        }

        /// <summary>
        /// Parse blocks and validate ordering
        /// NTCP2 spec lines 1345-1360:
        /// - Padding must be last
        /// - Termination must be last (except for Padding)
        /// - Multiple Padding blocks not allowed in single frame
        /// </summary>
        private static void ParseAndValidateBlocks(byte[] decrypted, NTCP2DataFrame frame)
        {
            var blockReader = new BufRef(decrypted);
            bool paddingSeen = false;
            bool terminationSeen = false;

            while (blockReader.BaseArrayOffset < decrypted.Length)
            {
                int remaining = decrypted.Length - blockReader.BaseArrayOffset;
                if (remaining < 3)
                    throw new Exception("Invalid block: insufficient data for header");

                var blockType = (NTCP2BlockType)blockReader.Read8();
                var blockLen = blockReader.ReadFlip16();

                remaining = decrypted.Length - blockReader.BaseArrayOffset;
                if (remaining < blockLen)
                    throw new Exception($"Invalid block: size {blockLen} exceeds remaining data");

                // Validate ordering constraints
                if (paddingSeen)
                    throw new Exception("Padding block must be last - found block after Padding");

                if (terminationSeen && blockType != NTCP2BlockType.Padding)
                    throw new Exception("Only Padding allowed after Termination block");

                var blockData = blockReader.Read(blockLen);

                frame.Blocks.Add(new NTCP2BlockWrapper
                {
                    BlockType = blockType,
                    Data = blockData
                });

                // Track special blocks
                if (blockType == NTCP2BlockType.Padding)
                {
                    if (paddingSeen)
                        throw new Exception("Multiple Padding blocks not allowed in single frame");
                    paddingSeen = true;
                }
                else if (blockType == NTCP2BlockType.Termination)
                {
                    if (terminationSeen)
                        throw new Exception("Multiple Termination blocks not allowed");
                    terminationSeen = true;
                }
            }
        }
    }

    public class NTCP2BlockWrapper
    {
        public NTCP2BlockType BlockType { get; set; }
        public byte[] Data { get; set; }

        public Ii2NpHeader ParseAsI2NPHeader()
        {
            var reader = new BufRefLen(Data);
            
            // Standard NTCP2 I2NP block (Type 3) has 9 bytes header:
            // MessageType(1), MessageID(4), Expiration(4)
            var msgType = (I2NpMessage.MessageTypes)reader.Read8();
            var msgId = reader.ReadFlip32();
            var expirationSeconds = reader.ReadFlip32();
            var expiration = new I2PDate(expirationSeconds * 1000UL); // seconds to ms

            // Remaining data is the message payload.
            // I2NP message objects expect 16 bytes of padding BEFORE the payload
            // to store their I2NPHeader16, so we must copy it to a new buffer.
            var payloadLen = reader.Length;
            var newBuf = new byte[payloadLen + I2NpMessage.I2NpMaxHeaderSize];
            Array.Copy(Data, Data.Length - payloadLen, newBuf, I2NpMessage.I2NpMaxHeaderSize, payloadLen);
            
            var payload = new BufRefLen(new BufLen(newBuf, I2NpMessage.I2NpMaxHeaderSize, payloadLen));

            // Construct the actual message object from payload
            var msg = I2NpUtil.GetMessage(msgType, payload, msgId);
            if (msg == null) return null;
            
            msg.Expiration = expiration;

            // Return a 16-byte header wrapper for system compatibility
            return msg.CreateHeader16;
        }
    }
}
