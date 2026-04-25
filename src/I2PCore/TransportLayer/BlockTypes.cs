using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TransportLayer
{
    /// <summary>
    /// Block types used in NTCP2 and SSU2 data frames
    /// </summary>
    public enum BlockType : byte
    {
        DateTime = 0,
        Options = 1,
        RouterInfo = 2,
        I2NP = 3,
        Termination = 4,
        Padding = 254
    }

    /// <summary>
    /// Represents a generic block in NTCP2/SSU2
    /// Format: Type (1 byte) | Length (2 bytes) | Data (variable)
    /// </summary>
    public class Block
    {
        public BlockType Type { get; set; }
        public ushort Length { get; set; }
        public byte[] Data { get; set; }

        public static Block Parse(I2PBufferCursor reader)
        {
            var block = new Block
            {
                Type = (BlockType)reader.ReadByte(),
                Length = reader.ReadUInt16BigEndian()
            };

            block.Data = reader.ReadBlock(block.Length).ToByteArray();

            return block;
        }

        public void Write(I2PBufferCursor writer)
        {
            writer.WriteByte((byte)Type);
            writer.WriteUInt16BigEndian(Length);
            writer.WriteBytes(Data);
        }

        /// <summary>
        /// Parse as DateTime block (Type 0)
        /// Contains: 4-byte timestamp
        /// </summary>
        public uint ParseAsDateTime()
        {
            if (Type != BlockType.DateTime || Data.Length < 4)
                throw new InvalidOperationException("Not a valid DateTime block");

            var reader = new I2PBufferCursor(Data);
            return reader.ReadUInt32BigEndian();
        }

        /// <summary>
        /// Parse as RouterInfo block (Type 2)
        /// Contains: 1-byte flags + RouterInfo structure
        /// </summary>
        public I2PRouterInfo ParseAsRouterInfo()
        {
            if (Type != BlockType.RouterInfo || Data.Length < 1)
                throw new InvalidOperationException("Not a valid RouterInfo block");

            var reader = new I2PBufferCursor(Data);
            var flags = reader.ReadByte(); // flags (currently unused)

            return new I2PRouterInfo(reader, false);
        }

        /// <summary>
        /// Parse as I2NP block (Type 3)
        /// Contains: 1-byte flags + 2-byte message ID + I2NP message
        /// </summary>
        public Ii2NpHeader ParseAsI2NPHeader()
        {
            if (Type != BlockType.I2NP || Data.Length < 3)
                throw new InvalidOperationException("Not a valid I2NP block");

            var reader = new I2PBufferCursor(Data);
            var flags = reader.ReadByte(); // flags
            var msgId = reader.ReadUInt16BigEndian(); // message ID (for fragmentation)

            // Parse I2NP message header
            return I2NpMessage.ReadHeader16(reader);
        }

        /// <summary>
        /// Parse as Termination block (Type 4)
        /// Contains: 1-byte reason + 8-byte timestamp (optional additional data)
        /// </summary>
        public (byte reason, ulong timestamp) ParseAsTermination()
        {
            if (Type != BlockType.Termination || Data.Length < 1)
                throw new InvalidOperationException("Not a valid Termination block");

            var reader = new I2PBufferCursor(Data);
            var reason = reader.ReadByte();

            ulong timestamp = 0;
            if (Data.Length >= 9)
            {
                timestamp = reader.ReadUInt64BigEndian();
            }

            return (reason, timestamp);
        }

        /// <summary>
        /// Create a DateTime block
        /// </summary>
        public static Block CreateDateTimeBlock(uint timestamp)
        {
            var data = new byte[4];
            var writer = new I2PBufferCursor(data);
            writer.WriteUInt32BigEndian(timestamp);

            return new Block
            {
                Type = BlockType.DateTime,
                Length = 4,
                Data = data
            };
        }

        /// <summary>
        /// Create a RouterInfo block
        /// </summary>
        public static Block CreateRouterInfoBlock(I2PRouterInfo routerInfo, byte flags = 0)
        {
            var riStream = new ArrayBufferWriter<byte>();
            routerInfo.Write(riStream);
            var riBytes = riStream.WrittenSpan.ToArray();

            var data = new byte[1 + riBytes.Length];
            data[0] = flags;
            Array.Copy(riBytes, 0, data, 1, riBytes.Length);

            return new Block
            {
                Type = BlockType.RouterInfo,
                Length = (ushort)data.Length,
                Data = data
            };
        }

        /// <summary>
        /// Create an I2NP block
        /// </summary>
        public static Block CreateI2NPBlock(I2NpMessage message, byte flags = 0, ushort messageId = 0)
        {
            // Serialize I2NP message to byte array
            var msgBytes = message.CreateHeader16.HeaderAndPayload.ToByteArray();

            var data = new byte[3 + msgBytes.Length];
            var writer = new I2PBufferCursor(data);
            writer.WriteByte(flags);
            writer.WriteUInt16BigEndian(messageId);
            writer.WriteBytes(msgBytes);

            return new Block
            {
                Type = BlockType.I2NP,
                Length = (ushort)data.Length,
                Data = data
            };
        }

        /// <summary>
        /// Create a Padding block
        /// </summary>
        public static Block CreatePaddingBlock(int length)
        {
            if (length < 0 || length > 65535)
                throw new ArgumentException("Invalid padding length", nameof(length));

            var data = new byte[length];
            new Random().NextBytes(data); // Fill with random data

            return new Block
            {
                Type = BlockType.Padding,
                Length = (ushort)length,
                Data = data
            };
        }

        /// <summary>
        /// Create a Termination block
        /// </summary>
        public static Block CreateTerminationBlock(byte reason, ulong timestamp = 0)
        {
            var data = timestamp > 0 ? new byte[9] : new byte[1];
            var writer = new I2PBufferCursor(data);
            writer.WriteByte(reason);

            if (timestamp > 0)
            {
                writer.WriteUInt64BigEndian(timestamp);
            }

            return new Block
            {
                Type = BlockType.Termination,
                Length = (ushort)data.Length,
                Data = data
            };
        }
    }

    /// <summary>
    /// Termination reasons
    /// </summary>
    public static class TerminationReason
    {
        public const byte NormalClose = 0;
        public const byte TerminationReceived = 1;
        public const byte IdleTimeout = 2;
        public const byte RouterShutdown = 3;
        public const byte DataPhaseAEADFailure = 4;
        public const byte IncompatibleOptions = 5;
        public const byte IncompatibleSignatureType = 6;
        public const byte ClockSkew = 7;
        public const byte PaddingViolation = 8;
        public const byte AEADFramingError = 9;
        public const byte PayloadFormatError = 10;
        public const byte MessageExpired = 11;
        public const byte IncompatibleVersion = 12;
    }
}
