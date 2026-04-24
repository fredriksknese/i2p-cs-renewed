using System;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TransportLayer.Crypto;
using I2PCore.TransportLayer.NTCP2;

namespace I2PCore.TransportLayer.NTCP2.Messages
{
    /// <summary>
    /// NTCP2 Session Confirmed (Handshake Message 3)
    ///
    /// Noise XK pattern: -> s, se
    ///
    /// Structure:
    /// - Part 1: Encrypted static key S (48 bytes: 32 key + 16 MAC)
    /// - Part 2: Encrypted RouterInfo + options + padding (variable, length sent in message 1)
    ///
    /// Total: 48 + m3p2len bytes
    ///
    /// NTCP2 spec lines 915-1093
    /// </summary>
    public class SessionConfirmed
    {
        public byte[] StaticKey { get; set; }  // Alice's static key, 32 bytes
        public I2PRouterInfo RouterInfo { get; set; }
        public NTCP2OptionsBlock Options { get; set; }
        public byte[] Padding { get; set; }

        public const int PART1_SIZE = 48;  // 32 bytes key + 16 bytes MAC

        /// <summary>
        /// Parse SessionConfirmed using NoiseXK state (Bob's side)
        /// </summary>
        public static SessionConfirmed Parse(BufRef data, int part2Length, NoiseXK noiseState)
        {
            var confirmed = new SessionConfirmed();

            // Read part 1: encrypted static key (48 bytes including MAC)
            var encryptedStatic = data.ReadBufLen(PART1_SIZE).ToByteArray();

            // Decrypt using Noise protocol (k from message 2, nonce = 1)
            // This also validates the static key and updates the handshake hash
            confirmed.StaticKey = noiseState.ProcessMessage3Part1(encryptedStatic);

            // Read part 2: encrypted RouterInfo + optional blocks
            var encryptedPart2 = data.ReadBufLen(part2Length).ToByteArray();

            // Decrypt using Noise protocol (new k from "se" DH, nonce = 0)
            var decryptedPayload = noiseState.ProcessMessage3Part2(encryptedPart2);

            // Parse blocks from decrypted payload
            ParseBlocks(decryptedPayload, confirmed);

            return confirmed;
        }

        /// <summary>
        /// Parse blocks from Message 3 Part 2 payload
        /// NTCP2 spec lines 1014-1081: Must contain RouterInfo, optional Options, optional Padding
        /// Order: RouterInfo -> Options -> Padding
        /// </summary>
        private static void ParseBlocks(byte[] payload, SessionConfirmed confirmed)
        {
            var reader = new BufRef(payload);
            bool routerInfoFound = false;
            bool optionsFound = false;

            while (reader.BaseArrayOffset < payload.Length)
            {
                int remaining = payload.Length - reader.BaseArrayOffset;
                if (remaining < 3)
                    throw new Exception("Invalid block: not enough data for header");

                byte blockType = reader.Read8();
                ushort blockSize = reader.ReadFlip16();

                remaining = payload.Length - reader.BaseArrayOffset;
                if (remaining < blockSize)
                    throw new Exception($"Invalid block: size {blockSize} exceeds remaining data {remaining}");

                switch (blockType)
                {
                    case 2: // RouterInfo block
                        if (routerInfoFound)
                            throw new Exception("Multiple RouterInfo blocks not allowed");
                        if (optionsFound)
                            throw new Exception("RouterInfo must come before Options");

                        // Skip flags byte
                        reader.Seek(1);
                        var riData = reader.ReadBufLen(blockSize - 1);
                        var riReader = new BufRef(riData.ToByteArray());
                        confirmed.RouterInfo = new I2PRouterInfo(riReader, true);
                        routerInfoFound = true;
                        break;

                    case 1: // Options block
                        if (optionsFound)
                            throw new Exception("Multiple Options blocks not allowed");

                        var optionsData = reader.ReadBufLen(blockSize);
                        confirmed.Options = new NTCP2OptionsBlock();
                        confirmed.Options.Parse(new BufRefLen(optionsData.ToByteArray()));
                        optionsFound = true;
                        break;

                    case 254: // Padding block (must be last)
                        var paddingData = reader.ReadBufLen(blockSize);
                        confirmed.Padding = paddingData.ToByteArray();

                        // Padding must be last block
                        if (reader.BaseArrayOffset < payload.Length)
                            throw new Exception("Padding block must be the last block");
                        break;

                    default:
                        // Unknown blocks should be treated as padding per spec
                        reader.Seek(blockSize);
                        break;
                }
            }

            if (!routerInfoFound)
                throw new Exception("RouterInfo block is required in SessionConfirmed");
        }

        /// <summary>
        /// Create SessionConfirmed using NoiseXK state (Alice's side)
        /// </summary>
        public static (byte[] part1, byte[] part2) Create(I2PRouterInfo routerInfo, NTCP2OptionsBlock options, byte[] padding, NoiseXK noiseState)
        {
            // Part 1: Encrypt static key using NoiseXK
            // This uses key from message 2, nonce = 1
            var encryptedStatic = noiseState.CreateMessage3Part1();

            // Part 2: Build and encrypt payload
            var payload = BuildPart2Payload(routerInfo, options, padding);
            var encryptedPart2 = noiseState.CreateMessage3Part2(payload);

            return (encryptedStatic, encryptedPart2);
        }

        /// <summary>
        /// Build Part 2 payload with blocks
        /// NTCP2 spec lines 1014-1081: RouterInfo (required) -> Options (optional) -> Padding (optional)
        /// </summary>
        private static byte[] BuildPart2Payload(I2PRouterInfo routerInfo, NTCP2OptionsBlock options, byte[] padding)
        {
            var result = new BufLen(new byte[8192]);  // Larger buffer for RouterInfo
            var writer = new BufRefLen(result);

            // Block 2: RouterInfo (required, must be first)
            writer.Write8(2);  // block type
            var riBytes = routerInfo.ToByteArray();
            writer.WriteFlip16((ushort)(riBytes.Length + 1));  // size includes flags
            writer.Write8(0);  // flags: bit 0 = 0 (local store), bit 1-7 unused
            writer.Write(riBytes);

            // Block 1: Options (optional)
            if (options != null)
            {
                var optionsBytes = options.Serialize();
                // optionsBytes already includes type and size
                writer.Write(optionsBytes);
            }

            // Block 254: Padding (optional, must be last)
            if (padding != null && padding.Length > 0)
            {
                writer.Write8(254);
                writer.WriteFlip16((ushort)padding.Length);
                writer.Write(padding);
            }

            return result.ToByteArray();
        }

        /// <summary>
        /// Validate block ordering for SessionConfirmed Part 2
        /// </summary>
        public static void ValidateBlockOrdering(byte[] payload)
        {
            var reader = new BufRef(payload);
            bool routerInfoSeen = false;
            bool optionsSeen = false;
            bool paddingSeen = false;

            while (reader.BaseArrayOffset < payload.Length)
            {
                int remaining = payload.Length - reader.BaseArrayOffset;
                if (remaining < 3)
                    throw new Exception("Block ordering validation: insufficient data");

                byte blockType = reader.Read8();
                ushort blockSize = reader.ReadFlip16();

                remaining = payload.Length - reader.BaseArrayOffset;
                if (remaining < blockSize)
                    throw new Exception("Block ordering validation: invalid block size");

                switch (blockType)
                {
                    case 2: // RouterInfo
                        if (routerInfoSeen)
                            throw new Exception("Multiple RouterInfo blocks");
                        if (optionsSeen || paddingSeen)
                            throw new Exception("RouterInfo must be first block");
                        routerInfoSeen = true;
                        break;

                    case 1: // Options
                        if (!routerInfoSeen)
                            throw new Exception("Options before RouterInfo");
                        if (optionsSeen)
                            throw new Exception("Multiple Options blocks");
                        if (paddingSeen)
                            throw new Exception("Options after Padding");
                        optionsSeen = true;
                        break;

                    case 254: // Padding
                        if (paddingSeen)
                            throw new Exception("Multiple Padding blocks");
                        paddingSeen = true;
                        // Padding must be last - check after reading block
                        break;

                    default:
                        // Unknown blocks treated as padding, allowed anywhere
                        break;
                }

                reader.Seek(blockSize);

                // If we saw padding, ensure it's the last block
                if (paddingSeen && reader.BaseArrayOffset < payload.Length)
                    throw new Exception("Padding block must be last");
            }

            if (!routerInfoSeen)
                throw new Exception("RouterInfo block required");
        }
    }
}
