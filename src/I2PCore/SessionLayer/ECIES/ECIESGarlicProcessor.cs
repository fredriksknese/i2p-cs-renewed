using System;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.SessionLayer.ECIES
{
    /// <summary>
    /// ECIES Garlic Clove Processor
    /// Processes garlic cloves from ECIES messages
    ///
    /// A garlic message contains multiple cloves
    /// Each clove contains instructions and a payload
    /// Cloves can be nested (garlic within garlic)
    /// </summary>
    public class ECIESGarlicProcessor
    {
        private readonly ECIESSessionKeyManager _sessionManager;
        private readonly I2PDestination _localDestination;

        public ECIESGarlicProcessor(
            ECIESSessionKeyManager sessionManager,
            I2PDestination localDestination)
        {
            _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
            _localDestination = localDestination ?? throw new ArgumentNullException(nameof(localDestination));
        }

        /// <summary>
        /// Process a garlic message
        /// </summary>
        public GarlicProcessingResult ProcessGarlicMessage(byte[] garlicData)
        {
            if (garlicData == null)
                throw new ArgumentNullException(nameof(garlicData));

            try
            {
                // Parse garlic cloves
                var cloves = ParseGarlicCloves(garlicData);

                // Process each clove
                var results = new List<CloveResult>();
                foreach (var clove in cloves)
                {
                    var result = ProcessClove(clove);
                    results.Add(result);
                }

                return new GarlicProcessingResult
                {
                    Success = true,
                    CloveResults = results
                };
            }
            catch (Exception ex)
            {
                return new GarlicProcessingResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Parse garlic cloves from data
        /// </summary>
        private List<GarlicClove> ParseGarlicCloves(byte[] data)
        {
            var cloves = new List<GarlicClove>();
            var reader = new BufRef(data);

            // Read clove count
            var cloveCount = reader.Read8();

            for (int i = 0; i < cloveCount; i++)
            {
                var clove = ParseClove(reader);
                cloves.Add(clove);
            }

            return cloves;
        }

        /// <summary>
        /// Parse a single garlic clove
        /// </summary>
        private GarlicClove ParseClove(BufRef reader)
        {
            var clove = new GarlicClove();

            // Read delivery instructions
            clove.DeliveryInstructions = ParseDeliveryInstructions(reader);

            // Read clove data length
            var cloveDataLength = reader.ReadFlip16();

            // Read clove data
            clove.Data = reader.Read(cloveDataLength);

            // Read clove ID
            clove.CloveId = reader.ReadFlip32();

            // Read expiration
            clove.Expiration = reader.ReadFlip32();

            return clove;
        }

        /// <summary>
        /// Parse delivery instructions
        /// </summary>
        private DeliveryInstructions ParseDeliveryInstructions(BufRef reader)
        {
            var instructions = new DeliveryInstructions();

            // Read flags
            var flags = reader.Read8();
            instructions.DeliveryType = (DeliveryType)(flags & 0x03);
            instructions.Encrypted = (flags & 0x80) != 0;

            // Read destination based on delivery type
            switch (instructions.DeliveryType)
            {
                case DeliveryType.Local:
                    // No destination info
                    break;

                case DeliveryType.Destination:
                    // Read destination hash
                    instructions.Destination = new I2PIdentHash(reader);
                    break;

                case DeliveryType.Router:
                    // Read router hash
                    instructions.RouterHash = new I2PIdentHash(reader);
                    break;

                case DeliveryType.Tunnel:
                    // Read tunnel ID and router hash
                    instructions.TunnelId = new I2PTunnelId(reader);
                    instructions.RouterHash = new I2PIdentHash(reader);
                    break;
            }

            // Read delay (optional)
            if ((flags & 0x04) != 0)
            {
                instructions.Delay = reader.ReadFlip32();
            }

            return instructions;
        }

        /// <summary>
        /// Process a single clove
        /// </summary>
        private CloveResult ProcessClove(GarlicClove clove)
        {
            try
            {
                // Check expiration
                if (IsExpired(clove.Expiration))
                {
                    return new CloveResult
                    {
                        Success = false,
                        Error = "Clove expired",
                        CloveId = clove.CloveId
                    };
                }

                // Process based on delivery type
                CloveResult result;
                switch (clove.DeliveryInstructions.DeliveryType)
                {
                    case DeliveryType.Local:
                        result = ProcessLocalClove(clove);
                        break;

                    case DeliveryType.Destination:
                        result = ProcessDestinationClove(clove);
                        break;

                    case DeliveryType.Router:
                        result = ProcessRouterClove(clove);
                        break;

                    case DeliveryType.Tunnel:
                        result = ProcessTunnelClove(clove);
                        break;

                    default:
                        return new CloveResult
                        {
                            Success = false,
                            Error = $"Unknown delivery type: {clove.DeliveryInstructions.DeliveryType}",
                            CloveId = clove.CloveId
                        };
                }

                if (result != null)
                {
                    result.Expiration = clove.Expiration;
                }
                return result;
            }
            catch (Exception ex)
            {
                return new CloveResult
                {
                    Success = false,
                    Error = ex.Message,
                    CloveId = clove.CloveId
                };
            }
        }

        /// <summary>
        /// Process local delivery clove (for this destination)
        /// </summary>
        private CloveResult ProcessLocalClove(GarlicClove clove)
        {
            // Parse as I2NP message or nested garlic
            // For now, treat as I2NP message
            return new CloveResult
            {
                Success = true,
                CloveId = clove.CloveId,
                DeliveryType = DeliveryType.Local,
                Payload = clove.Data
            };
        }

        /// <summary>
        /// Process destination delivery clove (forward to another destination)
        /// </summary>
        private CloveResult ProcessDestinationClove(GarlicClove clove)
        {
            return new CloveResult
            {
                Success = true,
                CloveId = clove.CloveId,
                DeliveryType = DeliveryType.Destination,
                ForwardDestination = clove.DeliveryInstructions.Destination,
                Payload = clove.Data
            };
        }

        /// <summary>
        /// Process router delivery clove (forward to a router)
        /// </summary>
        private CloveResult ProcessRouterClove(GarlicClove clove)
        {
            return new CloveResult
            {
                Success = true,
                CloveId = clove.CloveId,
                DeliveryType = DeliveryType.Router,
                ForwardRouter = clove.DeliveryInstructions.RouterHash,
                Payload = clove.Data
            };
        }

        /// <summary>
        /// Process tunnel delivery clove (forward through a tunnel)
        /// </summary>
        private CloveResult ProcessTunnelClove(GarlicClove clove)
        {
            return new CloveResult
            {
                Success = true,
                CloveId = clove.CloveId,
                DeliveryType = DeliveryType.Tunnel,
                ForwardTunnelId = clove.DeliveryInstructions.TunnelId,
                ForwardRouter = clove.DeliveryInstructions.RouterHash,
                Payload = clove.Data
            };
        }

        /// <summary>
        /// Check if clove is expired
        /// </summary>
        private bool IsExpired(uint expiration)
        {
            var expirationTime = DateTimeOffset.FromUnixTimeSeconds(expiration);
            return expirationTime < DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Build a garlic message from cloves
        /// </summary>
        public static byte[] BuildGarlicMessage(List<GarlicClove> cloves)
        {
            if (cloves == null)
                throw new ArgumentNullException(nameof(cloves));

            var stream = new BufRefStream();

            // Write clove count
            stream.Write((byte)cloves.Count);

            // Write each clove
            foreach (var clove in cloves)
            {
                WriteClove(stream, clove);
            }

            return stream.ToByteArray();
        }

        /// <summary>
        /// Write a single clove
        /// </summary>
        private static void WriteClove(BufRefStream stream, GarlicClove clove)
        {
            // Write delivery instructions
            WriteDeliveryInstructions(stream, clove.DeliveryInstructions);

            // Write clove data length
            stream.Write(BufUtils.Flip16Bl((ushort)clove.Data.Length));

            // Write clove data
            stream.Write(clove.Data);

            // Write clove ID
            stream.Write(BufUtils.Flip32Bl(clove.CloveId));

            // Write expiration
            stream.Write(BufUtils.Flip32Bl(clove.Expiration));
        }

        /// <summary>
        /// Write delivery instructions
        /// </summary>
        private static void WriteDeliveryInstructions(BufRefStream stream, DeliveryInstructions instructions)
        {
            // Build flags
            byte flags = (byte)instructions.DeliveryType;
            if (instructions.Encrypted)
                flags |= 0x80;
            if (instructions.Delay.HasValue)
                flags |= 0x04;

            stream.Write(flags);

            // Write destination based on delivery type
            switch (instructions.DeliveryType)
            {
                case DeliveryType.Local:
                    // No destination info
                    break;

                case DeliveryType.Destination:
                    instructions.Destination.Write(stream);
                    break;

                case DeliveryType.Router:
                    instructions.RouterHash.Write(stream);
                    break;

                case DeliveryType.Tunnel:
                    instructions.TunnelId.Write(stream);
                    instructions.RouterHash.Write(stream);
                    break;
            }

            // Write delay if present
            if (instructions.Delay.HasValue)
            {
                stream.Write(BufUtils.Flip32Bl(instructions.Delay.Value));
            }
        }
    }

    /// <summary>
    /// Delivery type for garlic cloves
    /// </summary>
    public enum DeliveryType : byte
    {
        Local = 0,
        Destination = 1,
        Router = 2,
        Tunnel = 3
    }

    /// <summary>
    /// Delivery instructions for a garlic clove
    /// </summary>
    public class DeliveryInstructions
    {
        public DeliveryType DeliveryType { get; set; }
        public bool Encrypted { get; set; }
        public I2PIdentHash Destination { get; set; }
        public I2PIdentHash RouterHash { get; set; }
        public I2PTunnelId TunnelId { get; set; }
        public uint? Delay { get; set; }
    }

    /// <summary>
    /// A garlic clove
    /// </summary>
    public class GarlicClove
    {
        public DeliveryInstructions DeliveryInstructions { get; set; }
        public byte[] Data { get; set; }
        public uint CloveId { get; set; }
        public uint Expiration { get; set; }
    }

    /// <summary>
    /// Result of processing a garlic message
    /// </summary>
    public class GarlicProcessingResult
    {
        public bool Success { get; set; }
        public List<CloveResult> CloveResults { get; set; }
        public string Error { get; set; }
    }

    /// <summary>
    /// Result of processing a single clove
    /// </summary>
    public class CloveResult
    {
        public bool Success { get; set; }
        public uint CloveId { get; set; }
        public uint Expiration { get; set; }
        public DeliveryType DeliveryType { get; set; }
        public byte[] Payload { get; set; }
        public I2PIdentHash ForwardDestination { get; set; }
        public I2PIdentHash ForwardRouter { get; set; }
        public I2PTunnelId ForwardTunnelId { get; set; }
        public string Error { get; set; }
    }
}
