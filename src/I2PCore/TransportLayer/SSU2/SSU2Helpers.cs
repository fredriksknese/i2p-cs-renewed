using System;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TransportLayer.SSU2.Messages;

namespace I2PCore.TransportLayer.SSU2
{
    /// <summary>
    /// Helper utilities for SSU2
    /// </summary>
    public static class SSU2Helpers
    {
        /// <summary>
        /// Validate connection IDs per SSU2 spec
        /// Source and Destination IDs must NOT be identical
        /// </summary>
        public static bool ValidateConnectionIds(ulong sourceId, ulong destinationId)
        {
            if (sourceId == destinationId)
            {
                Logging.LogDebug($"SSU2: Connection ID validation failed - source and destination are identical: {sourceId}");
                return false;
            }
            return true;
        }

        /// <summary>
        /// Fragment a SessionConfirmed message if RouterInfo exceeds MTU
        /// Per SSU2 spec lines 1779-1871
        /// </summary>
        public static List<byte[]> FragmentSessionConfirmed(
            SSU2Header header,
            byte[] encryptedStaticKey,
            byte[] routerInfoBytes,
            int mtu = 1280)
        {
            var fragments = new List<byte[]>();

            // Calculate available space per fragment
            // Header (32) + Encrypted static key (48) + Encrypted payload overhead (~16)
            var headerSize = 32;
            var staticKeySize = 48;
            var aeadOverhead = 16;
            var availablePerFragment = mtu - headerSize - staticKeySize - aeadOverhead;

            // First fragment contains the encrypted static key
            if (routerInfoBytes.Length <= availablePerFragment)
            {
                // No fragmentation needed
                var fragment = new byte[headerSize + staticKeySize + routerInfoBytes.Length + aeadOverhead];
                var writer = new BufRefLen(fragment);

                // Write header
                writer.Write(header.ToByteArray());

                // Write encrypted static key (Part 1)
                writer.Write(encryptedStaticKey);

                // Write RouterInfo (Part 2 - will be encrypted by caller)
                writer.Write(routerInfoBytes);

                fragments.Add(fragment);
            }
            else
            {
                // Fragmentation required
                var offset = 0;
                var fragmentIndex = 0;

                while (offset < routerInfoBytes.Length)
                {
                    var chunkSize = Math.Min(availablePerFragment, routerInfoBytes.Length - offset);
                    var isFirstFragment = (fragmentIndex == 0);
                    var isLastFragment = (offset + chunkSize >= routerInfoBytes.Length);

                    var fragmentSize = headerSize + (isFirstFragment ? staticKeySize : 0) + chunkSize + aeadOverhead;
                    var fragment = new byte[fragmentSize];
                    var writer = new BufRefLen(fragment);

                    // Modify header for fragmentation
                    var fragmentHeader = new SSU2Header
                    {
                        IsLongHeader = true,
                        Type = SSU2Header.TYPE_SESSION_CONFIRMED,
                        Version = header.Version,
                        NetId = header.NetId,
                        DestinationConnectionId = header.DestinationConnectionId,
                        SourceConnectionId = header.SourceConnectionId,
                        PacketNumber = (uint)(header.PacketNumber + fragmentIndex),  // Cast to uint
                        Token = header.Token
                    };

                    // Write fragment header
                    writer.Write(fragmentHeader.ToByteArray());

                    // First fragment includes encrypted static key
                    if (isFirstFragment)
                    {
                        writer.Write(encryptedStaticKey);
                    }

                    // Write RouterInfo chunk
                    var chunk = new byte[chunkSize];
                    Array.Copy(routerInfoBytes, offset, chunk, 0, chunkSize);
                    writer.Write(chunk);

                    fragments.Add(fragment);

                    offset += chunkSize;
                    fragmentIndex++;
                }

                Logging.LogDebug($"SSU2: Fragmented SessionConfirmed into {fragments.Count} packets");
            }

            return fragments;
        }

        /// <summary>
        /// Generate random packet number for handshake messages
        /// Per spec: SessionRequest/Created use random packet numbers (4 bytes)
        /// </summary>
        public static uint GenerateRandomPacketNumber()
        {
            var random = new Random();
            return (uint)random.Next();
        }

        /// <summary>
        /// Check if network ID is valid (2 for mainnet)
        /// </summary>
        public static bool ValidateNetworkId(byte netId)
        {
            var expectedNetId = (byte)I2PCore.Data.I2PConstants.I2PNetworkId;
            if (netId != expectedNetId)
            {
                Logging.LogDebug($"SSU2: Invalid network ID {netId}, expected {expectedNetId}");
                return false;
            }
            return true;
        }

        /// <summary>
        /// Check if version is supported (should be 2)
        /// </summary>
        public static bool ValidateVersion(byte version, byte expectedVersion = 2)
        {
            if (version != expectedVersion)
            {
                Logging.LogDebug($"SSU2: Unsupported version {version}, expected {expectedVersion}");
                return false;
            }
            return true;
        }
    }
}
