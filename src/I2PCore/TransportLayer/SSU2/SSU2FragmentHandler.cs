using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     Handles SSU2 message fragmentation and reassembly.
///     Per SSU2 spec: messages exceeding MTU are split into FirstFragment + FollowOnFragment blocks.
/// </summary>
public class SSU2FragmentHandler
{
    public const int SSU2_MAX_PACKET_SIZE = 1500;
    public const int IPV6_HEADER_SIZE = 40;
    public const int IPV4_HEADER_SIZE = 20;
    public const int UDP_HEADER_SIZE = 8;
    public const int CRYPTO_OVERHEAD = 32; // 16-byte short header + 16-byte MAC

    public const int MAX_PAYLOAD_SIZE_IPV6 =
        SSU2_MAX_PACKET_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE - CRYPTO_OVERHEAD;

    public const int MAX_PAYLOAD_SIZE_IPV4 =
        SSU2_MAX_PACKET_SIZE - IPV4_HEADER_SIZE - UDP_HEADER_SIZE - CRYPTO_OVERHEAD;

    public const int MAX_NUM_FRAGMENTS = 64;
    public const int INCOMPLETE_MESSAGE_TIMEOUT_SECONDS = 30;

    // Block header sizes
    public const int BLOCK_HEADER_SIZE = 3; // 1 type + 2 size
    public const int FIRST_FRAGMENT_HEADER = BLOCK_HEADER_SIZE; // type(1) + size(2), then raw I2NP
    public const int FOLLOWON_FRAGMENT_OVERHEAD = BLOCK_HEADER_SIZE + 5; // type(1) + size(2) + flags(1) + msgID(4)

    private readonly ConcurrentDictionary<uint, IncompleteMessage> _incompleteMessages = new();

    /// <summary>
    ///     Fragment a message that exceeds maxPayloadSize into FirstFragment + FollowOnFragment blocks.
    ///     Returns a list of block byte arrays, each fitting within maxPayloadSize.
    /// </summary>
    public static List<byte[]> FragmentMessage(byte[] i2npData, uint msgId, int maxPayloadSize)
    {
        var result = new List<byte[]>();

        // First fragment: block header (3) + data
        var firstFragDataSize = maxPayloadSize - FIRST_FRAGMENT_HEADER;
        if (firstFragDataSize <= 0)
            throw new ArgumentException("maxPayloadSize too small for fragmentation");

        if (firstFragDataSize > i2npData.Length)
            firstFragDataSize = i2npData.Length;

        // Build FirstFragment block
        var firstBlock = new byte[FIRST_FRAGMENT_HEADER + firstFragDataSize];
        firstBlock[0] = (byte)SSU2BlockType.FirstFragment;
        firstBlock[1] = (byte)(firstFragDataSize >> 8);
        firstBlock[2] = (byte)(firstFragDataSize & 0xFF);
        Array.Copy(i2npData, 0, firstBlock, FIRST_FRAGMENT_HEADER, firstFragDataSize);
        result.Add(firstBlock);

        // Follow-on fragments
        var offset = firstFragDataSize;
        byte fragmentNum = 0;
        while (offset < i2npData.Length)
        {
            fragmentNum++;
            if (fragmentNum >= MAX_NUM_FRAGMENTS)
            {
                Logging.LogWarning($"SSU2 Fragment: message too large, exceeds {MAX_NUM_FRAGMENTS} fragments");
                break;
            }

            var remaining = i2npData.Length - offset;
            var followOnDataSize = maxPayloadSize - FOLLOWON_FRAGMENT_OVERHEAD;
            var isLast = remaining <= followOnDataSize;
            if (!isLast)
            {
                // Not last, fill to max
            }
            else
            {
                followOnDataSize = remaining;
            }

            // Build FollowOnFragment block
            // Size field = data + 5 (flags + msgID)
            var blockDataSize = followOnDataSize + 5;
            var followBlock = new byte[BLOCK_HEADER_SIZE + blockDataSize];
            followBlock[0] = (byte)SSU2BlockType.FollowOnFragment;
            followBlock[1] = (byte)(blockDataSize >> 8);
            followBlock[2] = (byte)(blockDataSize & 0xFF);
            // Flags: fragmentNum << 1 | isLast
            followBlock[3] = (byte)((fragmentNum << 1) | (isLast ? 1 : 0));
            // Message ID (network byte order = big endian)
            followBlock[4] = (byte)(msgId >> 24);
            followBlock[5] = (byte)(msgId >> 16);
            followBlock[6] = (byte)(msgId >> 8);
            followBlock[7] = (byte)msgId;
            Array.Copy(i2npData, offset, followBlock, FOLLOWON_FRAGMENT_OVERHEAD, followOnDataSize);
            result.Add(followBlock);

            offset += followOnDataSize;
        }

        return result;
    }

    /// <summary>
    ///     Check if a message needs fragmentation based on maxPayloadSize.
    /// </summary>
    public static bool NeedsFragmentation(int messageSize, int maxPayloadSize)
    {
        // I2NP block: type(1) + size(2) + data
        return messageSize + BLOCK_HEADER_SIZE > maxPayloadSize;
    }

    /// <summary>
    ///     Handle a received FirstFragment block. Returns a complete I2NP message if
    ///     all fragments are now available, otherwise null.
    /// </summary>
    public byte[] HandleFirstFragment(byte[] data)
    {
        if (data.Length < 9) return null; // Minimum I2NP header fragment

        // Extract message ID from I2NP header (bytes 1-4 in NTCP2 short format)
        if (data.Length < 5) return null;
        var msgId = (uint)((data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]);

        var incomplete = _incompleteMessages.GetOrAdd(msgId, _ => new IncompleteMessage
        {
            Data = new byte[64 * 1024], // Max I2NP message size
            LastFragmentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            NextFragmentNum = 1
        });

        lock (incomplete)
        {
            incomplete.HasFirstFragment = true;
            Array.Copy(data, 0, incomplete.Data, 0, data.Length);
            incomplete.DataLength = data.Length;
            incomplete.LastFragmentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // Try to attach any out-of-order follow-on fragments
            return TryConcatenateFragments(msgId, incomplete);
        }
    }

    /// <summary>
    ///     Handle a received FollowOnFragment block. Returns a complete I2NP message if
    ///     all fragments are now available, otherwise null.
    /// </summary>
    public byte[] HandleFollowOnFragment(byte[] data)
    {
        if (data.Length < 5) return null; // flags(1) + msgID(4) minimum

        var flags = data[0];
        var fragmentNum = flags >> 1;
        var isLast = (flags & 1) == 1;
        var msgId = (uint)((data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]);

        if (fragmentNum == 0 || fragmentNum >= MAX_NUM_FRAGMENTS)
        {
            Logging.LogWarning($"SSU2 Fragment: invalid follow-on fragment num {fragmentNum}");
            return null;
        }

        var fragmentData = new byte[data.Length - 5];
        Array.Copy(data, 5, fragmentData, 0, fragmentData.Length);

        var incomplete = _incompleteMessages.GetOrAdd(msgId, _ => new IncompleteMessage
        {
            Data = new byte[64 * 1024],
            LastFragmentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            NextFragmentNum = 0 // Waiting for first fragment
        });

        lock (incomplete)
        {
            incomplete.LastFragmentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (incomplete.HasFirstFragment && fragmentNum == incomplete.NextFragmentNum)
            {
                // In-sequence fragment - append directly
                if (incomplete.DataLength + fragmentData.Length > incomplete.Data.Length)
                {
                    // Resize
                    var newData = new byte[incomplete.DataLength + fragmentData.Length + 4096];
                    Array.Copy(incomplete.Data, 0, newData, 0, incomplete.DataLength);
                    incomplete.Data = newData;
                }

                Array.Copy(fragmentData, 0, incomplete.Data, incomplete.DataLength, fragmentData.Length);
                incomplete.DataLength += fragmentData.Length;
                incomplete.NextFragmentNum++;

                if (isLast)
                {
                    // Complete!
                    var result = new byte[incomplete.DataLength];
                    Array.Copy(incomplete.Data, 0, result, 0, incomplete.DataLength);
                    _incompleteMessages.TryRemove(msgId, out _);
                    return result;
                }

                // Try to attach out-of-order fragments
                return TryConcatenateFragments(msgId, incomplete);
            }

            // Out-of-order or waiting for first fragment - store
            if (!incomplete.OutOfOrderFragments.ContainsKey(fragmentNum))
                incomplete.OutOfOrderFragments[fragmentNum] = new Fragment
                {
                    Data = fragmentData,
                    FragmentNum = fragmentNum,
                    IsLast = isLast
                };
            return null;
        }
    }

    private byte[] TryConcatenateFragments(uint msgId, IncompleteMessage incomplete)
    {
        if (!incomplete.HasFirstFragment) return null;

        while (incomplete.OutOfOrderFragments.Count > 0)
        {
            var nextExpected = incomplete.NextFragmentNum;
            if (!incomplete.OutOfOrderFragments.TryGetValue(nextExpected, out var frag))
                break;

            incomplete.OutOfOrderFragments.Remove(nextExpected);

            // Append
            if (incomplete.DataLength + frag.Data.Length > incomplete.Data.Length)
            {
                var newData = new byte[incomplete.DataLength + frag.Data.Length + 4096];
                Array.Copy(incomplete.Data, 0, newData, 0, incomplete.DataLength);
                incomplete.Data = newData;
            }

            Array.Copy(frag.Data, 0, incomplete.Data, incomplete.DataLength, frag.Data.Length);
            incomplete.DataLength += frag.Data.Length;
            incomplete.NextFragmentNum++;

            if (frag.IsLast)
            {
                var result = new byte[incomplete.DataLength];
                Array.Copy(incomplete.Data, 0, result, 0, incomplete.DataLength);
                _incompleteMessages.TryRemove(msgId, out _);
                return result;
            }
        }

        return null;
    }

    /// <summary>
    ///     Clean up incomplete messages that have timed out.
    ///     Should be called periodically.
    /// </summary>
    public void CleanUp()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var kvp in _incompleteMessages)
            if (now - kvp.Value.LastFragmentTime > INCOMPLETE_MESSAGE_TIMEOUT_SECONDS)
                if (_incompleteMessages.TryRemove(kvp.Key, out _))
                    Logging.LogWarning(
                        $"SSU2 Fragment: incomplete message {kvp.Key:X8} timed out after {INCOMPLETE_MESSAGE_TIMEOUT_SECONDS}s");
    }

    /// <summary>
    ///     Represents a partially-received message being reassembled from fragments.
    /// </summary>
    private class IncompleteMessage
    {
        public readonly SortedList<int, Fragment> OutOfOrderFragments = new();
        public byte[] Data;
        public int DataLength;
        public bool HasFirstFragment;
        public long LastFragmentTime;
        public int NextFragmentNum;
    }

    private class Fragment
    {
        public byte[] Data;
        public int FragmentNum;
        public bool IsLast;
    }
}