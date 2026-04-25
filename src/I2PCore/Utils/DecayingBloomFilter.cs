using System;
using System.Threading;

namespace I2PCore.Utils;

/// <summary>
///     Decaying Bloom filter for duplicate message detection.
///     Uses two bloom filters that alternate - when the active filter fills up,
///     the inactive one is cleared and becomes the new active filter.
///     This provides approximate duplicate detection with bounded memory.
/// </summary>
public class DecayingBloomFilter : IDisposable
{
    private const int DEFAULT_SIZE_BITS = 1 << 20; // ~1M bits = 128KB per filter
    private const int DEFAULT_HASH_COUNT = 8;
    private const int DEFAULT_DECAY_INTERVAL_MS = 300_000; // 5 minutes
    private readonly Timer _decayTimer;
    private readonly byte[][] _filters;
    private readonly int _hashCount;
    private readonly object _lock = new();

    private readonly int _sizeBits;
    private int _activeFilter;
    private long _insertCount;

    public DecayingBloomFilter(
        int sizeBits = DEFAULT_SIZE_BITS,
        int hashCount = DEFAULT_HASH_COUNT,
        int decayIntervalMs = DEFAULT_DECAY_INTERVAL_MS)
    {
        _sizeBits = sizeBits;
        _hashCount = hashCount;
        _activeFilter = 0;
        _filters = new byte[2][];
        _filters[0] = new byte[(_sizeBits + 7) / 8];
        _filters[1] = new byte[(_sizeBits + 7) / 8];

        _decayTimer = new Timer(Decay, null, decayIntervalMs, decayIntervalMs);
    }

    public void Dispose()
    {
        _decayTimer?.Dispose();
    }

    /// <summary>
    ///     Add an item and return true if it was already present (duplicate).
    /// </summary>
    public bool AddAndCheck(byte[] data)
    {
        if (data == null || data.Length == 0) return false;

        lock (_lock)
        {
            var exists = Check(data);
            Add(data);
            return exists;
        }
    }

    /// <summary>
    ///     Check if an item might be in the filter.
    ///     False = definitely not present. True = possibly present.
    /// </summary>
    public bool Check(byte[] data)
    {
        if (data == null || data.Length == 0) return false;

        lock (_lock)
        {
            // Check both filters
            for (var f = 0; f < 2; f++)
            {
                var found = true;
                for (var i = 0; i < _hashCount; i++)
                {
                    var bit = GetBit(data, i);
                    if (!GetFilterBit(_filters[f], bit))
                    {
                        found = false;
                        break;
                    }
                }

                if (found) return true;
            }

            return false;
        }
    }

    private void Add(byte[] data)
    {
        var active = _activeFilter;
        for (var i = 0; i < _hashCount; i++)
        {
            var bit = GetBit(data, i);
            SetFilterBit(_filters[active], bit);
        }

        Interlocked.Increment(ref _insertCount);
    }

    private void Decay(object state)
    {
        lock (_lock)
        {
            // Swap: clear the inactive filter and make it active
            var inactive = 1 - _activeFilter;
            Array.Clear(_filters[inactive], 0, _filters[inactive].Length);
            _activeFilter = inactive;
            Interlocked.Exchange(ref _insertCount, 0);
        }
    }

    private int GetBit(byte[] data, int hashIndex)
    {
        // Use MurmurHash3 with different seeds
        var hash = MurmurHash3.Hash32(data, (uint)hashIndex);
        return (int)(hash % (uint)_sizeBits);
    }

    private static bool GetFilterBit(byte[] filter, int bit)
    {
        return (filter[bit >> 3] & (1 << (bit & 7))) != 0;
    }

    private static void SetFilterBit(byte[] filter, int bit)
    {
        filter[bit >> 3] |= (byte)(1 << (bit & 7));
    }
}

/// <summary>
///     Simple MurmurHash3 32-bit for bloom filter hashing
/// </summary>
public static class MurmurHash3
{
    public static uint Hash32(byte[] data, uint seed = 0)
    {
        var h = seed;
        var length = data.Length;
        var nblocks = length / 4;

        const uint c1 = 0xcc9e2d51;
        const uint c2 = 0x1b873593;

        // Body
        for (var i = 0; i < nblocks; i++)
        {
            var k = (uint)(data[i * 4] | (data[i * 4 + 1] << 8) | (data[i * 4 + 2] << 16) | (data[i * 4 + 3] << 24));
            k *= c1;
            k = RotateLeft(k, 15);
            k *= c2;
            h ^= k;
            h = RotateLeft(h, 13);
            h = h * 5 + 0xe6546b64;
        }

        // Tail
        uint tail = 0;
        var tailOffset = nblocks * 4;
        switch (length & 3)
        {
            case 3:
                tail ^= (uint)data[tailOffset + 2] << 16;
                goto case 2;
            case 2:
                tail ^= (uint)data[tailOffset + 1] << 8;
                goto case 1;
            case 1:
                tail ^= data[tailOffset];
                tail *= c1;
                tail = RotateLeft(tail, 15);
                tail *= c2;
                h ^= tail;
                break;
        }

        // Finalization
        h ^= (uint)length;
        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;

        return h;
    }

    private static uint RotateLeft(uint x, int r)
    {
        return (x << r) | (x >> (32 - r));
    }
}