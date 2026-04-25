using System;
using System.Collections.Generic;
using I2PCore.Data;

namespace I2PCore;

/// <summary>
///     Kademlia DHT binary trie for XOR-distance based routing.
///     Stores I2PIdentHash entries in a binary tree indexed by hash bits,
///     enabling efficient closest-node lookups in O(log n) time.
///     Port of i2pd's DHTTable (KadDHT.h/.cpp).
/// </summary>
public class KadDHT
{
    private const int MAX_LEVELS = 256; // 32 bytes * 8 bits

    private readonly Node _root = new();

    public int Count { get; private set; }

    /// <summary>
    ///     Insert a hash into the DHT.
    /// </summary>
    public void Insert(I2PIdentHash hash)
    {
        if (hash == null) return;
        Insert(hash, _root, 0);
    }

    /// <summary>
    ///     Remove a hash from the DHT.
    /// </summary>
    public bool Remove(I2PIdentHash hash)
    {
        if (hash == null) return false;
        return Remove(hash, _root, 0);
    }

    /// <summary>
    ///     Find the single closest hash to the target.
    /// </summary>
    public I2PIdentHash FindClosest(I2PIdentHash target, Func<I2PIdentHash, bool> filter = null)
    {
        if (target == null) return null;
        return FindClosest(target, _root, 0, filter);
    }

    /// <summary>
    ///     Find the N closest hashes to the target.
    /// </summary>
    public List<I2PIdentHash> FindClosest(I2PIdentHash target, int count, Func<I2PIdentHash, bool> filter = null)
    {
        if (target == null) return new List<I2PIdentHash>();
        var results = new List<I2PIdentHash>();
        FindClosest(target, count, _root, 0, results, filter);
        return results;
    }

    /// <summary>
    ///     Remove all entries.
    /// </summary>
    public void Clear()
    {
        ClearNode(_root);
        Count = 0;
    }

    /// <summary>
    ///     Remove entries that don't pass the filter.
    /// </summary>
    public void Cleanup(Func<I2PIdentHash, bool> shouldKeep)
    {
        Cleanup(_root, shouldKeep);
    }

    // --- Private recursive methods ---

    private void Insert(I2PIdentHash hash, Node node, int level)
    {
        if (level >= MAX_LEVELS)
        {
            // Max depth - store here (hash collision at all 256 bits is impossible in practice)
            if (node.Hash == null) Count++;
            node.Hash = hash;
            return;
        }

        // Empty leaf - store the hash here
        if (node.Hash == null && node.Zero == null && node.One == null)
        {
            node.Hash = hash;
            Count++;
            return;
        }

        // Leaf with existing hash - need to push it down
        if (node.Hash != null)
        {
            if (node.Hash.Equals(hash)) return; // Duplicate, don't increment

            var existing = node.Hash;
            node.Hash = null;

            // Push existing down one level
            var existingBit = GetBit(existing, level);
            if (existingBit)
            {
                node.One ??= new Node();
                Insert(existing, node.One, level + 1);
            }
            else
            {
                node.Zero ??= new Node();
                Insert(existing, node.Zero, level + 1);
            }

            Count--; // Was counted when stored, will be re-counted when pushed down
        }

        // Insert the new hash down the appropriate branch
        var bit = GetBit(hash, level);
        if (bit)
        {
            node.One ??= new Node();
            Insert(hash, node.One, level + 1);
        }
        else
        {
            node.Zero ??= new Node();
            Insert(hash, node.Zero, level + 1);
        }
    }

    private bool Remove(I2PIdentHash hash, Node node, int level)
    {
        if (node == null) return false;

        if (node.Hash != null && node.Hash.Equals(hash))
        {
            node.Hash = null;
            Count--;

            // Move up a child if possible
            if (node.One != null && node.Zero == null)
                node.MoveRouterUp(true);
            else if (node.Zero != null && node.One == null)
                node.MoveRouterUp(false);

            return true;
        }

        if (level >= MAX_LEVELS) return false;

        var bit = GetBit(hash, level);
        var child = bit ? node.One : node.Zero;

        if (child == null) return false;

        var removed = Remove(hash, child, level + 1);
        if (removed && child.IsEmpty)
        {
            if (bit) node.One = null;
            else node.Zero = null;
        }

        return removed;
    }

    private I2PIdentHash FindClosest(I2PIdentHash target, Node node, int level, Func<I2PIdentHash, bool> filter)
    {
        if (node == null) return null;

        if (node.Hash != null)
        {
            if (filter == null || filter(node.Hash))
                return node.Hash;
            return null;
        }

        if (level >= MAX_LEVELS) return null;

        var bit = GetBit(target, level);

        // Try the preferred branch first (matching bit = closer in XOR distance)
        var preferred = bit ? node.One : node.Zero;
        var other = bit ? node.Zero : node.One;

        var result = FindClosest(target, preferred, level + 1, filter);
        if (result != null) return result;

        // Try the other branch
        return FindClosest(target, other, level + 1, filter);
    }

    private void FindClosest(I2PIdentHash target, int count, Node node, int level,
        List<I2PIdentHash> results, Func<I2PIdentHash, bool> filter)
    {
        if (node == null || results.Count >= count) return;

        if (node.Hash != null)
        {
            if (filter == null || filter(node.Hash))
                results.Add(node.Hash);
            return;
        }

        if (level >= MAX_LEVELS) return;

        var bit = GetBit(target, level);
        var preferred = bit ? node.One : node.Zero;
        var other = bit ? node.Zero : node.One;

        FindClosest(target, count, preferred, level + 1, results, filter);
        if (results.Count < count)
            FindClosest(target, count, other, level + 1, results, filter);
    }

    private void Cleanup(Node node, Func<I2PIdentHash, bool> shouldKeep)
    {
        if (node == null) return;

        if (node.Hash != null && !shouldKeep(node.Hash))
        {
            node.Hash = null;
            Count--;
        }

        Cleanup(node.Zero, shouldKeep);
        Cleanup(node.One, shouldKeep);

        // Prune empty children
        if (node.Zero != null && node.Zero.IsEmpty) node.Zero = null;
        if (node.One != null && node.One.IsEmpty) node.One = null;
    }

    private void ClearNode(Node node)
    {
        if (node == null) return;
        ClearNode(node.Zero);
        ClearNode(node.One);
        node.Zero = null;
        node.One = null;
        node.Hash = null;
    }

    /// <summary>
    ///     Get the bit at the specified position in a 32-byte hash.
    ///     Bit 0 is the MSB of byte 0.
    /// </summary>
    private static bool GetBit(I2PIdentHash hash, int bitIndex)
    {
        var byteIndex = bitIndex / 8;
        var bitOffset = 7 - bitIndex % 8; // MSB first
        return (hash.Hash[byteIndex] & (1 << bitOffset)) != 0;
    }

    private class Node
    {
        public I2PIdentHash Hash;
        public Node One;
        public Node Zero;

        public bool IsEmpty => Zero == null && One == null && Hash == null;

        public void MoveRouterUp(bool fromOne)
        {
            var child = fromOne ? One : Zero;
            if (child == null) return;

            if (child.Hash != null)
            {
                Hash = child.Hash;
                child.Hash = null;
            }

            if (fromOne) One = null;
            else Zero = null;
        }
    }
}