using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

/// <summary>
///     I2NP DatabaseLookup.
/// </summary>
/// <remarks>
///     Batch 3-16 (docs/PRODUCTION-PLAN.md). <b>The reply key and the reply tags are one field
///     group, and reading them was gated on the wrong flag.</b>
///     <para>
///     i2pd's <c>CreateLeaseSetDatabaseLookupMsg</c> (I2NPProtocol.cpp) sets
///     <c>DELIVERY | LEASESET_LOOKUP | ECIES</c> — flags <c>0x15</c>, with the encryption bit
///     <c>0x02</c> <i>clear</i> — and then unconditionally writes
///     <c>replyKey(32) || numTags(1) || tag(8)</c>. Its own floodfill reads them back the same
///     way: <c>NetDb::HandleDatabaseLookupMsg</c> treats <c>ENCRYPTION_FLAG | ECIES_FLAG</c> as
///     "encrypted reply requested" and then takes <c>excluded[32]</c> as the tag count whichever
///     of the two flags arrived.
///     </para>
///     <para>
///     This parser read the key on either flag but the tag count only on <c>Encryption</c>, so
///     every LeaseSet lookup i2pd sends parsed with <b>zero tags</b> — a reply key with nothing
///     to address the reply to. It was invisible because our own writer set both flags, so
///     reader and writer agreed with each other and neither agreed with the network. Both halves
///     now write and read the group together, which is also what Java I2P does.
///     </para>
/// </remarks>
public class DatabaseLookupMessage : I2NpMessage
{
    [Flags]
    public enum LookupTypes : byte
    {
        Tunnel = 0b00000001,
        Encryption = 0b00000010,
        Normal = 0b00000000,
        LeaseSet = 0b00000100,
        RouterInfo = 0b00001000,
        Exploration = 0b00001100,
        Ecies = 0b00010000
    }

    private readonly List<I2PIdentHash> CachedExcludeList = new();

    private readonly List<I2PSessionTag> CachedTags = new();

    private I2PIdentHash CachedFrom;

    private I2PIdentHash CachedKey;

    private LookupTypes CachedLookupType;

    private I2PSessionKey CachedReplyKey;

    private I2PTunnelId CachedTunnelId;

    public DatabaseLookupMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);
        UpdateCachedFields(reader);
        SetBuffer(start, reader);
    }

    public DatabaseLookupMessage(I2PIdentHash key, I2PIdentHash from, LookupTypes flags)
    {
        AllocateBuffer(2 * 32 + 1 + 2);
        var writer = new I2PBufferCursor(Payload);

        writer.WriteBlock(key.Hash);
        writer.WriteBlock(from.Hash);
        writer.WriteByte((byte)(flags & ~LookupTypes.Tunnel));
        writer.WriteUInt16LittleEndian(0);
    }

    public DatabaseLookupMessage(
        I2PIdentHash key,
        I2PIdentHash tunnelgw,
        I2PTunnelId tunnelid,
        LookupTypes flags,
        IEnumerable<I2PIdentHash> excludelist = null,
        DatabaseLookupKeyInfo keyinfo = null)
    {
        var excludecount = excludelist == null ? 0 : excludelist.Count();

        var keyandtagsize = KeyAndTagSize(keyinfo);

        var tunnelidsize = tunnelid != null ? 4 : 0;

        AllocateBuffer(2 * 32 + 1 + tunnelidsize + 2 + 32 * excludecount + keyandtagsize);
        var writer = new I2PBufferCursor(Payload);

        writer.WriteBlock(key.Hash);
        writer.WriteBlock(tunnelgw.Hash);

        var forceflags = flags;
        if (keyinfo != null)
        {
            forceflags &= ~LookupTypes.Encryption;
            forceflags &= ~LookupTypes.Ecies;

            forceflags |= keyinfo.EncryptionFlag ? LookupTypes.Encryption : 0;
            forceflags |= keyinfo.EciesFlag ? LookupTypes.Ecies : 0;
        }

        if (tunnelid != null)
            forceflags |= LookupTypes.Tunnel;
        else
            forceflags &= ~LookupTypes.Tunnel;
        writer.WriteByte((byte)forceflags);

        if (tunnelid != null) writer.WriteUInt32BigEndian(tunnelid);

        if (excludecount > 0)
        {
            writer.WriteUInt16BigEndian((ushort)excludecount);
            foreach (var addr in excludelist) writer.WriteBlock(addr.Hash);
        }
        else
        {
            writer.WriteUInt16LittleEndian(0);
        }

        WriteKeyAndTags(writer, keyinfo);
    }

    public DatabaseLookupMessage(
        I2PIdentHash key,
        I2PIdentHash from,
        LookupTypes flags,
        IEnumerable<I2PIdentHash> excludelist,
        DatabaseLookupKeyInfo keyinfo)
    {
        var excludecount = excludelist == null ? 0 : excludelist.Count();

        var keyandtagsize = KeyAndTagSize(keyinfo);

        AllocateBuffer(2 * 32 + 1 + 2 + 32 * excludecount + keyandtagsize);
        var writer = new I2PBufferCursor(Payload);

        writer.WriteBlock(key.Hash);
        writer.WriteBlock(from.Hash);

        var forceflags = flags & ~LookupTypes.Tunnel;
        if (keyinfo != null)
        {
            forceflags &= ~LookupTypes.Encryption;
            forceflags &= ~LookupTypes.Ecies;

            forceflags |= keyinfo.EncryptionFlag ? LookupTypes.Encryption : 0;
            forceflags |= keyinfo.EciesFlag ? LookupTypes.Ecies : 0;
        }

        writer.WriteByte((byte)forceflags);

        if (excludecount > 0)
        {
            writer.WriteUInt16BigEndian((ushort)excludecount);
            foreach (var addr in excludelist) writer.WriteBlock(addr.Hash);
        }
        else
        {
            writer.WriteUInt16LittleEndian(0);
        }

        WriteKeyAndTags(writer, keyinfo);
    }

    public DatabaseLookupMessage(
        I2PIdentHash key,
        I2PIdentHash from,
        LookupTypes flags,
        IEnumerable<I2PIdentHash> excludelist)
    {
        var excludecount = excludelist == null ? 0 : excludelist.Count();

        AllocateBuffer(2 * 32 + 1 + 2 + 32 * excludecount);
        var writer = new I2PBufferCursor(Payload);

        writer.WriteBlock(key.Hash);
        writer.WriteBlock(from.Hash);
        writer.WriteByte((byte)(flags & ~LookupTypes.Tunnel));

        if (excludecount > 0)
        {
            writer.WriteUInt16BigEndian((ushort)excludecount);
            foreach (var addr in excludelist) writer.WriteBlock(addr.Hash);
        }
        else
        {
            writer.WriteUInt16LittleEndian(0);
        }
    }

    public override MessageTypes MessageType => MessageTypes.DatabaseLookup;

    public I2PIdentHash Key
    {
        get
        {
            if (CachedKey == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedKey;
        }
    }

    public I2PIdentHash From
    {
        get
        {
            if (CachedKey == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedFrom;
        }
    }

    public LookupTypes LookupType
    {
        get
        {
            if (CachedKey == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedLookupType;
        }
    }

    public I2PTunnelId TunnelId
    {
        get
        {
            if (CachedKey == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedTunnelId;
        }
    }

    public List<I2PIdentHash> ExcludeList
    {
        get
        {
            if (CachedKey == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedExcludeList;
        }
    }

    public I2PSessionKey ReplyKey
    {
        get
        {
            if (CachedKey == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedReplyKey;
        }
    }

    public List<I2PSessionTag> Tags
    {
        get
        {
            if (CachedKey == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedTags;
        }
    }

    /// <summary>Bytes the reply key and its tag list occupy on the wire.</summary>
    private static int KeyAndTagSize(DatabaseLookupKeyInfo keyinfo)
    {
        if (keyinfo is null) return 0;

        // 32 for the key, then the tag count byte and the tags — always both, never one.
        return 32 + 1 + (keyinfo.Tags?.Sum(t => t.Length) ?? 0);
    }

    private static void WriteKeyAndTags(I2PBufferCursor writer, DatabaseLookupKeyInfo keyinfo)
    {
        if (keyinfo is null) return;

        writer.WriteBlock(keyinfo.ReplyKey);
        writer.WriteByte((byte)(keyinfo.Tags?.Length ?? 0));
        foreach (var tag in keyinfo.Tags ?? Array.Empty<I2PByteBlock>()) writer.WriteBlock(tag);
    }

    private void UpdateCachedFields(I2PBufferCursor reader)
    {
        CachedKey = new I2PIdentHash(reader);
        CachedFrom = new I2PIdentHash(reader);
        CachedLookupType = (LookupTypes)reader.ReadByte();
        if ((CachedLookupType & LookupTypes.Tunnel) != 0) CachedTunnelId = new I2PTunnelId(reader);

        var excludecount = reader.ReadUInt16BigEndian();
        for (var i = 0; i < excludecount; ++i) CachedExcludeList.Add(new I2PIdentHash(reader));

        // The reply key and the tags travel together: a key with no tag cannot encrypt anything,
        // and i2pd's floodfill reads both whenever *either* flag is set — see the class comment.
        if ((CachedLookupType & (LookupTypes.Encryption | LookupTypes.Ecies)) != 0)
        {
            CachedReplyKey = new I2PSessionKey(reader);

            var tagcount = reader.ReadByte();
            var tagsize = (CachedLookupType & LookupTypes.Ecies) != 0 ? 8 : 32;

            for (var i = 0; i < tagcount; ++i) CachedTags.Add(new I2PSessionTag(reader, tagsize));
        }
    }

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("DatabaseLookup");

        return result.ToString();
    }
}