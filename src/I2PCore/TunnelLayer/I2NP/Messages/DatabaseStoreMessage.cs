#define USE_BC_GZIP

using System;
using System.IO;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Messages;

public class DatabaseStoreMessage : I2NpMessage
{
    public enum MessageContent : byte
    {
        RouterInfo = 0b000,
        LeaseSet = 0b001,
        LeaseSet2 = 0b011,
        EncryptedLeaseSet = 0b101,
        MetaLeaseSet = 0b111
    }

    private MessageContent CachedContentType;
    private ILeaseSet CachedLeaseSet;
    private I2PIdentHash CachedReplyGateway;
    private uint CachedReplyToken;
    private uint CachedReplyTunnelId;

    private I2PIdentHash CachedRouterId;
    private I2PRouterInfo CachedRouterInfo;

    public DatabaseStoreMessage(
        I2PRouterInfo info,
        uint replytoken,
        I2PIdentHash replygw,
        I2PTunnelId replytunnelid)
    {
        I2PByteBlock msb;

#if USE_BC_GZIP
        msb = LzUtils.BcgZipCompressNew(new I2PByteBlock(info.ToByteArray()));
#else
            using ( var ms = new MemoryStream() )
            {
                var buf = info.ToByteArray();

                using ( var gzs = new GZipStream( ms, CompressionMode.Compress ) )
                {
                    gzs.Write( buf, 0, buf.Length );
                    gzs.Flush();
                }

                msb = new I2PByteBlock( ms.ToArray() );
            }
#endif

        var len = 32 + 1 + 4 + 2 + msb.Length + (replytoken != 0 ? 4 + 32 : 0);
        AllocateBuffer(len);
        var writer = new I2PBufferCursor(Payload);

        writer.WriteBlock(info.Identity.IdentHash.Hash);
        writer.WriteByte((byte)MessageContent.RouterInfo);
        writer.WriteUInt32BigEndian(replytoken);
        if (replytoken != 0)
        {
            writer.WriteUInt32BigEndian(replytunnelid);
            if (replygw == null || replygw.Hash.Length != 32)
                throw new FormatException("ReplyGateway has to be 32 bytes long!");
            writer.WriteBlock(replygw.Hash);
        }

        writer.WriteUInt16BigEndian((ushort)msb.Length);
        writer.WriteBlock(msb);
        UpdateCachedFields(new I2PBufferCursor(Payload));
    }

    public DatabaseStoreMessage(I2PRouterInfo info) : this(info, 0, null, 0)
    {
    }

    public DatabaseStoreMessage(
        ILeaseSet leaseset,
        uint replytoken,
        I2PIdentHash replygw,
        I2PTunnelId replytunnelid)
    {
        var ls = leaseset.ToByteArray();

        AllocateBuffer(32 + 5 + (replytoken != 0 ? 4 + 32 : 0) + ls.Length);
        var writer = new I2PBufferCursor(Payload);

        writer.WriteBlock(leaseset.Destination.IdentHash.Hash);
        writer.WriteByte((byte)leaseset.MessageType);
        writer.WriteUInt32BigEndian(replytoken);
        if (replytoken != 0)
        {
            writer.WriteUInt32BigEndian(replytunnelid);
            if (replygw == null || replygw.Hash.Length != 32)
                throw new FormatException("ReplyGateway has to be 32 bytes long!");
            writer.WriteBlock(replygw.Hash);
        }

        writer.WriteBytes(ls);
        UpdateCachedFields(new I2PBufferCursor(Payload));
    }

    public DatabaseStoreMessage(ILeaseSet leaseset) : this(leaseset, 0, null, 0)
    {
    }

    public DatabaseStoreMessage(I2PBufferCursor reader)
    {
        var start = new I2PBufferCursor(reader.BaseArray, reader.BaseArrayOffset);
        UpdateCachedFields(reader);
        SetBuffer(start, reader);
    }

    public override MessageTypes MessageType => MessageTypes.DatabaseStore;

    public I2PIdentHash Key
    {
        get
        {
            if (CachedRouterId == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedRouterId;
        }
    }

    public MessageContent Content
    {
        get
        {
            if (CachedRouterId == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedContentType;
        }
    }

    public uint ReplyToken
    {
        get
        {
            if (CachedRouterId == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedReplyToken;
        }
    }

    public uint ReplyTunnelId
    {
        get
        {
            if (CachedRouterId == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedReplyTunnelId;
        }
    }

    public I2PIdentHash ReplyGateway
    {
        get
        {
            if (CachedRouterId == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedReplyGateway;
        }
    }

    public I2PRouterInfo RouterInfo
    {
        get
        {
            if (CachedRouterId == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedRouterInfo;
        }
    }

    public ILeaseSet LeaseSet
    {
        get
        {
            if (CachedRouterId == null) UpdateCachedFields(new I2PBufferCursor(Payload));
            return CachedLeaseSet;
        }
    }

    private void UpdateCachedFields(I2PBufferCursor reader)
    {
        CachedRouterId = new I2PIdentHash(reader);
        CachedContentType = (MessageContent)reader.ReadByte();
        CachedReplyToken = reader.ReadUInt32BigEndian();
        if (CachedReplyToken != 0)
        {
            CachedReplyTunnelId = reader.ReadUInt32BigEndian();
            CachedReplyGateway = new I2PIdentHash(reader);
        }

        switch (CachedContentType)
        {
            case MessageContent.RouterInfo:
                var length = reader.ReadUInt16BigEndian();

#if USE_BC_GZIP
                CachedRouterInfo = new I2PRouterInfo(
                    new I2PBufferCursor(LzUtils.BcgZipDecompressNew(new I2PByteBlock(reader.BaseArray,
                        reader.BaseArrayOffset, length))), true);
#else
                    using ( var ms = new MemoryStream() )
                    {
                        ms.Write( reader.BaseArray, reader.BaseArrayOffset, length );
                        ms.Position = 0;

                        using ( var gzs = new GZipStream( ms, CompressionMode.Decompress ) )
                        {
                            var gzdata = StreamUtils.Read( gzs );
                            CachedRouterInfo = new I2PRouterInfo( new I2PBufferCursor( gzdata ), true );
                        }
                    }
#endif

                reader.Seek(length);
                break;

            case MessageContent.LeaseSet:
                CachedLeaseSet = new I2PLeaseSet(reader);
                break;

            case MessageContent.LeaseSet2:
                CachedLeaseSet = new I2PLeaseSet2(reader);
                break;

            case MessageContent.EncryptedLeaseSet:
                CachedLeaseSet = new I2PEncryptedLeaseSet(reader);
                break;

            case MessageContent.MetaLeaseSet:
                CachedLeaseSet = new I2PMetaLeaseSet(reader);
                break;

            default:
                try
                {
                    NetDb.Inst.Statistics.DestinationInformationFaulty(CachedRouterId);
                }
                catch
                {
                }

                throw new InvalidDataException(
                    $"DatabaseStoreMessage: {CachedContentType} not supported for destination {CachedRouterId.Id32Short}");
        }
    }

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine($"DatabaseStore {Content}, key {Key.Id32Short}");
        result.AppendLine($"Reply token {ReplyToken}, tunnel {ReplyTunnelId}, GW {ReplyGateway}");

        switch (CachedContentType)
        {
            case MessageContent.RouterInfo:
                result.AppendLine($"{RouterInfo}");
                break;

            case MessageContent.LeaseSet:
                result.AppendLine($"{LeaseSet}");
                break;

            case MessageContent.LeaseSet2:
                result.AppendLine("LeaseSet2");
                break;

            case MessageContent.EncryptedLeaseSet:
                result.AppendLine("EncryptedLeaseSet");
                break;

            case MessageContent.MetaLeaseSet:
                result.AppendLine("MetaLeaseSet");
                break;

            default:
                result.AppendLine("Unknown content type");
                break;
        }

        return result.ToString();
    }
}