using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TunnelLayer.I2NP.Data;

namespace I2PCore.TunnelLayer.I2NP.Messages
{
    public class DatabaseLookupMessage : I2NpMessage
    {
        public override MessageTypes MessageType { get { return MessageTypes.DatabaseLookup; } }

        [Flags]
        public enum LookupTypes: byte {
            Tunnel          = 0b00000001,
            Encryption      = 0b00000010,
            Normal          = 0b00000000,
            LeaseSet        = 0b00000100,
            RouterInfo      = 0b00001000,
            Exploration     = 0b00001100,
            Ecies           = 0b00010000,
        }

        private I2PIdentHash CachedKey;
        public I2PIdentHash Key
        {
            get
            {
                if ( CachedKey == null ) UpdateCachedFields( new I2PBufferCursor( Payload ) );
                return CachedKey;
            }
        }

        private I2PIdentHash CachedFrom;
        public I2PIdentHash From
        {
            get
            {
                if ( CachedKey == null ) UpdateCachedFields( new I2PBufferCursor( Payload ) );
                return CachedFrom;
            }
        }

        private LookupTypes CachedLookupType;
        public LookupTypes LookupType
        {
            get
            {
                if ( CachedKey == null ) UpdateCachedFields( new I2PBufferCursor( Payload ) );
                return CachedLookupType;
            }
        }

        private I2PTunnelId CachedTunnelId;
        public I2PTunnelId TunnelId
        {
            get
            {
                if ( CachedKey == null ) UpdateCachedFields( new I2PBufferCursor( Payload ) );
                return CachedTunnelId;
            }
        }

        private List<I2PIdentHash> CachedExcludeList = new();
        public List<I2PIdentHash> ExcludeList
        {
            get
            {
                if ( CachedKey == null ) UpdateCachedFields( new I2PBufferCursor( Payload ) );
                return CachedExcludeList;
            }
        }

        private I2PSessionKey CachedReplyKey;
        public I2PSessionKey ReplyKey
        {
            get
            {
                if ( CachedKey == null ) UpdateCachedFields( new I2PBufferCursor( Payload ) );
                return CachedReplyKey;
            }
        }

        private List<I2PSessionTag> CachedTags = new();
        public List<I2PSessionTag> Tags
        {
            get
            {
                if ( CachedKey == null ) UpdateCachedFields( new I2PBufferCursor( Payload ) );
                return CachedTags;
            }
        }

        public DatabaseLookupMessage( I2PBufferCursor reader )
        {
            var start = new I2PBufferCursor( reader.BaseArray, reader.BaseArrayOffset );
            UpdateCachedFields( reader );
            SetBuffer( start, reader );
        }

        public DatabaseLookupMessage( I2PIdentHash key, I2PIdentHash from, LookupTypes flags )
        {
            AllocateBuffer( 2 * 32 + 1 + 2 );
            var writer = new I2PBufferCursor( Payload );

            writer.WriteBlock( key.Hash );
            writer.WriteBlock( from.Hash );
            writer.WriteByte( (byte)( flags & ~LookupTypes.Tunnel ) );
            writer.WriteUInt16LittleEndian( 0 );
        }

        public DatabaseLookupMessage(
            I2PIdentHash key,
            I2PIdentHash tunnelgw,
            I2PTunnelId tunnelid,
            LookupTypes flags,
            IEnumerable<I2PIdentHash> excludelist = null,
            DatabaseLookupKeyInfo keyinfo = null )
        {
            var excludecount = excludelist == null ? 0 : excludelist.Count();

            var keyandtagsize = keyinfo is null ? 0 : keyinfo.ReplyKey.Length + 1 + keyinfo.Tags.Sum( t => t.Length );

            AllocateBuffer( 2 * 32 + 1 + 4 + 2 + 32 * excludecount + keyandtagsize );
            var writer = new I2PBufferCursor( Payload );

            writer.WriteBlock( key.Hash );
            writer.WriteBlock( tunnelgw.Hash );

            var forceflags = flags | LookupTypes.Tunnel;
            if ( keyinfo != null )
            {
                forceflags &= ~LookupTypes.Encryption;
                forceflags &= ~LookupTypes.Ecies;

                forceflags |= keyinfo.EncryptionFlag ? LookupTypes.Encryption : 0;
                forceflags |= keyinfo.EciesFlag ? LookupTypes.Ecies : 0;
            }
            writer.WriteByte( (byte)forceflags );

            writer.WriteUInt32BigEndian( tunnelid );

            if ( excludecount > 0 )
            {
                writer.WriteUInt16BigEndian( (ushort)excludecount );
                foreach ( var addr in excludelist )
                {
                    writer.WriteBlock( addr.Hash );
                }
            }
            else
            {
                writer.WriteUInt16LittleEndian( 0 );
            }

            if ( keyinfo is null ) return;

            writer.WriteBlock( keyinfo.ReplyKey );
            writer.WriteByte( (byte)keyinfo.Tags.Length );
            foreach( var tag in keyinfo.Tags )
            {
                writer.WriteBlock( tag );
            }
        }

        public DatabaseLookupMessage(
            I2PIdentHash key,
            I2PIdentHash from,
            LookupTypes flags,
            IEnumerable<I2PIdentHash> excludelist,
            DatabaseLookupKeyInfo keyinfo )
        {
            var excludecount = excludelist == null ? 0 : excludelist.Count();

            var keyandtagsize = keyinfo is null ? 0 : keyinfo.ReplyKey.Length + 1 + keyinfo.Tags.Sum( t => t.Length );

            AllocateBuffer( 2 * 32 + 1 + 2 + 32 * excludecount + keyandtagsize );
            var writer = new I2PBufferCursor( Payload );

            writer.WriteBlock( key.Hash );
            writer.WriteBlock( from.Hash );

            var forceflags = flags & ~LookupTypes.Tunnel;
            if ( keyinfo != null )
            {
                forceflags &= ~LookupTypes.Encryption;
                forceflags &= ~LookupTypes.Ecies;

                forceflags |= keyinfo.EncryptionFlag ? LookupTypes.Encryption : 0;
                forceflags |= keyinfo.EciesFlag ? LookupTypes.Ecies : 0;
            }
            writer.WriteByte( (byte)forceflags );

            if ( excludecount > 0 )
            {
                writer.WriteUInt16BigEndian( (ushort)excludecount );
                foreach ( var addr in excludelist )
                {
                    writer.WriteBlock( addr.Hash );
                }
            }
            else
            {
                writer.WriteUInt16LittleEndian( 0 );
            }

            if ( keyinfo is null ) return;

            writer.WriteBlock( keyinfo.ReplyKey );
            writer.WriteByte( (byte)keyinfo.Tags.Length );
            foreach( var tag in keyinfo.Tags )
            {
                writer.WriteBlock( tag );
            }
        }

        public DatabaseLookupMessage(
            I2PIdentHash key,
            I2PIdentHash from,
            LookupTypes flags,
            IEnumerable<I2PIdentHash> excludelist )
        {
            var excludecount = excludelist == null ? 0 : excludelist.Count();

            AllocateBuffer( 2 * 32 + 1 + 2 + 32 * excludecount );
            var writer = new I2PBufferCursor( Payload );

            writer.WriteBlock( key.Hash );
            writer.WriteBlock( from.Hash );
            writer.WriteByte( (byte)( flags & ~LookupTypes.Tunnel ) );

            if ( excludecount > 0 )
            {
                writer.WriteUInt16BigEndian( (ushort)excludecount );
                foreach ( var addr in excludelist )
                {
                    writer.WriteBlock( addr.Hash );
                }
            }
            else
            {
                writer.WriteUInt16LittleEndian( 0 );
            }
        }

        private void UpdateCachedFields( I2PBufferCursor reader )
        {
            CachedKey = new I2PIdentHash( reader );
            CachedFrom = new I2PIdentHash( reader );
            CachedLookupType = (LookupTypes)reader.ReadByte();
            if ( ( CachedLookupType & LookupTypes.Tunnel ) != 0 ) CachedTunnelId = new I2PTunnelId( reader );

            var excludecount = reader.ReadUInt16BigEndian();
            for ( int i = 0; i < excludecount; ++i )
            {
                CachedExcludeList.Add( new I2PIdentHash( reader ) );
            }

            if ( ( CachedLookupType & ( LookupTypes.Encryption | LookupTypes.Ecies ) ) != 0 )
            {
                CachedReplyKey = new I2PSessionKey( reader );

                var tagcount = reader.ReadByte();
                var tagsize = ( CachedLookupType & LookupTypes.Ecies ) != 0 ? 8 : 32;

                for ( int i = 0; i < tagcount; ++i )
                {
                    CachedTags.Add( new I2PSessionTag( reader, tagsize ) );
                }
            }
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "DatabaseLookup" );

            return result.ToString();
        }
    }
}
