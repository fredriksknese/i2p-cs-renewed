using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using System.Diagnostics;
using I2PCore.TunnelLayer.I2NP.Messages;
using static I2PCore.TunnelLayer.I2NP.Messages.I2NpMessage;

namespace I2PCore.TunnelLayer.I2NP.Data
{
    public class Garlic : I2PType
    {
        public I2PByteBlock Data;

        public List<GarlicClove> Cloves = new();

        public Garlic( I2PBufferCursor reader )
        {
            ParseData( reader );
        }

        public Garlic( params GarlicClove[] cloves )
            : this( DefaultRtt(), cloves )
        {
        }

        public Garlic( I2PDate expiration, params GarlicClove[] cloves )
            : this( expiration, cloves.AsEnumerable() )
        {
        }

        public Garlic( IEnumerable<GarlicClove> cloves )
            : this( DefaultRtt(), cloves )
        {
        }

        private static I2PDate DefaultRtt()
        {
            return new I2PDate( DateTime.UtcNow.AddSeconds( 15 ) );
        }

        public Garlic( I2PDate expiration, IEnumerable<GarlicClove> cloves )
        {
            var buf = new ArrayBufferWriter<byte>();
            buf.WriteByte( (byte)cloves.Count() );
            foreach ( var clove in cloves ) clove.Write( buf );
            Cloves = cloves.ToList();

            // Certificate
            buf.WriteBytes( new byte[] { 0, 0, 0 } );

            buf.WriteUInt32BigEndian( BufUtils.RandomUint() );
            expiration.Write( buf );

            Data = new I2PByteBlock( buf.WrittenSpan.ToArray() );
            ParseData( new I2PBufferCursor( Data ) );
        }

        private void ParseData( I2PBufferCursor reader )
        {
            var startPos = reader.Position;

            var cloves = reader.ReadByte();
            for ( int i = 0; i < cloves; ++i )
            {
                Cloves.Add( new GarlicClove( reader ) );
            }
            reader.Seek( 3 + 4 + 8 ); // Garlic: Cert, MessageId, Expiration

            Data = new I2PByteBlock( reader.BaseArray, startPos, reader.DistanceFrom( startPos ) );
        }

        public void Write( IBufferWriter<byte> dest )
        {
            dest.WriteBlock( Data );
        }

        public override string ToString()
        {
            return $"Garlic: {Cloves?.Count} cloves. {string.Join( ", ", Cloves )}";
        }

        public static GarlicMessage EgEncryptGarlic(
                Garlic msg,
                I2PPublicKey pubkey,
                I2PSessionKey sessionkey,
                List<I2PSessionTag> newtags )
        {
            var cipher = new CbcBlockCipher( new AesEngine() );

            var payload = msg.ToByteArray();
            var dest = new I2PByteBlock( new byte[65536] );
            // Reserve header + 4 bytes for GarlicMessageLength
            var writer = new I2PBufferCursor( dest.BaseArray, dest.BaseArrayOffset + I2NpMaxHeaderSize + 4 );

            // ElGamal block
            var egbuf = new I2PByteBlock( new byte[222] );
            var sessionkeybuf = egbuf.Slice( 0, 32 );
            var preivbuf = egbuf.Slice( 32, 32 );
            var egpadding = egbuf.Slice( 64, 158 );

            egpadding.Randomize();
            preivbuf.Randomize();
            sessionkeybuf.CopyFrom( sessionkey.Key, 0 );

            var iv = new I2PByteBlock( I2PHashSha256.GetHash( preivbuf ), 0, 16 );

            ElGamalCrypto.Encrypt( writer, egbuf, pubkey, true );


            // AES block
            var aesstart = writer.CurrentBlock;
            var aesblock = new GarlicAesBlock( writer, newtags, null, new I2PBufferCursor( payload ) );

            cipher.Init( true, sessionkey.Key.ToParametersWithIv( iv ) );
            cipher.ProcessBytes( aesblock.DataBuf );

            var length = writer.Position - dest.BaseArrayOffset;
            dest.WriteUInt32BigEndian( (uint)( length - 4 ), I2NpMaxHeaderSize );

            return new GarlicMessage( new I2PBufferCursor( dest.BaseArray, dest.BaseArrayOffset + I2NpMaxHeaderSize, length ) );
        }

        public static (GarlicAesBlock,I2PSessionKey) EgDecryptGarlic(
                    GarlicMessage garlic,
                    I2PPrivateKey privkey )
        {
            var cipher = new CbcBlockCipher( new AesEngine() );
            var egdata = garlic.EgData;

            var egbuf = egdata.Slice( 0, 514 );
            var egheader = ElGamalCrypto.Decrypt( egbuf, privkey, true );

            var sessionkey = new I2PSessionKey( egheader.Slice( 0, 32 ) );
            var preiv = egheader.Slice( 32, 32 );
            var egpadding = egheader.Slice( 64, 158 );
            var aesbuf = egdata.Slice( 514 );

            var pivh = I2PHashSha256.GetHash( preiv );

            cipher.Init( false, sessionkey.Key.ToParametersWithIv( new I2PByteBlock( pivh, 0, 16 ) ) );
            cipher.ProcessBytes( aesbuf );

            GarlicAesBlock aesblock =
                    new GarlicAesBlock( new I2PBufferCursor( aesbuf ) );

            if ( !aesblock.VerifyPayloadHash() )
            {
                throw new ChecksumFailureException( "AES block hash check failed!" );
            }

            return (aesblock,sessionkey);
        }


        public static GarlicMessage AesEncryptGarlic(
                Garlic msg,
                I2PSessionKey sessionkey,
                I2PSessionTag tag,
                I2PSessionKey newsessionkey,
                List<I2PSessionTag> newtags )
        {
            var cipher = new CbcBlockCipher( new AesEngine() );

            var payload = msg.ToByteArray();
            var dest = new I2PByteBlock( new byte[65536] );
            // Reserve header + 4 bytes for GarlicMessageLength
            var writer = new I2PBufferCursor( dest.BaseArray, dest.BaseArrayOffset + I2NpMaxHeaderSize + 4 );

            // Tag as header
            writer.WriteBlock( tag.Value );

            // AES block
            var aesstart = writer.CurrentBlock;
            var aesblock = new GarlicAesBlock( writer, newtags, newsessionkey, new I2PBufferCursor( payload ) );

            var pivh = I2PHashSha256.GetHash( tag.Value );

            cipher.Init( true, sessionkey.Key.ToParametersWithIv( new I2PByteBlock( pivh, 0, 16 ) ) );
            cipher.ProcessBytes( aesblock.DataBuf );

            var length = writer.Position - dest.BaseArrayOffset;
            dest.WriteUInt32BigEndian( (uint)( length - 4 ), I2NpMaxHeaderSize );

            return new GarlicMessage( new I2PBufferCursor( dest.BaseArray, dest.BaseArrayOffset + I2NpMaxHeaderSize, length ) );
        }

        public static (GarlicAesBlock,I2PSessionKey) RetrieveAesBlock(
                GarlicMessage garlic,
                I2PPrivateKey privatekey,
                Func<I2PSessionTag,I2PSessionKey> findsessionkey )
        {
            GarlicAesBlock result;

            var cipher = new CbcBlockCipher( new AesEngine() );

            var tag = new I2PSessionTag( new I2PBufferCursor( garlic.EgData.BaseArray, garlic.EgData.BaseArrayOffset, 32 ) );
            var sessionkey = findsessionkey?.Invoke( tag );
#if LOG_ALL_LEASE_MGMT
            Logging.LogDebug( $"RetrieveAESBlock: Garlic: Session key {sessionkey?.Key.ToString() ?? "[null]"}" );
#endif
            if ( sessionkey != null )
            {
                var aesbuf = garlic.EgData.Slice( 32 );
                var pivh = I2PHashSha256.GetHash( tag.Value );

                cipher.Init( false, sessionkey.Key.ToParametersWithIv( new I2PByteBlock( pivh, 0, 16 ) ) );
                cipher.ProcessBytes( aesbuf );

                try
                {
                    result = new GarlicAesBlock( new I2PBufferCursor( aesbuf ) );

                    if ( !result.VerifyPayloadHash() )
                    {
                        Logging.LogDebug( "Garlic: DecryptMessage: AES block SHA256 check failed." );
                        return (null,null);
                    }

                    return (result,sessionkey);
                }
                catch ( ArgumentException ex )
                {
                    Logging.Log( "Garlic", ex );
                }
                catch ( Exception ex )
                {
                    Logging.Log( "Garlic", ex );
                    return (null,null);
                }
            }

#if LOG_ALL_LEASE_MGMT
            Logging.LogDebug( "RetrieveAESBlock: Garlic: No session key. Using ElGamal to decrypt." );
#endif

            try
            {
                (result,sessionkey) = Garlic.EgDecryptGarlic( garlic, privatekey );
#if LOG_ALL_LEASE_MGMT
                Logging.LogDebug( $"RetrieveAESBlock: Garlic: EG session key {sessionkey?.Key.ToString() ?? "[null]"}" );
#endif
            }
            catch ( ChecksumFailureException ex )
            {
                Logging.LogDebug( "RetrieveAESBlock: Garlic: ElGamal DecryptMessage failed" );
                Logging.LogDebugData( $"RetrieveAESBlock: ReceivedSessions {ex}" );
                return (null,null);
            }
            catch ( ArgumentException ex )
            {
                Logging.LogDebug( $"RetrieveAESBlock: Garlic: {ex}" );
                throw;
            }
            catch
            {
                throw;
            }

            return (result,sessionkey);
        }
    }
}
