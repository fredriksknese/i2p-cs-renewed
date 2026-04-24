using System;
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
        public BufLen Data;

        public List<GarlicClove> Cloves = new();

        public Garlic( BufRefLen reader )
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
            BufRefStream buf = new BufRefStream();
            buf.Write( (byte)cloves.Count() );
            foreach ( var clove in cloves ) clove.Write( buf );
            Cloves = cloves.ToList();

            // Certificate
            buf.Write( new byte[] { 0, 0, 0 } );

            buf.Write( (BufRefLen)BufUtils.Flip32Bl( BufUtils.RandomUint() ) );
            expiration.Write( buf );

            Data = new BufLen( buf.ToArray() );
            ParseData( new BufRefLen( Data ) );
        }

        private void ParseData( BufRefLen reader )
        {
            var start = new BufLen( reader );

            var cloves = reader.Read8();
            for ( int i = 0; i < cloves; ++i )
            {
                Cloves.Add( new GarlicClove( reader ) );
            }
            reader.Seek( 3 + 4 + 8 ); // Garlic: Cert, MessageId, Expiration

            Data = new BufLen( start, 0, reader - start );
        }

        public void Write( BufRefStream dest )
        {
            Data.WriteTo( dest );
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
            var dest = new BufLen( new byte[65536] );
            // Reserve header + 4 bytes for GarlicMessageLength
            var writer = new BufRefLen( dest, I2NpMaxHeaderSize + 4 );

            // ElGamal block
            var egbuf = new BufLen( new byte[222] );
            var sessionkeybuf = new BufLen( egbuf, 0, 32 );
            var preivbuf = new BufLen( egbuf, 32, 32 );
            var egpadding = new BufLen( egbuf, 64, 158 );

            egpadding.Randomize();
            preivbuf.Randomize();
            sessionkeybuf.Poke( sessionkey.Key, 0 );

            var iv = new BufLen( I2PHashSha256.GetHash( preivbuf ), 0, 16 );

            ElGamalCrypto.Encrypt( writer, egbuf, pubkey, true );

            // AES block
            var aesstart = new BufLen( writer );
            var aesblock = new GarlicAesBlock( writer, newtags, null, new BufRefLen( payload ) );

            cipher.Init( true, sessionkey.Key.ToParametersWithIv( iv ) );
            cipher.ProcessBytes( aesblock.DataBuf );

            var length = writer - dest;
            dest.PokeFlip32( (uint)( length - 4 ), I2NpMaxHeaderSize );

            return new GarlicMessage( new BufRefLen( dest, I2NpMaxHeaderSize, length ) );
        }

        public static (GarlicAesBlock,I2PSessionKey) EgDecryptGarlic( 
                    GarlicMessage garlic, 
                    I2PPrivateKey privkey )
        {
            var cipher = new CbcBlockCipher( new AesEngine() );
            var egdata = garlic.EgData;

            var egbuf = new BufLen( egdata, 0, 514 );
            var egheader = ElGamalCrypto.Decrypt( egbuf, privkey, true );

            var sessionkey = new I2PSessionKey( new BufLen( egheader, 0, 32 ) );
            var preiv = new BufLen( egheader, 32, 32 );
            var egpadding = new BufLen( egheader, 64, 158 );
            var aesbuf = new BufLen( egdata, 514 );

            var pivh = I2PHashSha256.GetHash( preiv );

            cipher.Init( false, sessionkey.Key.ToParametersWithIv( new BufLen( pivh, 0, 16 ) ) );
            cipher.ProcessBytes( aesbuf );

            GarlicAesBlock aesblock =
                    new GarlicAesBlock( new BufRefLen( aesbuf ) );

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
            var dest = new BufLen( new byte[65536] );
            // Reserve header + 4 bytes for GarlicMessageLength
            var writer = new BufRefLen( dest, I2NpMaxHeaderSize + 4 );

            // Tag as header
            writer.Write( tag.Value );

            // AES block
            var aesstart = new BufLen( writer );
            var aesblock = new GarlicAesBlock( writer, newtags, newsessionkey, new BufRefLen( payload ) );

            var pivh = I2PHashSha256.GetHash( tag.Value );

            cipher.Init( true, sessionkey.Key.ToParametersWithIv( new BufLen( pivh, 0, 16 ) ) );
            cipher.ProcessBytes( aesblock.DataBuf );

            var length = writer - dest;
            dest.PokeFlip32( (uint)( length - 4 ), I2NpMaxHeaderSize );

            return new GarlicMessage( new BufRefLen( dest, I2NpMaxHeaderSize, length ) );
        }

        public static (GarlicAesBlock,I2PSessionKey) RetrieveAesBlock(
                GarlicMessage garlic,
                I2PPrivateKey privatekey,
                Func<I2PSessionTag,I2PSessionKey> findsessionkey )
        {
            GarlicAesBlock result;

            var cipher = new CbcBlockCipher( new AesEngine() );

            var tag = new I2PSessionTag( new BufRefLen( garlic.EgData, 0, 32 ) );
            var sessionkey = findsessionkey?.Invoke( tag );
#if LOG_ALL_LEASE_MGMT
            Logging.LogDebug( $"RetrieveAESBlock: Garlic: Session key {sessionkey?.Key.ToString() ?? "[null]"}" );
#endif
            if ( sessionkey != null )
            {
                var aesbuf = new BufLen( garlic.EgData, 32 );
                var pivh = I2PHashSha256.GetHash( tag.Value );

                cipher.Init( false, sessionkey.Key.ToParametersWithIv( new BufLen( pivh, 0, 16 ) ) );
                cipher.ProcessBytes( aesbuf );

                try
                {
                    result = new GarlicAesBlock( new BufRefLen( aesbuf ) );

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
