using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Utilities.Encoders;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2PRouterInfo : I2PType
    {
        public I2PRouterIdentity Identity;
        public I2PDate PublishedDate;
        public I2PRouterAddress[] Addresses;
        public I2PMapping Options;
        public I2PSignature Signature;

        private BufLen Data;

        public I2PRouterInfo(
            I2PRouterIdentity identity,
            I2PDate publisheddate,
            I2PRouterAddress[] addresses,
            I2PMapping options,
            I2PSigningPrivateKey privskey )
        {
            Identity = identity;
            PublishedDate = publisheddate;
            Addresses = addresses;
            Options = options;

            var dest = new BufRefStream();
            Identity.Write( dest );
            PublishedDate.Write( dest );
            dest.Write( (byte)Addresses.Length );
            foreach ( var addr in Addresses )
            {
                addr.Write( dest );
            }
            dest.Write( 0 ); // Always zero
            Options.Write( dest );
            Data = new BufLen( dest.ToArray() );

            Signature = new I2PSignature( new BufRefLen( I2PSignature.DoSign( privskey, Data ) ), privskey.Certificate );
        }

        public I2PRouterInfo( BufRef reader, bool verifysig )
        {
            var startview = new BufRef( reader );

            Identity = new I2PRouterIdentity( reader );
            PublishedDate = new I2PDate( reader );

            int addrcount = reader.Read8();
            var addresses = new List<I2PRouterAddress>();
            for ( int i = 0; i < addrcount; ++i )
            {
                addresses.Add( new I2PRouterAddress( reader ) );
            }
            Addresses = addresses.ToArray();

            reader.Seek( reader.Read8() * 32 ); // peer_size. Unused.

            Options = new I2PMapping( reader );
            var payloadend = new BufRef( reader );

            Data = new BufLen( startview, 0, reader - startview );
            Signature = new I2PSignature( reader, Identity.Certificate );

            if ( verifysig )
            {
                var versig = VerifySignature();
                if ( !versig )
                {
                    throw new InvalidOperationException( "I2PRouterInfo signature check failed" );
                }
            }
        }

        public bool VerifySignature()
        {
            var versig = I2PSignature.SupportedSignatureType( Identity.Certificate.SignatureType );

            if ( !versig )
            {
                Logging.LogDebug( "RouterInfo: VerifySignature false. Not supported: " + Identity.Certificate.SignatureType.ToString() );
                return false;
            }

            versig = I2PSignature.DoVerify( Identity.SigningPublicKey, Signature, Data );
            if ( !versig )
            {
                Logging.LogDebug( "RouterInfo: I2PSignature.DoVerify failed: " + Identity.Certificate.SignatureType.ToString() );
                return false;
            }

            return true;
        }

        /// <summary>
        /// Get the X25519 static public key for ECIES communication.
        /// Per I2P spec, the Noise N handshake uses the router's NTCP2/SSU2
        /// static key ("s" parameter from RouterInfo address), NOT the
        /// identity's encryption public key.
        /// </summary>
        public byte[] GetECIESPublicKey()
        {
            if ( Addresses != null )
            {
                // Try NTCP2 "s" parameter first (preferred)
                var ntcp2Addr = Addresses.FirstOrDefault( a =>
                    ( a.TransportStyle == "NTCP2" || a.TransportStyle == "NTCP" ) &&
                    a.Options.Contains( "s" ) );

                if ( ntcp2Addr != null )
                {
                    try
                    {
                        var sKey = Utils.FreenetBase64.Decode( ntcp2Addr.Options["s"] );
                        if ( sKey.Length == 32 ) return sKey;
                    }
                    catch ( Exception ) { }
                }

                // Try SSU2 "s" parameter as fallback
                var ssu2Addr = Addresses.FirstOrDefault( a =>
                    a.TransportStyle == "SSU2" && a.Options.Contains( "s" ) );

                if ( ssu2Addr != null )
                {
                    try
                    {
                        var sKey = Utils.FreenetBase64.Decode( ssu2Addr.Options["s"] );
                        if ( sKey.Length == 32 ) return sKey;
                    }
                    catch ( Exception ) { }
                }
            }

            // Fallback: try the identity public key
            var pubkey = Identity.PublicKey.ToByteArray();
            if ( pubkey.Length == 32 ) return pubkey;

            var keyType = Identity.Certificate.PublicKeyType;
            if ( keyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
                 keyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
                 keyType == I2PKeyType.KeyTypes.MLKEM1024_X25519 )
            {
                return pubkey.Skip( pubkey.Length - 32 ).Take( 32 ).ToArray();
            }

            return null;
        }

        public void Write( BufRefStream dest )
        {
            Data.WriteTo( dest );
            Signature.Write( dest );
        }

        public override string ToString()
        {
            var result = new StringBuilder();

            result.AppendLine( "I2PRouterInfo" );

            result.AppendLine( "Identity     : " + Identity.IdentHash.Id32 );
            result.AppendLine( "Identity     : " + Identity.ToString() );
            result.AppendLine( "Publish date : " + PublishedDate.ToString() );

            foreach( var addr in Addresses )
            {
                result.AppendLine( "Address      : " + addr.ToString() );
            }

            result.AppendLine( Options.ToString() );
            if ( Signature == null )
            {
                result.AppendLine( "Signature    : member (null)" );
            }
            else
            {
                result.AppendLine( "Signature    : " + ( Signature.Sig == null ? "(null)" :
                    " [" + Signature.Sig.Length + "] " + Signature.ToString() ) );
            }

            return result.ToString();
        }
    }
}
