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
        /// Get the X25519 public key for ECIES communication (garlic, tunnel builds, etc).
        /// Per Java I2P MessageWrapper.wrap() and BuildRequestor.java:
        ///   key = to.getIdentity().getPublicKey();
        /// Always uses the router's identity public key, NOT the NTCP2/SSU2
        /// transport static key ('s' parameter). The NTCP2 's' key is a separate
        /// key pair used only for transport-level sessions.
        /// </summary>
        public byte[] GetECIESPublicKey()
        {
            // Use the identity public key
            var pubkey = Identity.PublicKey.ToByteArray();
            if ( pubkey.Length == 32 ) return pubkey;

            // For hybrid PQ keys (ML-KEM + X25519), extract the X25519 component (last 32 bytes)
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
