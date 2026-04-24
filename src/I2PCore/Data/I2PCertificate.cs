using System;
using System.IO;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2PCertificate : I2PType
    {
        public enum CertTypes: byte { Null = 0, Hashcash = 1, Hidden = 2, Signed = 3, Multiple = 4, Key = 5 }

        public CertTypes CType { get { return (CertTypes)Data[0]; } set { Data[0] = (byte)value; } }
        public I2PSigningKey.SigningKeyTypes KeySignatureType
        {
            get
            {
                if ( Payload.Length < 4 ) return I2PSigningKey.SigningKeyTypes.Invalid;
                return (I2PSigningKey.SigningKeyTypes)Payload.PeekFlip16( 0 );
            }
            protected set
            {
                if ( Payload.Length < 4 ) throw new InvalidDataException( "Cert payload not 4 bytes for Key cert!" );
                Payload.PokeFlip16( (ushort)value, 0 );
            }
        }

        public I2PSigningKey.KeyTypes KeyPublicKeyType
        {
            get
            {
                if ( Payload.Length < 4 ) return I2PKeyType.KeyTypes.Invalid;
                return (I2PSigningKey.KeyTypes)Payload.PeekFlip16( 2 );
            }
            set
            {
                if ( Payload.Length < 4 ) throw new InvalidDataException( "Cert payload not 4 bytes for Key cert!" );
                Payload.PokeFlip16( (ushort)value, 2 );
            }
        }

        private int NotImplementedPublicKeyLength;

        public ushort PayloadLength { get { return Data.PeekFlip16( 1 ); } protected set { Data.PokeFlip16( value, 1 ); } }
        public BufLen Payload { get { return new BufLen( Data, 3, PayloadLength ); } }
        public BufLen PayloadExtraKeySpace 
        { 
            get 
            {
                if ( PayloadLength < 4 ) return null;
                return new BufLen( Data, 7, PayloadLength - 4 ); 
            } 
        }

        private BufLen Data;

        public I2PCertificate()
        {
            Data = new BufLen( new byte[3] );
            CType = CertTypes.Null;
        }

        public I2PCertificate( I2PSigningKey.SigningKeyTypes signkeytype )
        {
            ushort pllen = 0;

            switch ( signkeytype )
            {
                case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519ph:
                case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                    pllen = 4;
                    break;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                    pllen = 4 + 4;
                    break;

                case I2PSigningKey.SigningKeyTypes.MlDsa44:
                    // ML-DSA-44 public key is 1312 bytes. Standard KeysAndCert has 128 bytes
                    // for signing public key, so excess = 1312 - 128 = 1184 bytes in cert payload.
                    pllen = (ushort)(4 + (1312 - 128));
                    break;
            }

            switch ( signkeytype )
            {
                case I2PSigningKey.SigningKeyTypes.DsaSha1:
                    Data = new BufLen( new byte[3] );
                    PayloadLength = pllen;
                    CType = CertTypes.Null;
                    break;

                default:
                    Data = new BufLen( new byte[3 + pllen] );
                    PayloadLength = pllen;
                    CType = CertTypes.Key;
                    KeySignatureType = signkeytype;
                    break;
            }
        }

        public I2PCertificate( I2PPublicKey.KeyTypes keytype, int keylen = -1 )
        {
            Data = new BufLen( new byte[7] { (byte)CertTypes.Key, 0, 4, 0, 0, 0, 0 } );

            switch ( keytype )
            {
                case I2PKeyType.KeyTypes.ElGamal2048:
                case I2PKeyType.KeyTypes.P256:
                case I2PKeyType.KeyTypes.P384:
                case I2PKeyType.KeyTypes.P521:
                case I2PKeyType.KeyTypes.X25519:
                case I2PKeyType.KeyTypes.MLKEM512_X25519:
                case I2PKeyType.KeyTypes.MLKEM768_X25519:
                case I2PKeyType.KeyTypes.MLKEM1024_X25519:
                    KeyPublicKeyType = keytype;
                    break;

                default:
                    KeyPublicKeyType = I2PKeyType.KeyTypes.NotImplemented;
                    NotImplementedPublicKeyLength = keylen;
                    Logging.LogWarning( $"I2PCertificate: Public key type {keytype} not implemented" );
                    break;
            }
        }

        public I2PCertificate( BufRef buf )
        {
            Data = new BufLen( buf, 0, 3 ); // Get CertLength
            Data = buf.ReadBufLen( CertLength );
        }

        public I2PSigningKey.SigningKeyTypes SignatureType
        {
            get
            {
                switch ( CType )
                {
                    case CertTypes.Null:
                        return I2PSigningKey.SigningKeyTypes.DsaSha1;

                    case CertTypes.Key:
                        if ( Payload.Length < 4 ) throw new InvalidDataException( "Cert payload not 4 bytes for Key cert!" );
                        return (I2PSigningKey.SigningKeyTypes)Payload.PeekFlip16( 0 );

                    default:
                        Logging.LogWarning( $"I2PCertificate: Unknown cert type {CType} for SignatureType" );
                        return I2PSigningKey.SigningKeyTypes.Invalid;
                }
            }
        }

        public I2PKeyType.KeyTypes PublicKeyType
        {
            get
            {
                switch ( CType )
                {
                    case CertTypes.Null:
                        return I2PKeyType.KeyTypes.ElGamal2048;

                    case CertTypes.Key:
                        if ( Payload.Length < 4 ) throw new InvalidDataException( "Cert payload not 4 bytes for Key cert!" );
                        return (I2PKeyType.KeyTypes)Payload.PeekFlip16( 2 );

                    default:
                        Logging.LogWarning( $"I2PCertificate: Unknown cert type {CType} for PublicKeyType" );
                        return I2PKeyType.KeyTypes.Invalid;
                }
            }
        }

        public int CertLength { get { return 3 + PayloadLength; } }

        public int PublicKeyLength
        {
            get
            {
                var pkt = PublicKeyType;
                if ( pkt == I2PKeyType.KeyTypes.NotImplemented ) return NotImplementedPublicKeyLength;

                return I2PKeyType.PublicKeyLength( pkt );
            }
        }
        public int PrivateKeyLength
        {
            get
            {
                return I2PKeyType.PrivateKeyLength( PublicKeyType );
            }
        }

        public int SigningPublicKeyLength
        {
            get
            {
                switch ( CType )
                {
                    case CertTypes.Null:
                        return 128;

                    case CertTypes.Key:
                        return I2PSigningKey.SigningPublicKeyLength( SignatureType );

                    default:
                        Logging.LogWarning( $"I2PCertificate: Unknown cert type {CType} for SigningPublicKeyLength" );
                        return 128; // Default DSA length
                }
            }
        }

        public int SigningPrivateKeyLength
        {
            get
            {
                switch ( CType )
                {
                    case CertTypes.Null:
                        return 20;

                    case CertTypes.Key:
                        return I2PSigningKey.SigningPrivateKeyLength( SignatureType );

                    default:
                        Logging.LogWarning( $"I2PCertificate: Unknown cert type {CType} for SigningPrivateKeyLength" );
                        return 20; // Default DSA length
                }
            }
        }

        public int SignatureLength
        {
            get
            {
                switch ( CType )
                {
                    case CertTypes.Null:
                        return 40;

                    case CertTypes.Key:
                        return I2PSigningKey.SignatureLength( SignatureType );

                    default:
                        Logging.LogWarning( $"I2PCertificate: Unknown cert type {CType} for SignatureLength" );
                        return 40; // Default DSA length
                }
            }
        }

        public int RouterIdentitySize
        {
            get
            {
                return PublicKeyLength + 128 + CertLength;
            }
        }

        public void Write( BufRefStream dest )
        {
            Data.WriteTo( dest );
        }

        public override string ToString()
        {
            return $"{CType} {PublicKeyType} {SignatureType}";
        }
    }
}
