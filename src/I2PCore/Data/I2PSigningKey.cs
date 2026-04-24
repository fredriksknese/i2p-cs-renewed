using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Math;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public abstract class I2PSigningKey : I2PKeyType
    {
        public enum SigningKeyTypes : ushort
        {
            Invalid = ushort.MaxValue,
            DsaSha1 = 0,
            EcdsaSha256P256 = 1,
            EcdsaSha384P384 = 2,
            EcdsaSha512P521 = 3,
            RsaSha2562048 = 4,
            RsaSha3843072 = 5,
            RsaSha5124096 = 6,
            EdDsaSha512Ed25519 = 7,
            EdDsaSha512Ed25519ph = 8,
            GostR34102012_256 = 9,
            GostR34102012_512 = 10,
            RedDsaSha512Ed25519 = 11,
            MlDsa44 = 12,
        }

        protected I2PSigningKey( I2PCertificate cert ): base( cert )
        {
        }

        public I2PSigningKey( BufRef reader, I2PCertificate cert ) : base( reader, cert ) 
        {
        }

        public I2PSigningKey( BigInteger key, I2PCertificate cert ) : base( cert )
        {
            var buf = key.ToByteArrayUnsigned();
            if ( buf.Length == KeySizeBytes )
            {
                Key = new BufLen( buf );
            }
            else
            {
                Key = new BufLen( new byte[KeySizeBytes] );
                Key.Poke( buf, KeySizeBytes - buf.Length );
            }
        }

        public I2PSigningKey( BufLen key, I2PCertificate cert )
            : base( cert )
        {
            if ( key.Length == KeySizeBytes )
            {
                Key = key;
            }
            else if ( key.Length < KeySizeBytes )
            {
                Key = new BufLen( new byte[KeySizeBytes] );
                Key.Poke( key, KeySizeBytes - key.Length );
            }
            else
            {
                Key = new BufLen( key, 0, KeySizeBytes );
            }
        }
        public static int SigningPublicKeyLength( I2PSigningKey.SigningKeyTypes skt )
        {
            switch ( skt )
            {
                case I2PSigningKey.SigningKeyTypes.DsaSha1:
                    return 128;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                    return 65;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                    return 97;

                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519ph:
                case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                    return 32;

                case I2PSigningKey.SigningKeyTypes.GostR34102012_256:
                    return 64;

                case I2PSigningKey.SigningKeyTypes.GostR34102012_512:
                    return 128;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                    return 133;

                case I2PSigningKey.SigningKeyTypes.RsaSha2562048:
                    return 256;

                case I2PSigningKey.SigningKeyTypes.RsaSha3843072:
                    return 384;

                case I2PSigningKey.SigningKeyTypes.RsaSha5124096:
                    return 512;

                case I2PSigningKey.SigningKeyTypes.MlDsa44:
                    return 1312;  // MLDSA44_PUBLIC_KEY_LENGTH

                default:
                    Logging.LogWarning( $"I2PSigningKey: Unknown signing key type {skt} for SigningPublicKeyLength" );
                    return 128; // Default fallback
            }
        }
        public static int SigningPrivateKeyLength( I2PSigningKey.SigningKeyTypes skt )
        {
            switch ( skt )
            {
                case I2PSigningKey.SigningKeyTypes.DsaSha1:
                    return 20;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                    return 32;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                    return 48;

                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519ph:
                case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                    return 32;

                case I2PSigningKey.SigningKeyTypes.GostR34102012_256:
                    return 32;

                case I2PSigningKey.SigningKeyTypes.GostR34102012_512:
                    return 64;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                    return 66;

                case I2PSigningKey.SigningKeyTypes.RsaSha2562048:
                    return 512;

                case I2PSigningKey.SigningKeyTypes.RsaSha3843072:
                    return 768;

                case I2PSigningKey.SigningKeyTypes.RsaSha5124096:
                    return 1024;

                case I2PSigningKey.SigningKeyTypes.MlDsa44:
                    return 2560;  // MLDSA44_PRIVATE_KEY_LENGTH

                default:
                    Logging.LogWarning( $"I2PSigningKey: Unknown signing key type {skt} for SigningPrivateKeyLength" );
                    return 20; // Default fallback
            }
        }
        public static int SignatureLength( I2PSigningKey.SigningKeyTypes skt )
        {
            switch ( skt )
            {
                case I2PSigningKey.SigningKeyTypes.DsaSha1:
                    return 40;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                    return 64;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                    return 96;

                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519ph:
                case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                    return 64;

                case I2PSigningKey.SigningKeyTypes.GostR34102012_256:
                    return 64;

                case I2PSigningKey.SigningKeyTypes.GostR34102012_512:
                    return 128;

                case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                    return 132;

                case I2PSigningKey.SigningKeyTypes.RsaSha2562048:
                    return 256;

                case I2PSigningKey.SigningKeyTypes.RsaSha3843072:
                    return 384;

                case I2PSigningKey.SigningKeyTypes.RsaSha5124096:
                    return 512;

                case I2PSigningKey.SigningKeyTypes.MlDsa44:
                    return 2420;  // MLDSA44_SIGNATURE_LENGTH

                default:
                    Logging.LogWarning( $"I2PSigningKey: Unknown signing key type {skt} for SignatureLength" );
                    return 40; // Default fallback
            }
        }
    }
}
