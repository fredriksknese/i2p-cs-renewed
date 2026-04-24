using Org.BouncyCastle.Math;
using I2PCore.Utils;
using I2PCore.TransportLayer.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using I2PCore.Crypto.MLKEM;

namespace I2PCore.Data
{
    public class I2PPublicKey : I2PKeyType
    {
        public I2PPublicKey( I2PPrivateKey priv ): base( priv.Certificate )
        {
            switch( Certificate.PublicKeyType )
            {
                case KeyTypes.ElGamal2048:
                    Key = new BufLen( I2PConstants
                            .ElGamalG.ModPow(
                                priv.ToBigInteger(),
                                I2PConstants.ElGamalP )
                                    .ToByteArrayUnsigned() );
                    break;

                case KeyTypes.X25519:
                    Key = new BufLen( TransportLayer.Crypto.X25519.GetPublicKey( priv.ToByteArray() ) );
                    break;

                case KeyTypes.MLKEM512_X25519:
                    {
                        var privBytes = priv.ToByteArray();
                        var mlkemPriv = privBytes.Take( Crypto.MLKEM.MLKEM512.SecretKeyBytes ).ToArray();
                        var x25519Priv = privBytes.Skip( Crypto.MLKEM.MLKEM512.SecretKeyBytes ).Take( 32 ).ToArray();

                        var mlkemPub = Crypto.MLKEM.MLKEM512.GetPublicKey( mlkemPriv );
                        var x25519Pub = TransportLayer.Crypto.X25519.GetPublicKey( x25519Priv );

                        var combined = new byte[mlkemPub.Length + x25519Pub.Length];
                        Array.Copy( mlkemPub, 0, combined, 0, mlkemPub.Length );
                        Array.Copy( x25519Pub, 0, combined, mlkemPub.Length, x25519Pub.Length );
                        Key = new BufLen( combined );
                    }
                    break;

                case KeyTypes.MLKEM768_X25519:
                    {
                        var privBytes = priv.ToByteArray();
                        var mlkemPriv = privBytes.Take( Crypto.MLKEM.MLKEM768.SecretKeyBytes ).ToArray();
                        var x25519Priv = privBytes.Skip( Crypto.MLKEM.MLKEM768.SecretKeyBytes ).Take( 32 ).ToArray();

                        var mlkemPub = Crypto.MLKEM.MLKEM768.GetPublicKey( mlkemPriv );
                        var x25519Pub = TransportLayer.Crypto.X25519.GetPublicKey( x25519Priv );

                        var combined = new byte[mlkemPub.Length + x25519Pub.Length];
                        Array.Copy( mlkemPub, 0, combined, 0, mlkemPub.Length );
                        Array.Copy( x25519Pub, 0, combined, mlkemPub.Length, x25519Pub.Length );
                        Key = new BufLen( combined );
                    }
                    break;

                case KeyTypes.MLKEM1024_X25519:
                    {
                        var privBytes = priv.ToByteArray();
                        var mlkemPriv = privBytes.Take( Crypto.MLKEM.MLKEM1024.SecretKeyBytes ).ToArray();
                        var x25519Priv = privBytes.Skip( Crypto.MLKEM.MLKEM1024.SecretKeyBytes ).Take( 32 ).ToArray();

                        var mlkemPub = Crypto.MLKEM.MLKEM1024.GetPublicKey( mlkemPriv );
                        var x25519Pub = TransportLayer.Crypto.X25519.GetPublicKey( x25519Priv );

                        var combined = new byte[mlkemPub.Length + x25519Pub.Length];
                        Array.Copy( mlkemPub, 0, combined, 0, mlkemPub.Length );
                        Array.Copy( x25519Pub, 0, combined, mlkemPub.Length, x25519Pub.Length );
                        Key = new BufLen( combined );
                    }
                    break;

                case KeyTypes.P256:
                    {
                        var curve = ECNamedCurveTable.GetByName( "secp256r1" );
                        var domainParams = new ECDomainParameters( curve.Curve, curve.G, curve.N, curve.H );
                        var privKeyParams = new ECPrivateKeyParameters( new BigInteger( 1, priv.ToByteArray() ), domainParams );
                        var q = domainParams.G.Multiply( privKeyParams.D ).Normalize();
                        var xBytes = q.AffineXCoord.GetEncoded();
                        var yBytes = q.AffineYCoord.GetEncoded();
                        var pubBytes = new byte[64];
                        Array.Copy( xBytes, 0, pubBytes, 32 - xBytes.Length, xBytes.Length );
                        Array.Copy( yBytes, 0, pubBytes, 64 - yBytes.Length, yBytes.Length );
                        Key = new BufLen( pubBytes );
                    }
                    break;

                case KeyTypes.P384:
                    {
                        var curve = ECNamedCurveTable.GetByName( "secp384r1" );
                        var domainParams = new ECDomainParameters( curve.Curve, curve.G, curve.N, curve.H );
                        var privKeyParams = new ECPrivateKeyParameters( new BigInteger( 1, priv.ToByteArray() ), domainParams );
                        var q = domainParams.G.Multiply( privKeyParams.D ).Normalize();
                        var xBytes = q.AffineXCoord.GetEncoded();
                        var yBytes = q.AffineYCoord.GetEncoded();
                        var pubBytes = new byte[96];
                        Array.Copy( xBytes, 0, pubBytes, 48 - xBytes.Length, xBytes.Length );
                        Array.Copy( yBytes, 0, pubBytes, 96 - yBytes.Length, yBytes.Length );
                        Key = new BufLen( pubBytes );
                    }
                    break;

                case KeyTypes.P521:
                    {
                        var curve = ECNamedCurveTable.GetByName( "secp521r1" );
                        var domainParams = new ECDomainParameters( curve.Curve, curve.G, curve.N, curve.H );
                        var privKeyParams = new ECPrivateKeyParameters( new BigInteger( 1, priv.ToByteArray() ), domainParams );
                        var q = domainParams.G.Multiply( privKeyParams.D ).Normalize();
                        var xBytes = q.AffineXCoord.GetEncoded();
                        var yBytes = q.AffineYCoord.GetEncoded();
                        var pubBytes = new byte[132];
                        Array.Copy( xBytes, 0, pubBytes, 66 - xBytes.Length, xBytes.Length );
                        Array.Copy( yBytes, 0, pubBytes, 132 - yBytes.Length, yBytes.Length );
                        Key = new BufLen( pubBytes );
                    }
                    break;

                default:
                    Logging.LogWarning( $"I2PPublicKey: Public key derivation not implemented for key type {Certificate.PublicKeyType}" );
                    Key = new BufLen( new byte[KeySizeBytes] );
                    break;
            }
        }

        public I2PPublicKey( BufRef buf, I2PCertificate cert ) : base( buf, cert ) { }

        public I2PPublicKey( BigInteger pubkey, I2PCertificate cert ): base( cert )
        {
            Key = new BufLen( pubkey.ToByteArrayUnsigned() );
        }

        public override int KeySizeBytes { get { return Certificate.PublicKeyLength; } }
    }
}
