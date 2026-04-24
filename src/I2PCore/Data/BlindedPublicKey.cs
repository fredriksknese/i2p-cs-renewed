using System;
using System.Text;
using I2PCore.Utils;
using I2PCore.TransportLayer.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X9;

namespace I2PCore.Data
{
    /// <summary>
    /// Blinded public key for Encrypted LeaseSet2 (proposal 123).
    /// Implements key blinding for Ed25519 (EdDSA/RedDSA) and ECDSA curves.
    /// Used to derive store hashes and subcredentials for encrypted LS2 lookups.
    /// </summary>
    public class BlindedPublicKey
    {
        private const byte B33_TWO_BYTES_SIGTYPE_FLAG = 0x01;
        private const byte B33_PER_CLIENT_AUTH_FLAG = 0x04;

        // Ed25519 curve constants
        private static readonly BigInteger EdP = BigInteger.One.ShiftLeft( 255 ).Subtract( BigInteger.ValueOf( 19 ) );
        private static readonly BigInteger EdL = BigInteger.One.ShiftLeft( 252 )
            .Add( new BigInteger( "27742317777372353535851937790883648493" ) );
        private static readonly BigInteger EdD;
        private static readonly BigInteger EdI; // sqrt(-1) mod p

        private readonly byte[] PublicKey;
        public I2PSigningKey.SigningKeyTypes SigType { get; }
        public I2PSigningKey.SigningKeyTypes BlindedSigType { get; }
        public bool IsClientAuth { get; }

        public bool IsValid => SigType != I2PSigningKey.SigningKeyTypes.DsaSha1
                            && SigType != I2PSigningKey.SigningKeyTypes.Invalid;

        /// <summary>
        /// Create from an I2P identity (destination's signing public key).
        /// </summary>
        public BlindedPublicKey( I2PKeysAndCert identity, bool clientAuth = false )
        {
            if ( identity == null ) throw new ArgumentNullException( nameof( identity ) );

            IsClientAuth = clientAuth;
            SigType = identity.Certificate.SignatureType;

            var spk = identity.SigningPublicKey;
            PublicKey = new byte[spk.Key.Length];
            Array.Copy( spk.Key.BaseArray, spk.Key.BaseArrayOffset, PublicKey, 0, spk.Key.Length );

            // EdDSA -> RedDSA for blinded type
            if ( SigType == I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519 )
                BlindedSigType = I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519;
            else
                BlindedSigType = SigType;
        }

        /// <summary>
        /// Create from a b33 address string (without .b32.i2p suffix).
        /// </summary>
        public BlindedPublicKey( string b33 )
        {
            var addr = I2PCore.Utils.BufUtils.Base32ToByteArray( b33 );
            if ( addr == null || addr.Length < 32 )
            {
                Logging.LogDebug( $"BlindedPublicKey: Malformed b33 {b33}" );
                SigType = I2PSigningKey.SigningKeyTypes.Invalid;
                BlindedSigType = I2PSigningKey.SigningKeyTypes.Invalid;
                PublicKey = Array.Empty<byte>();
                return;
            }

            // Compute CRC32 checksum over payload (starting at byte 3)
            uint checksum = Crc32( addr, 3, addr.Length - 3 );
            // XOR first 3 bytes with checksum (Little Endian)
            addr[0] ^= (byte)( checksum & 0xFF );
            addr[1] ^= (byte)( ( checksum >> 8 ) & 0xFF );
            addr[2] ^= (byte)( ( checksum >> 16 ) & 0xFF );

            byte flags = addr[0];
            int offset = 1;

            if ( ( flags & B33_TWO_BYTES_SIGTYPE_FLAG ) != 0 )
            {
                SigType = (I2PSigningKey.SigningKeyTypes)( ( addr[offset] << 8 ) | addr[offset + 1] );
                offset += 2;
                BlindedSigType = (I2PSigningKey.SigningKeyTypes)( ( addr[offset] << 8 ) | addr[offset + 1] );
                offset += 2;
            }
            else
            {
                SigType = (I2PSigningKey.SigningKeyTypes)addr[offset];
                offset++;
                BlindedSigType = (I2PSigningKey.SigningKeyTypes)addr[offset];
                offset++;
            }

            IsClientAuth = ( flags & B33_PER_CLIENT_AUTH_FLAG ) != 0;

            int pubKeyLen = I2PSigningKey.SigningPublicKeyLength( SigType );
            if ( offset + pubKeyLen <= addr.Length )
            {
                PublicKey = new byte[pubKeyLen];
                Array.Copy( addr, offset, PublicKey, 0, pubKeyLen );
            }
            else
            {
                Logging.LogDebug( $"BlindedPublicKey: Public key in b33 too short for sig type {(int)SigType}" );
                PublicKey = Array.Empty<byte>();
            }
        }

        /// <summary>
        /// Encode to b33 address string (without .b32.i2p suffix).
        /// </summary>
        public string ToB33()
        {
            if ( PublicKey.Length > 32 ) return string.Empty;

            var addr = new byte[3 + PublicKey.Length];
            byte flags = 0;
            if ( IsClientAuth ) flags |= B33_PER_CLIENT_AUTH_FLAG;

            addr[0] = flags;
            addr[1] = (byte)SigType;
            addr[2] = (byte)BlindedSigType;
            Array.Copy( PublicKey, 0, addr, 3, PublicKey.Length );

            uint checksum = Crc32( addr, 3, PublicKey.Length );
            addr[0] ^= (byte)( checksum & 0xFF );
            addr[1] ^= (byte)( ( checksum >> 8 ) & 0xFF );
            addr[2] ^= (byte)( ( checksum >> 16 ) & 0xFF );

            return I2PCore.Utils.BufUtils.ToBase32String( addr );
        }

        /// <summary>
        /// Compute credential = H("credential", A || stA || stA1)
        /// </summary>
        private byte[] GetCredential()
        {
            var stA = UInt16BE( (ushort)SigType );
            var stA1 = UInt16BE( (ushort)BlindedSigType );
            return H( "credential", PublicKey, stA, stA1 );
        }

        /// <summary>
        /// Compute subcredential = H("subcredential", credential || blindedPublicKey)
        /// </summary>
        public byte[] GetSubcredential( byte[] blindedKey )
        {
            var credential = GetCredential();
            return H( "subcredential", credential, blindedKey );
        }

        /// <summary>
        /// Generate alpha seed = HKDF(H("I2PGenerateAlpha", A || stA || stA1), date, "i2pblinding1", 64)
        /// </summary>
        private byte[] GenerateAlpha( string date )
        {
            var stA = UInt16BE( (ushort)SigType );
            var stA1 = UInt16BE( (ushort)BlindedSigType );
            var salt = H( "I2PGenerateAlpha", PublicKey, stA, stA1 );
            var dateBytes = Encoding.ASCII.GetBytes( date );
            var info = Encoding.ASCII.GetBytes( "i2pblinding1" );
            return HKDF.DeriveKey( salt, dateBytes, info, 64 );
        }

        /// <summary>
        /// Compute blinded public key for the given date (YYYYMMDD format).
        /// </summary>
        public byte[] GetBlindedKey( string date )
        {
            var seed = GenerateAlpha( date );

            switch ( SigType )
            {
                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
                case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                    return BlindPublicKeyEd25519( PublicKey, seed );

                case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                    return BlindPublicKeyECDSA( "P-256", PublicKey, seed );

                case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                    return BlindPublicKeyECDSA( "P-384", PublicKey, seed );

                case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                    return BlindPublicKeyECDSA( "P-521", PublicKey, seed );

                default:
                    Logging.LogDebug( $"BlindedPublicKey: Can't blind signature type {(int)SigType}" );
                    return null;
            }
        }

        /// <summary>
        /// Blind a private key for the given date (YYYYMMDD format).
        /// Returns (blindedPrivateKey, blindedPublicKey).
        /// </summary>
        public (byte[] blindedPriv, byte[] blindedPub) BlindPrivateKey( byte[] privateKey, string date )
        {
            var seed = GenerateAlpha( date );

            switch ( SigType )
            {
                case I2PSigningKey.SigningKeyTypes.RedDsaSha512Ed25519:
                    return BlindPrivateKeyEd25519( privateKey, seed );

                case I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519:
                {
                    var expanded = ExpandEd25519PrivateKey( privateKey );
                    return BlindPrivateKeyEd25519( expanded, seed );
                }

                case I2PSigningKey.SigningKeyTypes.EcdsaSha256P256:
                    return BlindPrivateKeyECDSA( "P-256", privateKey, seed );

                case I2PSigningKey.SigningKeyTypes.EcdsaSha384P384:
                    return BlindPrivateKeyECDSA( "P-384", privateKey, seed );

                case I2PSigningKey.SigningKeyTypes.EcdsaSha512P521:
                    return BlindPrivateKeyECDSA( "P-521", privateKey, seed );

                default:
                    Logging.LogDebug( $"BlindedPublicKey: Can't blind private key for type {(int)SigType}" );
                    return (null, null);
            }
        }

        /// <summary>
        /// Compute the store hash for looking up this encrypted LS2 in the NetDb.
        /// storeHash = SHA256(blindedSigType_BE || blindedPublicKey)
        /// </summary>
        public I2PIdentHash GetStoreHash( string date = null )
        {
            if ( date == null )
                date = DateTime.UtcNow.ToString( "yyyyMMdd" );

            var blindedKey = GetBlindedKey( date );
            if ( blindedKey == null )
            {
                Logging.LogDebug( $"BlindedPublicKey: Blinded key type {(int)BlindedSigType} not supported" );
                return I2PIdentHash.Zero;
            }

            var stA1 = UInt16BE( (ushort)BlindedSigType );

            var sha = new Sha256Digest();
            sha.BlockUpdate( stA1, 0, 2 );
            sha.BlockUpdate( blindedKey, 0, blindedKey.Length );
            var hash = new byte[32];
            sha.DoFinal( hash, 0 );

            return new I2PIdentHash( new BufRef( hash ) );
        }

        // --- Ed25519 blinding using BigInteger arithmetic on twisted Edwards curve ---

        /// <summary>
        /// Blind an Ed25519 public key: A' = A + alpha*B
        /// where alpha = seed (little-endian 64 bytes) mod L
        /// </summary>
        private static byte[] BlindPublicKeyEd25519( byte[] pub, byte[] seed )
        {
            // alpha = seed (LE 64 bytes) mod L
            var seedInt = new BigInteger( 1, ReverseBytes( seed ) );
            var alpha = seedInt.Mod( EdL );
            var alphaLE = BigIntToLE32( alpha );

            // alpha * B (base point multiplication)
            var alphaB = EdScalarMultBase( alphaLE );

            // Decode public key A
            var A = EdDecodePoint( pub );

            // A' = A + alpha*B
            var result = EdAddPoints( A, alphaB );

            return EdEncodePoint( result );
        }

        /// <summary>
        /// Blind an Ed25519 private key: a' = (a + alpha) mod L
        /// </summary>
        private static (byte[] blindedPriv, byte[] blindedPub) BlindPrivateKeyEd25519( byte[] priv, byte[] seed )
        {
            // alpha = seed (LE 64 bytes) mod L
            var seedInt = new BigInteger( 1, ReverseBytes( seed ) );
            var alpha = seedInt.Mod( EdL );

            // priv as LE integer
            var privInt = new BigInteger( 1, ReverseBytes( priv, 32 ) );

            // a' = (a + alpha) mod L
            var blindedPrivInt = privInt.Add( alpha ).Mod( EdL );
            var blindedPriv = BigIntToLE32( blindedPrivInt );

            // A' = a' * B
            var blindedPubPoint = EdScalarMultBase( blindedPriv );
            var blindedPub = EdEncodePoint( blindedPubPoint );

            return (blindedPriv, blindedPub);
        }

        /// <summary>
        /// Expand EdDSA private key: SHA-512 + clamp first 32 bytes
        /// </summary>
        private static byte[] ExpandEd25519PrivateKey( byte[] key )
        {
            var sha512 = new Sha512Digest();
            var expanded = new byte[64];
            sha512.BlockUpdate( key, 0, 32 );
            sha512.DoFinal( expanded, 0 );

            expanded[0] &= 0xF8;
            expanded[31] &= 0x3F;
            expanded[31] |= 0x40;

            var scalar = new byte[32];
            Array.Copy( expanded, 0, scalar, 0, 32 );
            return scalar;
        }

        // --- Ed25519 point arithmetic ---
        // Extended coordinates (X, Y, Z, T) where x=X/Z, y=Y/Z, x*y=T/Z

        private struct EdPoint
        {
            public BigInteger X, Y, Z, T;
        }

        private static readonly EdPoint EdBasePoint;

        static BlindedPublicKey()
        {
            // d = -121665 * inv(121666) mod p
            EdD = BigInteger.ValueOf( 121666 ).ModInverse( EdP )
                .Multiply( BigInteger.ValueOf( 121665 ).Negate() ).Mod( EdP );
            // I = 2^((p-1)/4) mod p  (this is sqrt(-1) mod p)
            EdI = BigInteger.Two.ModPow( EdP.Subtract( BigInteger.One ).ShiftRight( 2 ), EdP );

            // Base point B: y = 4/5 mod p
            var By = BigInteger.ValueOf( 5 ).ModInverse( EdP ).Multiply( BigInteger.ValueOf( 4 ) ).Mod( EdP );
            var Bx = EdRecoverX( By );
            if ( Bx.TestBit( 0 ) ) Bx = EdP.Subtract( Bx ); // x should be positive (even)
            EdBasePoint = new EdPoint
            {
                X = Bx, Y = By, Z = BigInteger.One, T = Bx.Multiply( By ).Mod( EdP )
            };
        }

        /// <summary>
        /// Recover x coordinate from y on Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2
        /// x^2 = (y^2 - 1) / (d*y^2 + 1)
        /// </summary>
        private static BigInteger EdRecoverX( BigInteger y )
        {
            var y2 = y.Multiply( y ).Mod( EdP );
            var num = y2.Subtract( BigInteger.One ).Mod( EdP );
            var den = EdD.Multiply( y2 ).Add( BigInteger.One ).Mod( EdP );
            var x2 = num.Multiply( den.ModInverse( EdP ) ).Mod( EdP );

            if ( x2.Equals( BigInteger.Zero ) ) return BigInteger.Zero;

            // x = x2^((p+3)/8) mod p
            var exp = EdP.Add( BigInteger.ValueOf( 3 ) ).ShiftRight( 3 );
            var x = x2.ModPow( exp, EdP );

            // Verify: if x^2 != x2, multiply by sqrt(-1)
            if ( !x.Multiply( x ).Mod( EdP ).Equals( x2 ) )
                x = x.Multiply( EdI ).Mod( EdP );

            if ( !x.Multiply( x ).Mod( EdP ).Equals( x2 ) )
                throw new ArithmeticException( "Ed25519: no valid x for given y" );

            return x;
        }

        /// <summary>
        /// Decode Ed25519 point from 32-byte compressed encoding.
        /// </summary>
        private static EdPoint EdDecodePoint( byte[] encoded )
        {
            var yBytes = new byte[32];
            Array.Copy( encoded, yBytes, 32 );
            bool xSign = ( yBytes[31] & 0x80 ) != 0;
            yBytes[31] &= 0x7F;

            var y = new BigInteger( 1, ReverseBytes( yBytes, 32 ) );
            var x = EdRecoverX( y );

            if ( x.TestBit( 0 ) != xSign )
                x = EdP.Subtract( x );

            return new EdPoint
            {
                X = x, Y = y, Z = BigInteger.One, T = x.Multiply( y ).Mod( EdP )
            };
        }

        /// <summary>
        /// Encode Ed25519 point to 32-byte compressed format.
        /// </summary>
        private static byte[] EdEncodePoint( EdPoint p )
        {
            var zinv = p.Z.ModInverse( EdP );
            var x = p.X.Multiply( zinv ).Mod( EdP );
            var y = p.Y.Multiply( zinv ).Mod( EdP );

            var result = new byte[32];
            BigIntToLE( y, result, 32 );

            if ( x.TestBit( 0 ) )
                result[31] |= 0x80;

            return result;
        }

        /// <summary>
        /// Extended coordinates point addition on Ed25519.
        /// </summary>
        private static EdPoint EdAddPoints( EdPoint P, EdPoint Q )
        {
            // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
            var A = P.X.Multiply( Q.X ).Mod( EdP );
            var B = P.Y.Multiply( Q.Y ).Mod( EdP );
            var C = P.T.Multiply( EdD ).Mod( EdP ).Multiply( Q.T ).Mod( EdP );
            var D = P.Z.Multiply( Q.Z ).Mod( EdP );
            var E = P.X.Add( P.Y ).Multiply( Q.X.Add( Q.Y ) ).Mod( EdP )
                .Subtract( A ).Subtract( B ).Mod( EdP );
            var F = D.Subtract( C ).Mod( EdP );
            var G = D.Add( C ).Mod( EdP );
            var HH = B.Add( A ).Mod( EdP ); // Note: twisted Edwards has a=-1, so B - a*A = B + A

            return new EdPoint
            {
                X = E.Multiply( F ).Mod( EdP ),
                Y = G.Multiply( HH ).Mod( EdP ),
                Z = F.Multiply( G ).Mod( EdP ),
                T = E.Multiply( HH ).Mod( EdP )
            };
        }

        /// <summary>
        /// Point doubling on Ed25519 (extended coordinates).
        /// </summary>
        private static EdPoint EdDoublePoint( EdPoint P )
        {
            var A = P.X.Multiply( P.X ).Mod( EdP );
            var B = P.Y.Multiply( P.Y ).Mod( EdP );
            var C = BigInteger.Two.Multiply( P.Z ).Multiply( P.Z ).Mod( EdP );
            var D = EdP.Subtract( A ); // a*A where a=-1 => -A mod p
            var E = P.X.Add( P.Y ).Multiply( P.X.Add( P.Y ) ).Mod( EdP )
                .Subtract( A ).Subtract( B ).Mod( EdP );
            var G = D.Add( B ).Mod( EdP );
            var F = G.Subtract( C ).Mod( EdP );
            var HH = D.Subtract( B ).Mod( EdP );

            return new EdPoint
            {
                X = E.Multiply( F ).Mod( EdP ),
                Y = G.Multiply( HH ).Mod( EdP ),
                Z = F.Multiply( G ).Mod( EdP ),
                T = E.Multiply( HH ).Mod( EdP )
            };
        }

        /// <summary>
        /// Scalar multiplication: k * B (base point)
        /// k is 32-byte little-endian scalar.
        /// </summary>
        private static EdPoint EdScalarMultBase( byte[] k )
        {
            return EdScalarMult( k, EdBasePoint );
        }

        /// <summary>
        /// Scalar multiplication: k * P using double-and-add.
        /// k is 32-byte little-endian scalar.
        /// </summary>
        private static EdPoint EdScalarMult( byte[] k, EdPoint P )
        {
            var scalar = new BigInteger( 1, ReverseBytes( k, 32 ) );
            var result = new EdPoint { X = BigInteger.Zero, Y = BigInteger.One, Z = BigInteger.One, T = BigInteger.Zero };
            var current = P;

            while ( scalar.SignValue > 0 )
            {
                if ( scalar.TestBit( 0 ) )
                    result = EdAddPoints( result, current );
                current = EdDoublePoint( current );
                scalar = scalar.ShiftRight( 1 );
            }

            return result;
        }

        // --- ECDSA blinding ---

        private static byte[] BlindPublicKeyECDSA( string curveName, byte[] pub, byte[] seed )
        {
            var ecParams = ECNamedCurveTable.GetByName( curveName );
            if ( ecParams == null )
                throw new ArgumentException( $"Unknown curve: {curveName}" );

            var curve = ecParams.Curve;
            int halfLen = pub.Length / 2;

            var x = new BigInteger( 1, pub, 0, halfLen );
            var y = new BigInteger( 1, pub, halfLen, halfLen );
            var point = curve.CreatePoint( x, y );

            var seedInt = new BigInteger( 1, seed );
            var alpha = seedInt.Mod( ecParams.N );

            var alphaG = ecParams.G.Multiply( alpha );
            var blinded = point.Add( alphaG ).Normalize();

            var bx = blinded.AffineXCoord.ToBigInteger();
            var by = blinded.AffineYCoord.ToBigInteger();

            var result = new byte[pub.Length];
            BigIntToBE( bx, result, 0, halfLen );
            BigIntToBE( by, result, halfLen, halfLen );
            return result;
        }

        private static (byte[] blindedPriv, byte[] blindedPub) BlindPrivateKeyECDSA(
            string curveName, byte[] priv, byte[] seed )
        {
            var ecParams = ECNamedCurveTable.GetByName( curveName );
            if ( ecParams == null )
                throw new ArgumentException( $"Unknown curve: {curveName}" );

            int halfLen = priv.Length;

            var seedInt = new BigInteger( 1, seed );
            var alpha = seedInt.Mod( ecParams.N );

            var privInt = new BigInteger( 1, priv );
            var blindedPrivInt = privInt.Add( alpha ).Mod( ecParams.N );

            var blindedPriv = new byte[halfLen];
            BigIntToBE( blindedPrivInt, blindedPriv, 0, halfLen );

            var blindedPoint = ecParams.G.Multiply( blindedPrivInt ).Normalize();
            var bx = blindedPoint.AffineXCoord.ToBigInteger();
            var by = blindedPoint.AffineYCoord.ToBigInteger();

            var blindedPub = new byte[halfLen * 2];
            BigIntToBE( bx, blindedPub, 0, halfLen );
            BigIntToBE( by, blindedPub, halfLen, halfLen );
            return (blindedPriv, blindedPub);
        }

        // --- Hash helper ---

        private static byte[] H( string prefix, params byte[][] bufs )
        {
            var sha = new Sha256Digest();
            var prefixBytes = Encoding.UTF8.GetBytes( prefix );
            sha.BlockUpdate( prefixBytes, 0, prefixBytes.Length );
            foreach ( var buf in bufs )
                sha.BlockUpdate( buf, 0, buf.Length );
            var hash = new byte[32];
            sha.DoFinal( hash, 0 );
            return hash;
        }

        // --- Utility methods ---

        private static byte[] UInt16BE( ushort value )
        {
            return new byte[] { (byte)( value >> 8 ), (byte)( value & 0xFF ) };
        }

        private static byte[] ReverseBytes( byte[] src, int length = 0 )
        {
            if ( length == 0 ) length = src.Length;
            var result = new byte[length];
            for ( int i = 0; i < length; i++ )
                result[i] = src[length - 1 - i];
            return result;
        }

        private static byte[] BigIntToLE32( BigInteger value )
        {
            var result = new byte[32];
            BigIntToLE( value, result, 32 );
            return result;
        }

        private static void BigIntToLE( BigInteger value, byte[] buf, int len )
        {
            var be = value.ToByteArrayUnsigned();
            for ( int i = 0; i < len; i++ )
            {
                int srcIdx = be.Length - 1 - i;
                buf[i] = srcIdx >= 0 ? be[srcIdx] : (byte)0;
            }
        }

        private static void BigIntToBE( BigInteger value, byte[] buf, int offset, int len )
        {
            var be = value.ToByteArrayUnsigned();
            int padLen = len - be.Length;
            if ( padLen > 0 )
            {
                Array.Clear( buf, offset, padLen );
                Array.Copy( be, 0, buf, offset + padLen, be.Length );
            }
            else
            {
                Array.Copy( be, be.Length - len, buf, offset, len );
            }
        }

        private static uint Crc32( byte[] data, int offset, int length )
        {
            uint crc = 0xFFFFFFFF;
            for ( int i = offset; i < offset + length; i++ )
            {
                crc ^= data[i];
                for ( int j = 0; j < 8; j++ )
                {
                    if ( ( crc & 1 ) != 0 )
                        crc = ( crc >> 1 ) ^ 0xEDB88320;
                    else
                        crc >>= 1;
                }
            }
            return crc ^ 0xFFFFFFFF;
        }
    }
}
