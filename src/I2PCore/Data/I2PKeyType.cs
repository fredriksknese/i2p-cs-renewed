using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Math;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public abstract class I2PKeyType: I2PType
    {
        public I2PByteBlock Key;

        public enum KeyTypes : ushort
        {
            Invalid = ushort.MaxValue,
            NotImplemented = ushort.MaxValue - 1,
            ElGamal2048 = 0,
            P256 = 1,
            P384 = 2,
            P521 = 3,
            X25519 = 4,
            MLKEM512_X25519 = 5,
            MLKEM768_X25519 = 6,
            MLKEM1024_X25519 = 7,
            // Handshake-only types (not used in KeysAndCert)
            MLKEM512 = 100,
            MLKEM768 = 101,
            MLKEM1024 = 102,
            MLKEM512_CT = 103,
            MLKEM768_CT = 104,
            MLKEM1024_CT = 105,
        }

        // Replace when ElGamal is optional
        public static readonly I2PCertificate DefaultAsymetricKeyCert = new();

        public static readonly I2PCertificate DefaultSigningKeyCert = new();

        public readonly I2PCertificate Certificate;

        public int KeySizeBits { get { return KeySizeBytes * 8; } }
        public abstract int KeySizeBytes { get; }

        protected I2PKeyType( I2PCertificate cert )
        {
            Certificate = cert;
        }

        protected I2PKeyType( I2PBufferCursor buf, I2PCertificate cert )
        {
            Certificate = cert;
            Key = buf.ReadBlock( KeySizeBytes );
        }

        public void Write( IBufferWriter<byte> dest )
        {
            dest.WriteBytes( ToByteArray() );
        }

        public byte[] ToByteArray()
        {
            return Key.ToByteArray();
        }

        public BigInteger ToBigInteger()
        {
            return Key.ToBigInteger();
        }

        public override string ToString()
        {
            return $"I2PKeyType {GetType().Name}" +
                $"Key : {KeySizeBits} bits, {KeySizeBytes} bytes." +
                $"Key : {Key}";
        }
        public static int PublicKeyLength( I2PKeyType.KeyTypes kt )
        {
            switch ( kt )
            {
                case I2PKeyType.KeyTypes.ElGamal2048:
                    return 256;

                case I2PKeyType.KeyTypes.P256:
                    return 64;

                case I2PKeyType.KeyTypes.P384:
                    return 96;

                case I2PKeyType.KeyTypes.P521:
                    return 132;

                case I2PKeyType.KeyTypes.X25519:
                    return 32;

                case I2PKeyType.KeyTypes.MLKEM512_X25519:
                    return 800 + 32;

                case I2PKeyType.KeyTypes.MLKEM768_X25519:
                    return 1184 + 32;

                case I2PKeyType.KeyTypes.MLKEM1024_X25519:
                    return 1568 + 32;

                case I2PKeyType.KeyTypes.MLKEM512:
                    return 800;

                case I2PKeyType.KeyTypes.MLKEM768:
                    return 1184;

                case I2PKeyType.KeyTypes.MLKEM1024:
                    return 1568;

                case I2PKeyType.KeyTypes.MLKEM512_CT:
                    return 768;

                case I2PKeyType.KeyTypes.MLKEM768_CT:
                    return 1088;

                case I2PKeyType.KeyTypes.MLKEM1024_CT:
                    return 1568;

                default:
                    Logging.LogWarning( $"I2PKeyType: Unknown key type {kt} for PublicKeyLength" );
                    return 256; // Default ElGamal length
            }
        }
        public static int PrivateKeyLength( I2PKeyType.KeyTypes kt )
        {
            switch ( kt )
            {
                case I2PKeyType.KeyTypes.ElGamal2048:
                    return 256;

                case I2PKeyType.KeyTypes.P256:
                    return 32;

                case I2PKeyType.KeyTypes.P384:
                    return 48;

                case I2PKeyType.KeyTypes.P521:
                    return 66;

                case I2PKeyType.KeyTypes.X25519:
                    return 32;

                case I2PKeyType.KeyTypes.MLKEM512_X25519:
                    return 1632 + 32;

                case I2PKeyType.KeyTypes.MLKEM768_X25519:
                    return 2400 + 32;

                case I2PKeyType.KeyTypes.MLKEM1024_X25519:
                    return 3168 + 32;

                case I2PKeyType.KeyTypes.MLKEM512:
                    return 1632;

                case I2PKeyType.KeyTypes.MLKEM768:
                    return 2400;

                case I2PKeyType.KeyTypes.MLKEM1024:
                    return 3168;

                default:
                    Logging.LogWarning( $"I2PKeyType: Unknown key type {kt} for PrivateKeyLength" );
                    return 256; // Default ElGamal length
            }
        }
    }
}
