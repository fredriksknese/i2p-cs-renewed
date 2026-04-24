using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;
using I2PCore.Utils;

namespace I2PCore.Data
{
    public class I2PKeysAndCert : I2PType, IEquatable<I2PKeysAndCert>
    {
        /// <summary>
        /// The usable encryption public key bytes. Per Java I2P KeysAndCert.writeBytes():
        /// the key is written first (left-justified), followed by padding to fill 256 bytes.
        /// When the signing key is larger than 128 bytes, it overflows into the end of
        /// the 256-byte encryption key area, reducing the available encryption key space.
        /// </summary>
        public BufLen PublicKeyBuf
        {
            get
            {
                var spkLen = Certificate.SigningPublicKeyLength;
                var overflow = Math.Max( 0, spkLen - 128 );
                var effectiveLen = Math.Min( Certificate.PublicKeyLength, 256 - overflow );
                return new BufLen( Data, 0, effectiveLen );
            }
        }
        public I2PPublicKey PublicKey { 
            get 
            { 
                return new I2PPublicKey( (BufRefLen)PublicKeyBuf, Certificate ); 
            } 
            
            set 
            { 
                ( (BufRefLen)PublicKeyBuf ).Write( value.ToByteArray() ); 
            } 
        }

        public BufLen Padding
        {
            get
            {
                // For signing keys <= 128 bytes, padding fills the unused portion
                // of the 128-byte signing key field. For oversized keys (> 128 bytes),
                // no padding - the key extends into the encryption key area.
                var spkLen = Certificate.SigningPublicKeyLength;
                return new BufLen( Data, 256 + 128 - Math.Min( 128, spkLen ), spkLen );
            }
        }

        /// <summary>
        /// Buffer containing the signing public key data.
        /// Per I2P spec, when the signing key is larger than 128 bytes,
        /// the overflow bytes are stored at the end of the 256-byte encryption
        /// key area. The full signing key is a contiguous block starting at
        /// offset (384 - spkLen) with length spkLen.
        /// </summary>
        public BufLen SigningPublicKeyBuf
        {
            get
            {
                var spkLen = Certificate.SigningPublicKeyLength;
                // The signing key always ends at byte 383 (offset 256+128-1).
                // It starts at (384 - spkLen). For keys <= 128, start >= 256 (within signing area).
                // For keys > 128, start < 256 (overflows into encryption key area).
                return new BufLen( Data, 384 - spkLen, spkLen );
            }
        }

        /// <summary>
        /// Unused padding bytes in the 128-byte signing key field (offsets 256..255+padding).
        /// Only non-zero when the signing key is shorter than 128 bytes.
        /// </summary>
        public BufLen SigningPublicKeyPadding
        {
            get
            {
                var spkLen = Certificate.SigningPublicKeyLength;
                var paddingLen = spkLen >= 128 ? 0 : 128 - spkLen;
                return new BufLen( Data, 256, paddingLen );
            }
        }

        public I2PSigningPublicKey SigningPublicKey
        {
            get
            {
                return new I2PSigningPublicKey( (BufRefLen)SigningPublicKeyBuf, Certificate );
            }

            set
            {
                SigningPublicKeyPadding.Randomize();
                var writer = (BufRefLen)SigningPublicKeyBuf;
                writer.Write( value.ToByteArray() );
            }
        }

        public BufLen CertificateBuf 
        { 
            get 
            { 
                return new BufLen( 
                        Data, 
                        256 + 128, 
                        new I2PCertificate( 
                            new BufRef( Data, 256 + 128 ) )
                                .CertLength ); 
            } 
        }

        public I2PCertificate Certificate
        {
            get
            {
                return new I2PCertificate( new BufRef( Data, 256 + 128 ) );
            }

            protected set
            {
                var writer = new BufRef( CertificateBuf ); // We know the length
                var ar = value.ToByteArray();
                writer.Write( ar );
            }
        }

        private readonly BufLen Data;

        public I2PKeysAndCert( I2PPublicKey pubkey, I2PSigningPublicKey signkey )
        {
            Data = new BufLen( new byte[RecordSize( signkey.Certificate )] );
            Data.Randomize();

            Certificate = signkey.Certificate;
            PublicKey = pubkey;
            SigningPublicKey = signkey;
        }

        public int Size { get => RecordSize( SigningPublicKey.Certificate ); }

        private int RecordSize( I2PCertificate cert )
        {
            return 256 + 128 + cert.CertLength;
        }

        public I2PKeysAndCert( BufRef reader )
        {
            var cert = new I2PCertificate( new BufRef( reader, 256 + 128 ) );
            Data = reader.ReadBufLen( RecordSize( cert ) );
        }

        public void Write( BufRefStream dest )
        {
            dest.Write( (BufRefLen)Data );
        }

        private I2PIdentHash CachedIdentHash;

        public I2PIdentHash IdentHash
        {
            get
            {
                if ( CachedIdentHash != null ) return CachedIdentHash;
                CachedIdentHash = new I2PIdentHash( this );
                return CachedIdentHash;
            }
        }

        public override string ToString()
        {
            return $"{GetType().Name} {IdentHash.Id32Short}";
        }

        public override int GetHashCode()
        {
            return IdentHash?.GetHashCode() ?? 0;
        }

        public override bool Equals( object obj )
        {
            var other = obj as I2PKeysAndCert;
            if ( other is null || obj is null ) return false;

            return IdentHash?.Equals( other?.IdentHash ) ?? false;
        }

        public bool Equals( I2PKeysAndCert other )
        {
            return IdentHash?.Equals( other?.IdentHash ) ?? false;
        }
    }
}
