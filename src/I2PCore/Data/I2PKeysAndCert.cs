using System;
using System.Buffers;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PKeysAndCert : I2PType, IEquatable<I2PKeysAndCert>
{
    private readonly I2PByteBlock Data;

    private I2PIdentHash CachedIdentHash;

    public I2PKeysAndCert(I2PPublicKey pubkey, I2PSigningPublicKey signkey)
    {
        Data = new I2PByteBlock(new byte[RecordSize(signkey.Certificate)]);
        Data.Randomize();

        Certificate = signkey.Certificate;
        PublicKey = pubkey;
        SigningPublicKey = signkey;
    }

    public I2PKeysAndCert(I2PBufferCursor reader)
    {
        var cert = new I2PCertificate(reader.CreateSubCursor(256 + 128));
        Data = reader.ReadBlock(RecordSize(cert));
    }

    /// <summary>
    ///     The usable encryption public key bytes. Per Java I2P KeysAndCert.writeBytes():
    ///     the key is written first (left-justified), followed by padding to fill 256 bytes.
    ///     When the signing key is larger than 128 bytes, it overflows into the end of
    ///     the 256-byte encryption key area, reducing the available encryption key space.
    /// </summary>
    public I2PByteBlock PublicKeyBuf
    {
        get
        {
            var spkLen = Certificate.SigningPublicKeyLength;
            var overflow = Math.Max(0, spkLen - 128);
            var effectiveLen = Math.Min(Certificate.PublicKeyLength, 256 - overflow);
            return new I2PByteBlock(Data.BaseArray, Data.BaseArrayOffset, effectiveLen);
        }
    }

    public I2PPublicKey PublicKey
    {
        get => new(new I2PBufferCursor(PublicKeyBuf), Certificate);

        set => PublicKeyBuf.CopyFrom(value.ToByteArray(), 0);
    }

    public I2PByteBlock Padding
    {
        get
        {
            // For signing keys <= 128 bytes, padding fills the unused portion
            // of the 128-byte signing key field. For oversized keys (> 128 bytes),
            // no padding - the key extends into the encryption key area.
            var spkLen = Certificate.SigningPublicKeyLength;
            return new I2PByteBlock(Data.BaseArray, Data.BaseArrayOffset + 256 + 128 - Math.Min(128, spkLen), spkLen);
        }
    }

    /// <summary>
    ///     Buffer containing the signing public key data.
    ///     Per I2P spec, when the signing key is larger than 128 bytes,
    ///     the overflow bytes are stored at the end of the 256-byte encryption
    ///     key area. The full signing key is a contiguous block starting at
    ///     offset (384 - spkLen) with length spkLen.
    /// </summary>
    public I2PByteBlock SigningPublicKeyBuf
    {
        get
        {
            var spkLen = Certificate.SigningPublicKeyLength;
            // The signing key always ends at byte 383 (offset 256+128-1).
            // It starts at (384 - spkLen). For keys <= 128, start >= 256 (within signing area).
            // For keys > 128, start < 256 (overflows into encryption key area).
            return new I2PByteBlock(Data.BaseArray, Data.BaseArrayOffset + 384 - spkLen, spkLen);
        }
    }

    /// <summary>
    ///     Unused padding bytes in the 128-byte signing key field (offsets 256..255+padding).
    ///     Only non-zero when the signing key is shorter than 128 bytes.
    /// </summary>
    public I2PByteBlock SigningPublicKeyPadding
    {
        get
        {
            var spkLen = Certificate.SigningPublicKeyLength;
            var paddingLen = spkLen >= 128 ? 0 : 128 - spkLen;
            return new I2PByteBlock(Data.BaseArray, Data.BaseArrayOffset + 256, paddingLen);
        }
    }

    public I2PSigningPublicKey SigningPublicKey
    {
        get => new(new I2PBufferCursor(SigningPublicKeyBuf), Certificate);

        set
        {
            SigningPublicKeyPadding.Randomize();
            SigningPublicKeyBuf.CopyFrom(value.ToByteArray(), 0);
        }
    }

    public I2PByteBlock CertificateBuf =>
        new(
            Data.BaseArray,
            Data.BaseArrayOffset + 256 + 128,
            new I2PCertificate(
                    new I2PBufferCursor(Data.BaseArray, Data.BaseArrayOffset + 256 + 128))
                .CertLength);

    public I2PCertificate Certificate
    {
        get => new(new I2PBufferCursor(Data.BaseArray, Data.BaseArrayOffset + 256 + 128));

        protected set
        {
            var ar = value.ToByteArray();
            CertificateBuf.CopyFrom(ar, 0);
        }
    }

    public int Size => RecordSize(SigningPublicKey.Certificate);

    public I2PIdentHash IdentHash
    {
        get
        {
            if (CachedIdentHash != null) return CachedIdentHash;
            CachedIdentHash = new I2PIdentHash(this);
            return CachedIdentHash;
        }
    }

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteBlock(Data);
    }

    public bool Equals(I2PKeysAndCert other)
    {
        return IdentHash?.Equals(other?.IdentHash) ?? false;
    }

    private int RecordSize(I2PCertificate cert)
    {
        return 256 + 128 + cert.CertLength;
    }

    public override string ToString()
    {
        return $"{GetType().Name} {IdentHash.Id32Short}";
    }

    public override int GetHashCode()
    {
        return IdentHash?.GetHashCode() ?? 0;
    }

    public override bool Equals(object obj)
    {
        var other = obj as I2PKeysAndCert;
        if (other is null || obj is null) return false;

        return IdentHash?.Equals(other?.IdentHash) ?? false;
    }
}