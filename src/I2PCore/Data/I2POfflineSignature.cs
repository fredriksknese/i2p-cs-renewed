using System.Buffers;
using I2PCore.Utils;
using static I2PCore.Data.I2PSigningKey;

namespace I2PCore.Data;

public class I2POfflineSignature : I2PType
{
    public I2POfflineSignature(I2PBufferCursor reader, I2PCertificate cert)
    {
        Expires = new I2PDateShort(reader.ReadUInt32BigEndian());
        SignatureType = (SigningKeyTypes)reader.ReadUInt16BigEndian();

        TransientPublicKey = new I2PSigningPublicKey(
            reader,
            new I2PCertificate(SignatureType));

        Signature = new I2PSignature(reader, cert);
    }

    public I2PDateShort Expires { get; set; }
    public SigningKeyTypes SignatureType { get; set; }
    public I2PSigningPublicKey TransientPublicKey { get; set; }
    public I2PSignature Signature { get; set; }

    public void Write(IBufferWriter<byte> dest)
    {
        Expires.Write(dest);
        dest.WriteUInt16BigEndian((ushort)SignatureType);
        TransientPublicKey.Write(dest);
        Signature.Write(dest);
    }
}