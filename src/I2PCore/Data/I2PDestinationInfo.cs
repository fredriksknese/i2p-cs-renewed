using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PDestinationInfo
{
    public readonly I2PDestination Destination;
    public readonly I2PPrivateKey PrivateKey;
    public readonly I2PSigningPrivateKey PrivateSigningKey;

    public I2PDestinationInfo(I2PSigningKey.SigningKeyTypes signkeytype)
        : this(signkeytype, I2PKeyType.KeyTypes.ElGamal2048)
    {
    }

    public I2PDestinationInfo(
        I2PSigningKey.SigningKeyTypes signkeytype,
        I2PKeyType.KeyTypes pubkeytype)
    {
        var certificate = new I2PCertificate(signkeytype);

        PrivateKey = new I2PPrivateKey(new I2PCertificate(pubkeytype));
        PrivateSigningKey = new I2PSigningPrivateKey(certificate);

        Destination = new I2PDestination(
            new I2PPublicKey(PrivateKey),
            new I2PSigningPublicKey(PrivateSigningKey));
    }

    public I2PDestinationInfo(I2PBufferCursor reader)
    {
        Destination = new I2PDestination(reader);
        PrivateKey = new I2PPrivateKey(reader, Destination.Certificate);
        PrivateSigningKey = new I2PSigningPrivateKey(reader, Destination.Certificate);
    }

    public I2PDestinationInfo(string base64)
        : this(new I2PBufferCursor(FreenetBase64.Decode(base64)))
    {
    }

    public byte[] ToByteArray()
    {
        return BufUtils.ToByteArray(Destination, PrivateKey, PrivateSigningKey);
    }

    public string ToBase64()
    {
        return FreenetBase64.Encode(new I2PByteBlock(ToByteArray()));
    }

    public override string ToString()
    {
        return $"{Destination}";
    }
}