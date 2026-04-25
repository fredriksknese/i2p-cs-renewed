using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PDestination : I2PKeysAndCert
{
    public I2PDestination(I2PPublicKey pubkey, I2PSigningPublicKey signkey) : base(pubkey, signkey)
    {
    }

    public I2PDestination(I2PBufferCursor buf) : base(buf)
    {
    }
}