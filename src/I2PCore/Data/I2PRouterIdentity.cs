using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PRouterIdentity : I2PKeysAndCert
{
    public I2PRouterIdentity(I2PPublicKey pubkey, I2PSigningPublicKey signkey) : base(pubkey, signkey)
    {
    }

    public I2PRouterIdentity(I2PBufferCursor data) : base(data)
    {
    }
}