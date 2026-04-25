
using I2PCore.Utils;

public class DatabaseLookupKeyInfo
{
    public bool EncryptionFlag { get; set; }
    public bool EciesFlag { get; set; }
    public I2PByteBlock ReplyKey { get; set; }
    public I2PByteBlock[] Tags { get; set; }
}