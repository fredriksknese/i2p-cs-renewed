using System.Buffers;

namespace I2PCore.Data;

/// <summary>
///     Can be byte serialized according to specification.
/// </summary>
public interface I2PType
{
    void Write(IBufferWriter<byte> dest);
}