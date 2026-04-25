using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data
{
    /// <summary>
    /// Can be byte serialized according to specification.
    /// </summary>
    public interface I2PType
    {
        void Write( IBufferWriter<byte> dest );
    }
}
