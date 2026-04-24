using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace I2PCore.Utils
{
    public class RefPair<TL,TR>
    {
        public TL Left { get; set; }
        public TR Right { get; set; }

        public RefPair( TL l, TR r ) { Left = l; Right = r; }
    }
}
