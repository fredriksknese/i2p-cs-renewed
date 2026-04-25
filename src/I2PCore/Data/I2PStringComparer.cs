using System.Collections.Generic;

namespace I2PCore.Data;

public class I2PStringComparer : IComparer<I2PString>
{
    int IComparer<I2PString>.Compare(I2PString x, I2PString y)
    {
        return x.CompareTo(y);
    }
}