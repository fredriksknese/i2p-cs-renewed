using System;

namespace I2PCore;

public class RouterUnresolvableException : Exception
{
    public RouterUnresolvableException()
    {
    }

    public RouterUnresolvableException(string text) : base(text)
    {
    }
}