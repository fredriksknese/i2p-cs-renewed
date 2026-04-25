using System;

namespace I2PCore;

public class FailedToConnectException : Exception
{
    public FailedToConnectException(string text) : base(text)
    {
    }
}