using System;

namespace I2PCore;

public class ChecksumFailureException : Exception
{
    public ChecksumFailureException()
    {
    }

    public ChecksumFailureException(string msg) : base(msg)
    {
    }
}