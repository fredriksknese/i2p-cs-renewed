using System;

namespace I2PCore;

public class SignatureCheckFailureException : Exception
{
    public SignatureCheckFailureException()
    {
    }

    public SignatureCheckFailureException(string msg) : base(msg)
    {
    }
}