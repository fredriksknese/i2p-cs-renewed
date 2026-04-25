using System;

namespace I2PCore;

public class EndOfStreamEncounteredException : Exception
{
    public EndOfStreamEncounteredException()
    {
    }

    public EndOfStreamEncounteredException(string text) : base(text)
    {
    }
}