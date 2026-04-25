using System.IO;

namespace I2PCore.Utils;

public class StreamLogStore : ILogStore
{
    protected StreamWriter LogFile { get; private set; }

    public Stream Stream
    {
        set
        {
            Close();
            LogFile = new StreamWriter(value);
        }
    }

    public virtual string Name
    {
        get => null;

        set { }
    }

    public virtual void CheckStoreRotation()
    {
    }

    public void Close()
    {
        if (LogFile != null)
        {
            LogFile.Close();
            LogFile.Dispose();
        }

        LogFile = null;
    }

    public virtual void Log(string text)
    {
        LogFile.Write($"{text}\r\n");
        LogFile.Flush();
        LogFile.BaseStream.Flush();
    }
}