namespace I2PCore.Utils;

public interface ILogStore
{
    string Name { get; set; }
    void Log(string text);
    void CheckStoreRotation();
    void Close();
}