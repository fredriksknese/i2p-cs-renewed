using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.I2NP.Data;

public class BuildResponseRecord : I2PType
{
    public enum RequestResponse : byte
    {
        Accept = 0,
        ProbabalisticReject = 10,
        TransientOverload = 20,
        Bandwidth = 30,
        Critical = 50
    }

    public const RequestResponse DefaultErrorReply = RequestResponse.Bandwidth;
    private readonly I2PByteBlock Data;

    public BuildResponseRecord(I2PBufferCursor buf)
    {
        Data = buf.ReadBlock(Length);
    }

    public BuildResponseRecord(I2PByteBlock src)
    {
        if (src.Length != Length) throw new ArgumentException("BuildResponseRecord needs a 528 byte record!");
        Data = src;
    }

    public BuildResponseRecord(EgBuildRequestRecord request)
    {
        // Replace it
        Data = request.Data;
        Data.Randomize();
    }

    public BuildResponseRecord(AesEgBuildRequestRecord request)
    {
        // Reuse it
        Data = request.Data;
    }

    public int Length => 528;

    public RequestResponse Reply
    {
        get => (RequestResponse)Data[527];
        set => Data[527] = (byte)value;
    }

    public I2PByteBlock Payload => Data.Slice(0, Length);

    public I2PByteBlock Hash => Data.Slice(0, 32);

    public I2PByteBlock HashedArea => Data.Slice(32, 496);

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteBlock(Data);
    }

    public bool CheckHash()
    {
        var hash = I2PHashSha256.GetHash(HashedArea);
        return Hash.Equals(hash);
    }

    public void UpdateHash()
    {
        var hash = I2PHashSha256.GetHash(HashedArea);
        Hash.CopyFrom(new ReadOnlySpan<byte>(hash), 0);
    }

    public bool IsDestination(I2PIdentHash comp)
    {
        return comp.Hash16 == Data;
    }

    public override string ToString()
    {
        return Data.Length == 0
            ? "BuildResponseRecord Content: (null)"
            : $"BuildResponseRecord Content: Reply: {Reply}";
    }
}