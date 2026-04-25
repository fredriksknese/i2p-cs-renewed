using System;
using System.Buffers;
using System.Collections.Generic;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Digests;

namespace I2PCore.Data;

public class I2PHashSha256 : I2PType
{
    private readonly List<I2PType> Batch;

    public byte[] Hash;

    private BuildMode Mode;

    private byte[] SignedData;

    public I2PHashSha256()
    {
        Mode = BuildMode.BatchList;
        Batch = new List<I2PType>();
    }

    public I2PHashSha256(byte[] buf)
    {
        Mode = BuildMode.Constructor;

        Hash = DoSign(buf);
    }

    public void Write(IBufferWriter<byte> dest)
    {
        if (SignedData == null) throw new InvalidOperationException("No signed data available");
        dest.WriteBytes(SignedData);
        dest.WriteBytes(Hash);
    }

    private byte[] DoSign(byte[] buf)
    {
        return GetHash(buf, 0, buf.Length);
    }

    public static byte[] GetHash(params I2PByteBlock[] bufs)
    {
        var sha = new Sha256Digest();
        foreach (var buf in bufs) sha.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);
        return hash;
    }

    public static byte[] GetHash(I2PByteBlock buf)
    {
        var sha = new Sha256Digest();
        sha.BlockUpdate(buf.BaseArray, buf.BaseArrayOffset, buf.Length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);
        return hash;
    }

    public static byte[] GetHash(byte[] buf)
    {
        return GetHash(buf, 0, buf.Length);
    }

    public static byte[] GetHash(byte[] buf, int offset, int length)
    {
        var sha = new Sha256Digest();
        sha.BlockUpdate(buf, offset, length);
        var hash = new byte[sha.GetDigestSize()];
        sha.DoFinal(hash, 0);
        return hash;
    }

    public void Add(I2PType data)
    {
        if (Mode != BuildMode.BatchList) throw new InvalidOperationException("Cannot mix build modes");
        Batch.Add(data);
    }

    public void Sign()
    {
        if (Mode != BuildMode.BatchList) throw new InvalidOperationException("Cannot mix build modes");

        var buf = new ArrayBufferWriter<byte>();
        foreach (var data in Batch) data.Write(buf);

        SignedData = buf.WrittenSpan.ToArray();
        Hash = DoSign(SignedData);

        Mode = BuildMode.Signed;
    }

    public bool Verify(byte[] buf, int offset, int length)
    {
        if (Mode != BuildMode.Signed) throw new InvalidOperationException("No signature available");

        var hash = GetHash(buf, offset, length);
        return Equals(Hash, hash);
    }

    public void WriteSigOnly(IBufferWriter<byte> dest)
    {
        dest.WriteBytes(Hash);
    }

    public void WriteContentOnly(IBufferWriter<byte> dest)
    {
        dest.WriteBytes(SignedData);
    }

    private enum BuildMode
    {
        Constructor,
        BatchList,
        Signed
    }
}