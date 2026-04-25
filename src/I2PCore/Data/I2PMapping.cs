using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PMapping : I2PType, IEnumerable<KeyValuePair<I2PString, I2PString>>
{
    // The Mapping must be sorted by key so that the signature will be validated correctly in the router. 
    public SortedDictionary<I2PString, I2PString> Mappings = new(new I2PStringComparer());

    public I2PMapping()
    {
    }

    public I2PMapping(I2PBufferCursor buf)
    {
        var bytes = buf.ReadUInt16BigEndian();
        var endpos = buf.BaseArrayOffset + bytes;

        while (buf.BaseArrayOffset < endpos)
        {
            var key = new I2PString(buf);
            if (buf.BaseArrayOffset < endpos && buf.PeekByte(0) == '=') buf.Seek(1);
            var value = new I2PString(buf);
            if (buf.BaseArrayOffset < endpos && buf.PeekByte(0) == ';') buf.Seek(1);
            Mappings[key] = value;
        }
    }

    public string this[string key]
    {
        get => Mappings[new I2PString(key)].ToString();
        set => Mappings[new I2PString(key)] = new I2PString(value);
    }

    public void Write(IBufferWriter<byte> dest)
    {
        var buf = new ArrayBufferWriter<byte>();

        foreach (var one in Mappings)
        {
            one.Key.Write(buf);
            buf.WriteByte((byte)'=');
            one.Value.Write(buf);
            buf.WriteByte((byte)';');
        }

        dest.WriteUInt16BigEndian((ushort)buf.WrittenCount);
        dest.WriteFrom(buf);
    }

    public IEnumerator<KeyValuePair<I2PString, I2PString>> GetEnumerator()
    {
        return Mappings.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return Mappings.GetEnumerator();
    }

    public I2PString TryGet(string key)
    {
        return Mappings.TryGetValue(new I2PString(key), out var result) ? result : null;
    }

    public string TryGet(string key, string def)
    {
        return Mappings.TryGetValue(new I2PString(key), out var result) ? result.ToString() : def;
    }

    public bool TryGet(string key, out I2PString result)
    {
        return Mappings.TryGetValue(new I2PString(key), out result);
    }

    public bool Contains(string key)
    {
        return Mappings.ContainsKey(new I2PString(key));
    }

    public bool ValueContains(string key, string value)
    {
        var val = TryGet(key);
        if (val == null) return false;
        return val.ToString().Contains(value);
    }

    public override string ToString()
    {
        var result = new StringBuilder();

        result.Append("I2PMapping: Pairs: ->");
        foreach (var one in Mappings) result.AppendFormat("({0}:{1})", one.Key, one.Value);
        result.Append("<-");

        return result.ToString();
    }
}