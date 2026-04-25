using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PLeaseSet2 : I2PType, ILeaseSet
{
    private static readonly I2PByteBlock ThreeBl = BufUtils.To8Bl(3);
    private readonly I2PSigningPrivateKey PrivateSigningKey;
    private readonly IList<I2PPublicKey> PublicKeysField;
    public List<I2PLease2> LeasesField;

    private I2PSigningPublicKey PublicSigningKey;

    public I2PLeaseSet2(
        I2PDestination dest,
        IEnumerable<I2PLease2> leases,
        IList<I2PPublicKey> pubkeys,
        I2PSigningPublicKey spubkey,
        I2PSigningPrivateKey sprivkey)
    {
        var now = DateTime.UtcNow;

        Header = new I2PLeaseSet2Header(
            dest,
            new I2PDateShort(now),
            I2PLeaseSet2Header.HeaderFlagTypes.None,
            (ushort)(leases.Any()
                ? (leases.Max(l => l.Expire) - now).TotalSeconds
                : I2PLease2.DefaultLeaseLifetimeSeconds));
        Options = new I2PMapping();

        PublicKeysField = pubkeys;
        LeasesField =
            new List<I2PLease2>(leases?.Where(l => l.Expire > DateTime.UtcNow) ?? Enumerable.Empty<I2PLease2>());
        PublicSigningKey = spubkey;
        PrivateSigningKey = sprivkey;
    }

    public I2PLeaseSet2(I2PBufferCursor reader)
    {
        var startPos = reader.Position;

        Header = new I2PLeaseSet2Header(reader);
        Options = new I2PMapping(reader);

        var keycount = reader.ReadByte();
        PublicKeysField = new List<I2PPublicKey>();
        for (var i = 0; i < keycount; ++i)
        {
            var keytype = reader.ReadUInt16BigEndian();
            var keylen = reader.ReadUInt16BigEndian();
            var cert = new I2PCertificate((I2PKeyType.KeyTypes)keytype, keylen);
            PublicKeysField.Add(new I2PPublicKey(reader, cert));
        }

        var leasecount = reader.ReadByte();
        LeasesField = new List<I2PLease2>();
        for (var i = 0; i < leasecount; ++i) LeasesField.Add(new I2PLease2(reader));

        var body = reader.BlockSince(startPos);
        Signature = new I2PSignature(reader, Header.Destination.Certificate);

        var spkey = Header.Destination.SigningPublicKey;
        var versig = I2PSignature.DoVerify(spkey, Signature, ThreeBl, body);
        if (!versig)
        {
            var msg = $"I2PLeaseSet: I2PSignature.DoVerify failed: {spkey.Certificate.SignatureType}";
            Logging.LogDebug(msg);
            throw new SignatureCheckFailureException(msg);
        }
    }

    public I2PLeaseSet2Header Header { get; set; }
    public I2PMapping Options { get; set; }
    public I2PSignature Signature { get; set; }

    public void Write(IBufferWriter<byte> dest)
    {
        var ar = WriteBody().WrittenSpan.ToArray();

        if (Signature is null)
            Signature = new I2PSignature(
                new I2PBufferCursor(
                    I2PSignature.DoSign(PrivateSigningKey, ThreeBl, new I2PByteBlock(ar))),
                PrivateSigningKey.Certificate);

        dest.WriteBytes(ar);
        Signature.Write(dest);
    }

    public DatabaseStoreMessage.MessageContent MessageType => DatabaseStoreMessage.MessageContent.LeaseSet2;
    public IEnumerable<ILease> Leases => LeasesField;

    // ILeaseSet
    public I2PDestination Destination => Header?.Destination;
    public DateTime Expire => (DateTime)Header?.Published + TimeSpan.FromSeconds((double)Header?.ExpiresSeconds);

    public IEnumerable<I2PPublicKey> PublicKeys => PublicKeysField;

    public void RemoveExpired()
    {
        var now = DateTime.UtcNow;

        foreach (var ls in LeasesField.ToArray())
            if ((DateTime)ls.EndDate < now)
                LeasesField.Remove(ls);
    }

    byte[] ILeaseSet.ToByteArray()
    {
        return this.ToByteArray();
    }

    private ArrayBufferWriter<byte> WriteBody()
    {
        var lbuf = new ArrayBufferWriter<byte>();

        Header.Write(lbuf);
        Options.Write(lbuf);

        var keycount = (byte)PublicKeysField.Count;
        lbuf.WriteByte(keycount);
        foreach (var key in PublicKeysField)
        {
            lbuf.WriteUInt16BigEndian((ushort)key.Certificate.PublicKeyType);
            lbuf.WriteUInt16BigEndian((ushort)key.Certificate.PublicKeyLength);
            key.Write(lbuf);
        }

        lbuf.WriteByte((byte)LeasesField.Count);
        foreach (var lease in LeasesField) lease.Write(lbuf);

        return lbuf;
    }

    public void AddLease(I2PIdentHash tunnelgw, I2PTunnelId tunnelid, I2PDate enddate)
    {
        RemoveExpired();

        if ((DateTime)enddate <= DateTime.UtcNow) return;

        var endshort = new I2PDateShort(enddate);

        var expsort = LeasesField
            .OrderBy(l => l.Expire)
            .ToArray();

        foreach (var ls in expsort)
            if (LeasesField.Count >= 16)
                LeasesField.Remove(ls);
            else
                break;

        LeasesField.Add(new I2PLease2(tunnelgw, tunnelid, endshort));
    }

    public void RemoveLease(I2PIdentHash tunnelgw, I2PTunnelId tunnelid)
    {
        var remove = LeasesField
            .Where(l =>
                l.TunnelId == tunnelid
                && l.TunnelGw == tunnelgw)
            .Select(l => l)
            .ToArray();

        if (remove.Length != 0)
            foreach (var one in remove)
                LeasesField.Remove(one);
#if LOG_ALL_TUNNEL_TRANSFER
            else
            {
                Logging.LogDebug( "I2PLeaseSet RemoveLease: No lease found to remove" );
            }
#endif
    }

    public override string ToString()
    {
        return $"I2PLeaseSet2 [{Leases?.Count()}]: {Destination?.IdentHash.Id32Short} " +
               $"TTL: {Expire - DateTime.UtcNow} {string.Join(",", LeasesField)}";
    }
}