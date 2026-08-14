using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PLeaseSet : I2PType, ILeaseSet
{
    private readonly List<I2PLease> LeasesField = new();
    public I2PSigningPublicKey PublicSigningKey;

    public I2PSignature Signature;

    public I2PLeaseSet(
        I2PDestination dest,
        IEnumerable<I2PLease> leases,
        I2PPublicKey pubkey,
        I2PSigningPublicKey spubkey,
        I2PSigningPrivateKey sprivkey)
    {
        Destination = dest;

        PublicKey = pubkey;
        PublicSigningKey = spubkey;

        if (leases is null) return;

        leases = leases.Where(l => l.Expire > DateTime.UtcNow);

        if (leases?.Any() ?? false) LeasesField.AddRange(leases);

        if (sprivkey != null)
            Signature = new I2PSignature(
                new I2PBufferCursor(
                    CreateSignature(sprivkey)),
                sprivkey.Certificate);
    }

    public I2PLeaseSet(I2PBufferCursor reader)
    {
        Destination = new I2PDestination(reader);
        PublicKey = new I2PPublicKey(reader, I2PKeyType.DefaultAsymetricKeyCert);
        PublicSigningKey = new I2PSigningPublicKey(reader, Destination.Certificate);

        int leasecount = reader.ReadByte();
        for (var i = 0; i < leasecount; ++i) LeasesField.Add(new I2PLease(reader));

        Signature = new I2PSignature(reader, Destination.Certificate);

        if (!VerifySignature(Destination.SigningPublicKey)) throw new SignatureCheckFailureException();
    }

    public I2PPublicKey PublicKey { get; }

    public void Write(IBufferWriter<byte> dest)
    {
        Destination.Write(dest);
        PublicKey.Write(dest);
        PublicSigningKey.Write(dest);

        dest.WriteByte((byte)LeasesField.Count);

        foreach (var lease in LeasesField)
        {
            var buf = lease.ToByteArray();
            dest.WriteBytes(buf);
        }

        Signature.Write(dest);
    }

    public DatabaseStoreMessage.MessageContent MessageType => DatabaseStoreMessage.MessageContent.LeaseSet;

    public I2PDestination Destination { get; }

    public IEnumerable<ILease> Leases => LeasesField;

    public void RemoveExpired()
    {
        var now = DateTime.UtcNow;

        foreach (var ls in LeasesField.ToArray())
            if ((DateTime)ls.EndDate < now)
                LeasesField.Remove(ls);
    }

    /// <summary>
    ///     UTC of the largest EndDate for a lease
    /// </summary>
    /// <value>The end of life.</value>
    public DateTime Expire
    {
        get
        {
            if (!Leases?.Any() ?? true) return DateTime.UtcNow;
            return (DateTime)LeasesField.Max(l => l.EndDate);
        }
    }

    public IEnumerable<I2PPublicKey> PublicKeys
    {
        get { return new[] { PublicKey }; }
    }

    byte[] ILeaseSet.ToByteArray()
    {
        return this.ToByteArray();
    }

    public void AddLease(I2PIdentHash tunnelgw, I2PTunnelId tunnelid, I2PDate enddate)
    {
        RemoveExpired();

        if ((DateTime)enddate <= DateTime.UtcNow) return;

        var expsort = LeasesField
            .OrderBy(l => (ulong)l.EndDate)
            .ToArray();

        foreach (var ls in expsort)
        {
            ls.EndDate.Nudge();

            if (LeasesField.Count >= 16)
                LeasesField.Remove(ls);
            else
                break;
        }

        LeasesField.Add(new I2PLease(tunnelgw, tunnelid, enddate));
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
        else
            Logging.LogTrace( TraceCategories.TunnelTransfer,
                "I2PLeaseSet RemoveLease: No lease found to remove" );
    }

    public bool VerifySignature(I2PSigningPublicKey spkey)
    {
        try
        {
            var signfields = new List<I2PByteBlock>
            {
                new(Destination.ToByteArray()),
                PublicKey.Key,
                PublicSigningKey.Key,
                BufUtils.To8Bl((byte)LeasesField.Count)
            };

            foreach (var lease in LeasesField) signfields.Add(new I2PByteBlock(lease.ToByteArray()));

            var versig = I2PSignature.DoVerify(spkey, Signature, signfields.ToArray());
            if (!versig)
            {
                Logging.LogDebug($"I2PLeaseSet: I2PSignature.DoVerify failed: {spkey.Certificate.SignatureType}");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            Logging.LogDebug(ex);
            return false;
        }
    }

    private byte[] CreateSignature(I2PSigningPrivateKey privsignkey)
    {
        var cnt = (byte)LeasesField.Count;
        if (cnt > 16) throw new OverflowException("Max 16 leases per I2PLeaseSet");

        var signfields = new List<I2PByteBlock>
        {
            new(Destination.ToByteArray()),
            PublicKey.Key,
            PublicSigningKey.Key,
            BufUtils.To8Bl(cnt)
        };

        foreach (var lease in LeasesField)
        {
            var buf = lease.ToByteArray();
            signfields.Add(new I2PByteBlock(buf));
        }

        return I2PSignature.DoSign(privsignkey, signfields.ToArray());
    }

    public override string ToString()
    {
        return $"I2PLeaseSet [{Leases?.Count()}]: {Destination?.IdentHash.Id32Short} " +
               $"TTL: {Expire - DateTime.UtcNow} {string.Join(",", LeasesField)}";
    }
}