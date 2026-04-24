using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.Data
{
    /// <summary>
    /// MetaLeaseSet structure - DatabaseStore type 7.
    /// Contains MetaLeases that can point to other LeaseSets or routers.
    /// Supported as of 0.9.38 (proposal 123).
    /// </summary>
    public class I2PMetaLeaseSet : I2PType, ILeaseSet
    {
        public DatabaseStoreMessage.MessageContent MessageType
        {
            get => DatabaseStoreMessage.MessageContent.MetaLeaseSet;
        }

        public I2PLeaseSet2Header Header { get; set; }
        public I2PMapping Options { get; set; }
        public List<I2PMetaLease> MetaLeases { get; set; }
        public List<I2PIdentHash> Revocations { get; set; }
        public I2PSignature Signature { get; set; }

        private I2PSigningPublicKey PublicSigningKey;
        private I2PSigningPrivateKey PrivateSigningKey;

        /// <summary>
        /// Create a new MetaLeaseSet for publishing
        /// </summary>
        public I2PMetaLeaseSet(
            I2PDestination dest,
            IEnumerable<I2PMetaLease> metaleases,
            IEnumerable<I2PIdentHash> revocations,
            I2PSigningPublicKey spubkey,
            I2PSigningPrivateKey sprivkey)
        {
            var now = DateTime.UtcNow;
            var maxExpire = metaleases.Max(l => l.Expire);

            Header = new I2PLeaseSet2Header(
                dest,
                new I2PDateShort(now),
                I2PLeaseSet2Header.HeaderFlagTypes.None,
                (ushort)(maxExpire - now).TotalSeconds);

            Options = new I2PMapping();
            MetaLeases = new List<I2PMetaLease>(metaleases);
            Revocations = new List<I2PIdentHash>(revocations ?? Enumerable.Empty<I2PIdentHash>());
            PublicSigningKey = spubkey;
            PrivateSigningKey = sprivkey;
        }

        private static readonly BufLen SevenBl = BufUtils.To8Bl(7);

        /// <summary>
        /// Parse MetaLeaseSet from buffer
        /// </summary>
        public I2PMetaLeaseSet(BufRef reader)
        {
            var start = new BufRef(reader);

            Header = new I2PLeaseSet2Header(reader);
            Options = new I2PMapping(reader);

            var leaseCount = reader.Read8();
            MetaLeases = new List<I2PMetaLease>();
            for (int i = 0; i < leaseCount; ++i)
            {
                MetaLeases.Add(new I2PMetaLease(reader));
            }

            var revocationCount = reader.Read8();
            Revocations = new List<I2PIdentHash>();
            for (int i = 0; i < revocationCount; ++i)
            {
                Revocations.Add(new I2PIdentHash(reader));
            }

            var body = new BufLen(start, 0, reader - start);
            Signature = new I2PSignature(reader, Header.Destination.Certificate);

            // Verify signature
            var spkey = Header.OfflineSignature?.TransientPublicKey ?? Header.Destination.SigningPublicKey;
            var versig = I2PSignature.DoVerify(spkey, Signature, SevenBl, body);
            if (!versig)
            {
                var msg = $"I2PMetaLeaseSet: I2PSignature.DoVerify failed: {spkey.Certificate.SignatureType}";
                Logging.LogDebug(msg);
                throw new SignatureCheckFailureException(msg);
            }
        }

        public void Write(BufRefStream dest)
        {
            var ar = WriteBody().ToByteArray();

            if (Signature is null)
            {
                Signature = new I2PSignature(
                    new BufRefLen(
                        I2PSignature.DoSign(PrivateSigningKey, SevenBl, new BufLen(ar))),
                    PrivateSigningKey.Certificate);
            }

            dest.Write(ar);
            Signature.Write(dest);
        }

        private BufRefStream WriteBody()
        {
            var lbuf = new BufRefStream();

            Header.Write(lbuf);
            Options.Write(lbuf);

            lbuf.Write((byte)MetaLeases.Count);
            foreach (var lease in MetaLeases)
            {
                lease.Write(lbuf);
            }

            lbuf.Write((byte)Revocations.Count);
            foreach (var revocation in Revocations)
            {
                revocation.Write(lbuf);
            }

            return lbuf;
        }

        // ILeaseSet implementation
        public I2PDestination Destination => Header?.Destination;
        
        public DateTime Expire => 
            (DateTime)Header?.Published + TimeSpan.FromSeconds((double)Header?.ExpiresSeconds);

        public IEnumerable<ILease> Leases => MetaLeases;

        public IEnumerable<I2PPublicKey> PublicKeys
        {
            get
            {
                // MetaLeaseSet doesn't contain encryption keys directly
                return Enumerable.Empty<I2PPublicKey>();
            }
        }

        public void AddLease(I2PIdentHash tunnelgw, I2PTunnelId tunnelid, I2PDate enddate)
        {
            throw new NotSupportedException("MetaLeaseSet does not support adding regular leases. Use MetaLeases instead.");
        }

        public void RemoveLease(I2PIdentHash tunnelgw, I2PTunnelId tunnelid)
        {
            throw new NotSupportedException("MetaLeaseSet does not support removing regular leases. Use MetaLeases instead.");
        }

        public void RemoveExpired()
        {
            var now = DateTime.UtcNow;
            MetaLeases.RemoveAll(l => l.Expire < now);
        }

        public override string ToString()
        {
            return $"I2PMetaLeaseSet [{MetaLeases?.Count}]: {Destination?.IdentHash.Id32Short} " +
                $"TTL: {Expire - DateTime.UtcNow}, Revocations: {Revocations?.Count}";
        }

        byte[] ILeaseSet.ToByteArray()
        {
            var stream = new BufRefStream();
            Write(stream);
            return stream.ToByteArray();
        }
    }
}
