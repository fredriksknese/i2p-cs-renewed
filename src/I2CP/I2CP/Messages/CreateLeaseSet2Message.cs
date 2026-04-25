using System.Buffers;
using System.Collections.Generic;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2P.I2CP.Messages;

public class CreateLeaseSet2Message : I2CpMessage
{
    public I2PSigningPrivateKey DsaPrivateSigningKey;
    public I2PLeaseSet Leases;
    public I2PLeaseSet2 Leases2;
    public IList<I2PPrivateKey> PrivateKeys;
    public ushort SessionId;

    public CreateLeaseSet2Message(I2PBufferCursor reader, I2CpSession session)
        : base(ProtocolMessageType.CreateLeaseSet2Message)
    {
        SessionId = reader.ReadUInt16BigEndian();

        var lstype = reader.ReadByte();
        switch (lstype)
        {
            case 1: // LS
                Leases = new I2PLeaseSet(reader);
                break;

            case 3: // LS2
                Leases2 = new I2PLeaseSet2(reader);
                break;

            case 5: // Encrypted LS2
                Logging.LogWarning(
                    "CreateLeaseSet2Message: Encrypted LS2 (type 5) received but parsing not yet supported");
                break;

            case 7: // Meta LS2
                Logging.LogWarning("CreateLeaseSet2Message: Meta LS2 (type 7) received but parsing not yet supported");
                break;
        }

        PrivateKeys = new List<I2PPrivateKey>();
        var privkeycount = reader.ReadByte();
        for (var i = 0; i < privkeycount; ++i)
        {
            var etype = (I2PKeyType.KeyTypes)reader.ReadUInt16BigEndian();
            var keylen = reader.ReadUInt16BigEndian();
            PrivateKeys.Add(new I2PPrivateKey(reader, new I2PCertificate(etype, keylen)));
        }
    }

    public override void Write(ArrayBufferWriter<byte> dest)
    {
        dest.WriteUInt16BigEndian(SessionId);

        if (Leases2 != null)
        {
            dest.WriteByte(3); // LS2 type
            Leases2.Write(dest);
        }
        else if (Leases != null)
        {
            dest.WriteByte(1); // LS type
            Leases.Write(dest);
        }

        dest.WriteByte((byte)(PrivateKeys?.Count ?? 0));
        if (PrivateKeys != null)
            foreach (var pk in PrivateKeys)
            {
                dest.WriteUInt16BigEndian((ushort)pk.Certificate.PublicKeyType);
                dest.WriteUInt16BigEndian((ushort)pk.KeySizeBytes);
                pk.Write(dest);
            }
    }
}