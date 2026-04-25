using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.TunnelLayer;

public class TunnelBuildRequestDecrypt
{
    private readonly I2PPrivateKey Key;
    private readonly I2PIdentHash Me;
    private readonly EgBuildRequestRecord MyRecord;
    private readonly AesEgBuildRequestRecord ToMeField;

    public TunnelBuildRequestDecrypt(
        IEnumerable<AesEgBuildRequestRecord> records,
        I2PIdentHash me,
        I2PPrivateKey key)
    {
        Records = records;
        Me = me;
        Key = key;

        ToMeField = Records.FirstOrDefault(rec => Me.Hash16 == rec.ToPeer16);

        if (ToMeField != null)
        {
            MyRecord = new EgBuildRequestRecord(ToMeField);
            try
            {
                Decrypted = MyRecord.Decrypt(key);
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"TunnelBuildRequestDecrypt: Decryption failed for {Me.Id32Short}: {ex.Message}");
            }
        }
    }

    public BuildRequestRecord Decrypted { get; }

    public IEnumerable<AesEgBuildRequestRecord> Records { get; }

    public TunnelBuildRequestDecrypt Clone()
    {
        return new TunnelBuildRequestDecrypt(
            Records.Select(r => r.Clone()),
            Me,
            Key);
    }

    public AesEgBuildRequestRecord ToMe()
    {
        return ToMeField;
    }

    public IEnumerable<AesEgBuildRequestRecord> CreateTunnelBuildReplyRecords(
        BuildResponseRecord.RequestResponse response)
    {
        var newrecords = new List<AesEgBuildRequestRecord>(
            Records.Select(r => r.Clone())
        );

        var tmp = new TunnelBuildRequestDecrypt(newrecords, Me, Key);

        tmp.ToMeField.Data.Randomize();
        var responserec = new BuildResponseRecord(tmp.ToMeField.Data)
        {
            Reply = response
        };
        responserec.UpdateHash();

        var cipher = new CbcBlockCipher(new AesEngine());
        cipher.Init(true, Decrypted.ReplyKeyBuf.ToParametersWithIv(Decrypted.ReplyIv));

        foreach (var one in newrecords)
        {
            cipher.Reset();
            one.Process(cipher);
        }

        return newrecords;
    }


    public override string ToString()
    {
        return $"{GetType().Name} {Decrypted}";
    }
}