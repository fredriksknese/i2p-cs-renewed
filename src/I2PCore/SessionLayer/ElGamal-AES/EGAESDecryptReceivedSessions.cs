using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.SessionLayer;

/// <summary>
///     Decrypts currently received EG/AES Sessions with tags.
/// </summary>
public class EgaesDecryptReceivedSessions
{
    public const int TagLimit = 100;
    private readonly object Owner;

    private readonly TimeWindowDictionary<I2PSessionTag, I2PSessionKey> SessionTags =
        new(EgaesSessionKeyOrigin.SentTagLifetime);

    protected CbcBlockCipher Cipher = new(new AesEngine());

    public EgaesDecryptReceivedSessions(object owner)
    {
        Owner = owner;
    }

    public List<I2PPrivateKey> PrivateKeys { get; set; }

    public Garlic DecryptMessage(GarlicMessage message)
    {
        var (aesblock, sessionkey) = Garlic.RetrieveAesBlock(
            message,
            PrivateKeys.First(pk => pk.Certificate.PublicKeyType == I2PKeyType.KeyTypes.ElGamal2048),
            stag => { return SessionTags.TryRemove(stag, out var sessionkeyfound) ? sessionkeyfound : null; });

        if (aesblock is null)
        {
            Logging.LogDebug($"{Owner} ReceivedSessions: Aes block decrypt failed.");
            return null;
        }

        Logging.LogTrace( TraceCategories.LeaseMgmt, $"{Owner} ReceivedSessions: Working Aes block received. {SessionTags.Count()} tags available." );

        if (aesblock?.Tags?.Count > 0)
        {
            Logging.LogTrace( TraceCategories.LeaseMgmt, $"{Owner} ReceivedSessions: {aesblock.Tags.Count} new tags received." );
            var currenttagcount = SessionTags.Count();

            foreach (var onetag in aesblock.Tags)
            {
                if (currenttagcount >= TagLimit) break;

                SessionTags[new I2PSessionTag(new I2PBufferCursor(onetag))] =
                    aesblock?.NewSessionKey is null
                        ? sessionkey
                        : aesblock?.NewSessionKey;

                ++currenttagcount;
            }
        }

        return new Garlic(new I2PBufferCursor(aesblock.Payload));
    }

    public DatabaseLookupKeyInfo KeyGenerator(I2PIdentHash ffrouterid)
    {
        var newtag = new I2PSessionTag();
        var newkey = new I2PSessionKey();
        SessionTags[newtag] = newkey;

        return new DatabaseLookupKeyInfo
        {
            EncryptionFlag = true,
            EciesFlag = false,
            ReplyKey = newkey.Key,
            Tags = new[] { newtag.Value }
        };
    }
}