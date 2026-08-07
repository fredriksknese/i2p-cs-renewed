using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.ECIES;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace I2PTests;

/// <summary>
///     Ported from TunnelProvider.RunNoiseNSelfTest, which ran unconditionally on every router
///     start and reported its results by writing 17 LogCritical lines — visible at every log
///     level, and unable to fail anything because it only logged and swallowed exceptions.
///     Batch 0-5 put the runtime copy behind --self-test and moved the checks here, where a
///     mismatch actually fails a build.
///
///     What it proves: our Noise N encryption of a ShortTunnelBuild record is decryptable by
///     our own responder, both sides derive identical keys, and the record survives the
///     ShortTunnelBuildMessage round trip into ECIESTunnelDecrypt with its fields intact. If
///     this breaks, remote peers cannot decrypt our tunnel build requests either.
/// </summary>
[TestFixture]
public class NoiseNSelfTest
{
    private const uint TestReceiveTunnelId = 12345u;
    private const uint TestNextTunnelId = 67890u;
    private const uint TestNextMessageId = 0xDEADBEEF;
    private const int NoiseMessageSize = 202;
    private const int RouterHashPrefixSize = 16;

    private RouterContext _ctx;
    private byte[] _encPubKey;
    private byte[] _decPrivKey;
    private I2PIdentHash _ourIdentHash;

    [SetUp]
    public void Setup()
    {
        // A standalone context, not RouterContext.Inst — this test must not depend on or
        // disturb process-wide router state.
        _ctx = new RouterContext();
        _ourIdentHash = _ctx.MyRouterIdentity.IdentHash;
        _encPubKey = _ctx.X25519PublicKey;
        _decPrivKey = _ctx.X25519PrivateKey;
    }

    private ShortBuildRequestRecord MakeTestRecord()
    {
        return new ShortBuildRequestRecord
        {
            ReceiveTunnelId = new I2PTunnelId( TestReceiveTunnelId ),
            NextRouterHash = _ourIdentHash,
            NextTunnelId = new I2PTunnelId( TestNextTunnelId ),
            Flags = (byte)ShortBuildRequestRecord.BuildRequestFlags.OutboundEndpoint,
            RequestTime = (uint)( DateTime.UtcNow - I2PDate.RefDate ).TotalMinutes,
            RequestExpiration = 600,
            NextMessageId = TestNextMessageId
        };
    }

    /// <summary>Encrypts to our own key and returns the initiator's transcript state.</summary>
    private (byte[] cleartext, byte[] noiseMessage, byte[] ck, byte[] hash) EncryptToSelf()
    {
        var cleartext = MakeTestRecord().ToByteArray();

        var noiseInit = NoiseN.CreateInitiator( _encPubKey );
        var noiseMessage = noiseInit.CreateMessage( cleartext );
        var ck = noiseInit.GetChainingKey();
        var hash = noiseInit.GetHash();
        noiseInit.Dispose();

        return ( cleartext, noiseMessage, ck, hash );
    }

    private byte[] BuildOnWireRecord( byte[] noiseMessage )
    {
        var onWireRecord = new byte[ShortBuildRequestRecord.OnWireRecordSize];
        var hashBytes = _ourIdentHash.Hash.ToByteArray();

        Array.Copy( hashBytes, 0, onWireRecord, 0, RouterHashPrefixSize );
        Array.Copy( noiseMessage, 0, onWireRecord, RouterHashPrefixSize, noiseMessage.Length );

        return onWireRecord;
    }

    [Test]
    public void ResponderRecoversTheCleartextWeEncrypted()
    {
        var ( cleartext, noiseMessage, _, _ ) = EncryptToSelf();

        var noiseResp = NoiseN.CreateResponder( _decPrivKey, _encPubKey );
        var decrypted = noiseResp.ProcessMessage( noiseMessage );
        noiseResp.Dispose();

        CollectionAssert.AreEqual( cleartext, decrypted,
            "our own responder must recover what our initiator encrypted" );
    }

    [Test]
    public void BothSidesAgreeOnTheNoiseTranscript()
    {
        var ( _, noiseMessage, initCK, initHash ) = EncryptToSelf();

        var noiseResp = NoiseN.CreateResponder( _decPrivKey, _encPubKey );
        noiseResp.ProcessMessage( noiseMessage );
        var respCK = noiseResp.GetChainingKey();
        var respHash = noiseResp.GetHash();
        noiseResp.Dispose();

        CollectionAssert.AreEqual( initCK, respCK, "chaining keys diverged" );
        CollectionAssert.AreEqual( initHash, respHash, "transcript hashes diverged" );
    }

    [Test]
    public void BothSidesDeriveIdenticalTunnelKeys()
    {
        var ( _, noiseMessage, initCK, initHash ) = EncryptToSelf();

        var noiseResp = NoiseN.CreateResponder( _decPrivKey, _encPubKey );
        noiseResp.ProcessMessage( noiseMessage );
        var respCK = noiseResp.GetChainingKey();
        var respHash = noiseResp.GetHash();
        noiseResp.Dispose();

        var ( initLayer, initIv, initReply, _, initGarlic, initTag ) =
            ShortBuildRequestRecord.DeriveAllKeys( initCK, initHash, true );
        var ( respLayer, respIv, respReply, _, respGarlic, respTag ) =
            ShortBuildRequestRecord.DeriveAllKeys( respCK, respHash, true );

        CollectionAssert.AreEqual( initLayer, respLayer, "layer key mismatch" );
        CollectionAssert.AreEqual( initIv, respIv, "IV key mismatch" );
        CollectionAssert.AreEqual( initReply, respReply, "reply key mismatch" );

        ClassicAssert.IsNotNull( initGarlic, "initiator garlic key must be derived" );
        ClassicAssert.IsNotNull( respGarlic, "responder garlic key must be derived" );
        CollectionAssert.AreEqual( initGarlic, respGarlic, "garlic key mismatch" );

        ClassicAssert.AreEqual( initTag, respTag, "garlic tag mismatch" );
    }

    /// <summary>
    ///     The record has to survive being carried in a ShortTunnelBuildMessage byte-for-byte;
    ///     a single shifted byte breaks the AEAD.
    /// </summary>
    [Test]
    public void RecordBytesSurviveTheShortTunnelBuildMessageRoundTrip()
    {
        var ( _, noiseMessage, _, _ ) = EncryptToSelf();
        var onWireRecord = BuildOnWireRecord( noiseMessage );

        var stbm = MakeMessageWithRecordFirst( onWireRecord );
        var stbmRecordBytes = stbm.Records[0].ToByteArray();

        CollectionAssert.AreEqual( onWireRecord, stbmRecordBytes,
            "the on-wire record must round-trip through ShortTunnelBuildMessage unchanged" );
    }

    /// <summary>
    ///     ECIESTunnelDecrypt reads the Noise message with Peek rather than by copying, so the
    ///     two extraction paths have to agree.
    /// </summary>
    [Test]
    public void PeekExtractionMatchesTheEncryptedNoiseMessage()
    {
        var ( _, noiseMessage, _, _ ) = EncryptToSelf();
        var onWireRecord = BuildOnWireRecord( noiseMessage );

        var stbm = MakeMessageWithRecordFirst( onWireRecord );

        var peekNoise = new byte[NoiseMessageSize];
        stbm.Records[0].Peek( peekNoise, RouterHashPrefixSize, 0, NoiseMessageSize );

        CollectionAssert.AreEqual( noiseMessage, peekNoise,
            "Peek must yield the same bytes the initiator produced" );
    }

    // NOT PORTED: the self-test's final stage, ECIESTunnelDecrypt.ProcessShortTunnelBuild.
    //
    // ECIESTunnelDecrypt takes the decryption keys as constructor arguments but selects which
    // record is "ours" by reading RouterContext.Inst.MyRouterIdentity directly
    // (ECIESTunnelDecrypt.cs:56-57). Constructor keys and selection identity can therefore
    // disagree, and they do here: driving it from a standalone RouterContext makes the record
    // unfindable and Success comes back false, while the same code reports success at runtime
    // purely because the singleton happens to be the identity that built the record.
    //
    // Covering it in the unit suite would mean depending on process-wide router state — which
    // no unit test currently does, and which writes router files into the working directory.
    // Left uncovered here on purpose. It stays exercised by the runtime --self-test path and
    // by the integration suite; Phase 8 (de-singleton) is what makes it unit-testable, and
    // batch p8/instance-routercontext should pick this up.

    /// <summary>Our record first, then three random decoys, as a real build message carries.</summary>
    private static ShortTunnelBuildMessage MakeMessageWithRecordFirst( byte[] onWireRecord )
    {
        return new ShortTunnelBuildMessage( new List<byte[]>
        {
            onWireRecord,
            BufUtils.RandomBytes( ShortBuildRequestRecord.OnWireRecordSize ),
            BufUtils.RandomBytes( ShortBuildRequestRecord.OnWireRecordSize ),
            BufUtils.RandomBytes( ShortBuildRequestRecord.OnWireRecordSize )
        } );
    }
}
