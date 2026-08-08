using System;
using System.Net;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages;

/// <summary>
///     SSU2 Retry (type 9) and the TokenRequest (type 10) it answers.
///
///     <para>
///         Batch 4-2a (docs/PRODUCTION-PLAN.md). i2pd's <b>first</b> packet to a peer it holds no
///         token for is a TokenRequest, and nothing in this repository handled type 10 — it fell
///         through <c>SSU2Host.DispatchPacket</c>'s final <c>else</c> to "Received packet type 10
///         from unknown endpoint". <b>So an inbound SSU2 session from i2pd could not begin at
///         all</b>, which is a large part of why Phase 4 had nothing to measure.
///     </para>
///     <para>
///         <b>The wire format here is verified, not inferred.</b> Batch 3-5 captured a real i2pd
///         TokenRequest (<c>TestData/ssu2_tokenrequest_i2pd.txt</c>) and batch 4-2a decrypted it
///         end to end: the Poly1305 tag authenticates with the key being the responder's intro
///         key, the AD being all 32 plaintext header bytes, and the nonce being
///         <see cref="ChaCha20Poly1305.CreateNonce" /> over the header's packet number. A
///         verifying tag over that AD proves every header byte was recovered exactly as i2pd
///         wrote it — far stronger than the three bytes <c>Ssu2GoldenVectorTest</c> checks.
///         <c>Ssu2RetryTokenTest</c> reproduces that decode as a standing test.
///     </para>
///     <para>
///         Header masking is the <b>16-byte</b> tail form — <see cref="SSU2HeaderEncryption" />'s
///         <c>EncryptLongHeaderComplete</c> — because neither message carries an ephemeral key.
///         <b>Batch 4-0b must not change this path</b>: its 48-byte single pass applies only to
///         Session Request and Session Created, and the captured bytes above pin the 16-byte form
///         for these two.
///     </para>
/// </summary>
public static class Retry
{
    /// <summary>
    ///     A Retry is 32 header + payload + 16 tag. <c>EncryptLongHeaderInPacket</c> derives its
    ///     IVs from the last 24 bytes of the packet, so a packet shorter than 64 bytes would read
    ///     its own header as an IV; the padding below keeps us clear of that by construction.
    /// </summary>
    private const int MinPayloadBytes = 32;

    /// <summary>
    ///     Build a Retry answering <paramref name="request" />, carrying <paramref name="token" />.
    ///
    ///     <para>
    ///         <b>The connection IDs are echoed, not recomputed.</b> Ours becomes the request's
    ///         source ID and vice versa: i2pd routes an inbound packet by the destination
    ///         connection ID it recovers, and a Retry addressed to anything else is dropped
    ///         silently at both ends. This is the single likeliest way to get a Retry subtly
    ///         wrong.
    ///     </para>
    /// </summary>
    public static byte[] Build( SSU2Header request, ulong token, byte[] introKey, IPEndPoint remote )
    {
        if ( request == null ) throw new ArgumentNullException( nameof( request ) );
        if ( introKey == null ) throw new ArgumentNullException( nameof( introKey ) );

        var header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_RETRY,
            Version = 2,
            NetId = (byte)I2PConstants.I2PNetworkId,
            Flag = 0,
            DestinationConnectionId = request.SourceConnectionId,
            SourceConnectionId = request.DestinationConnectionId,
            Token = token,
            PacketNumber = BufUtils.RandomUint()
        };

        var headerBytes = header.ToByteArray();
        var payload = BuildPayload( remote );

        // AD is the plaintext header; masking happens afterwards, over the finished packet.
        var nonce = ChaCha20Poly1305.CreateNonce( header.PacketNumber );
        var encrypted = ChaCha20Poly1305.Encrypt( introKey, nonce, payload, headerBytes );

        var packet = new byte[headerBytes.Length + encrypted.Length];
        Array.Copy( headerBytes, 0, packet, 0, headerBytes.Length );
        Array.Copy( encrypted, 0, packet, headerBytes.Length, encrypted.Length );

        // Last, because the mask for bytes 0-15 is keyed on IVs taken from the packet's tail.
        SSU2HeaderEncryption.EncryptLongHeaderComplete( packet, 0, introKey, introKey );

        return packet;
    }

    /// <summary>
    ///     Recover the plaintext header and payload of a TokenRequest or Retry masked with
    ///     <paramref name="introKey" />, or null if it is not one / does not authenticate.
    ///
    ///     <para>
    ///         Static and host-free on purpose: it is the entry point the golden-vector test
    ///         drives, so the convention can be checked against real i2pd bytes without standing
    ///         up a router.
    ///     </para>
    /// </summary>
    public static bool TryOpen(
        byte[] packet, byte[] introKey, byte expectedType, out SSU2Header header, out byte[] payload )
    {
        header = null;
        payload = null;

        // 32-byte header plus a 16-byte tag is the floor; below it the IV derivation would read
        // header bytes as an IV.
        if ( packet == null || packet.Length < 64 || introKey == null ) return false;

        var plaintextHeader = (byte[])packet.Clone();
        SSU2HeaderEncryption.DecryptLongHeaderComplete( plaintextHeader, 0, introKey, introKey );

        var parsed = SSU2Header.ParseLongHeader( new I2PBufferCursor( plaintextHeader ) );
        if ( parsed.Type != expectedType ) return false;

        var headerBytes = new byte[SSU2Header.LONG_HEADER_SIZE];
        Array.Copy( plaintextHeader, 0, headerBytes, 0, headerBytes.Length );

        var ciphertext = new byte[packet.Length - SSU2Header.LONG_HEADER_SIZE];
        Array.Copy( packet, SSU2Header.LONG_HEADER_SIZE, ciphertext, 0, ciphertext.Length );

        var decrypted = ChaCha20Poly1305.Decrypt(
            introKey, ChaCha20Poly1305.CreateNonce( parsed.PacketNumber ), ciphertext, headerBytes );

        if ( decrypted == null ) return false;

        header = parsed;
        payload = decrypted;

        return true;
    }

    /// <summary>
    ///     DateTime, the peer's observed address, and padding. i2pd clock-skew-checks the
    ///     timestamp, so it is ours rather than an echo of the request's.
    /// </summary>
    private static byte[] BuildPayload( IPEndPoint remote )
    {
        var dateTime = new DateTimeBlock().Serialize();
        var address = new AddressBlock
        {
            IPAddress = remote?.Address?.GetAddressBytes() ?? new byte[4],
            Port = (ushort)( remote?.Port ?? 0 )
        }.Serialize();

        var bodyLength = dateTime.Length + address.Length;
        var padding = new PaddingBlock( Math.Max( MinPayloadBytes - bodyLength, 1 ) ).Serialize();

        var payload = new byte[bodyLength + padding.Length];
        Array.Copy( dateTime, 0, payload, 0, dateTime.Length );
        Array.Copy( address, 0, payload, dateTime.Length, address.Length );
        Array.Copy( padding, 0, payload, bodyLength, padding.Length );

        return payload;
    }
}
