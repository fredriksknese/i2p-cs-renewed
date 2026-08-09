using System;
using System.Buffers;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     The payload of a Session Request or Session Created: a sequence of SSU2 blocks, opening
///     with a DateTime block.
///
///     <para>
///         <b>Batch 4-0i (docs/PRODUCTION-PLAN.md).</b> This repository used to write a bare
///         4-byte timestamp followed by a 2-byte padding length and 2 reserved bytes, and read
///         the same thing back. The two halves agreed with each other and with nothing on the
///         network. Verified against the Session Request i2pd 2.61.0 really sent — batch 4-2c's
///         vector — whose authenticated plaintext is:
///     </para>
///     <code>
///         00 0004 6a77a32d    DateTime block, 4 bytes, seconds since the epoch
///         fe 001a 00…         Padding block, 26 bytes
///     </code>
///     <para>
///         Read the old way, that DateTime block decodes as a timestamp of <c>0x00000406</c> —
///         a router forty years in the past, which the clock-skew check rejects even if nothing
///         else does. So the two routers could never have agreed on the time, let alone the rest.
///     </para>
///     <para>
///         <b>Unknown block types are skipped, not rejected.</b> Every block carries its own
///         length precisely so a reader can step over what it does not implement, and a peer
///         adding a block we have never heard of must not break the handshake.
///     </para>
/// </summary>
public static class SSU2HandshakePayload
{
    /// <summary>Type byte plus the two-byte big-endian length that every SSU2 block carries.</summary>
    private const int BlockHeaderSize = 3;

    /// <summary>
    ///     A serialised DateTime block: block header plus four bytes of seconds. The PQ appendix
    ///     starts here — see the note in <c>SSU2Session.BuildRequestPayload</c>.
    /// </summary>
    public const int DateTimeBlockSize = BlockHeaderSize + 4;

    /// <summary>
    ///     Build a handshake payload: a DateTime block carrying <paramref name="timestamp" />,
    ///     then a Padding block of <paramref name="paddingLength" /> bytes.
    /// </summary>
    public static byte[] Build(uint timestamp, int paddingLength)
    {
        if (paddingLength < 0) throw new ArgumentOutOfRangeException(nameof(paddingLength));

        var stream = new ArrayBufferWriter<byte>();

        stream.Write(new DateTimeBlock(timestamp).Serialize());
        if (paddingLength > 0) stream.Write(new PaddingBlock(paddingLength).Serialize());

        return stream.WrittenSpan.ToArray();
    }

    /// <summary>
    ///     Read a handshake payload. Returns what the handshake actually needs from it — the
    ///     peer's clock, for the skew check — and how much of it was padding.
    /// </summary>
    public static ParsedPayload Parse(byte[] payload)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));

        var result = new ParsedPayload();
        var offset = 0;

        while (offset + BlockHeaderSize <= payload.Length)
        {
            var blockType = (SSU2BlockType)payload[offset];
            var size = (payload[offset + 1] << 8) | payload[offset + 2];
            var dataOffset = offset + BlockHeaderSize;

            // A length that runs past the end is a malformed payload, not a block we can skip:
            // stop rather than read someone else's memory or loop forever.
            if (dataOffset + size > payload.Length) break;

            switch (blockType)
            {
                case SSU2BlockType.DateTime when size == 4:
                    result.Timestamp = (uint)((payload[dataOffset] << 24)
                                              | (payload[dataOffset + 1] << 16)
                                              | (payload[dataOffset + 2] << 8)
                                              | payload[dataOffset + 3]);
                    result.HasTimestamp = true;
                    break;

                case SSU2BlockType.Padding:
                    result.PaddingLength += size;
                    break;
            }

            offset = dataOffset + size;
        }

        return result;
    }

    /// <summary>What a handshake payload tells the session. Batch 4-0i.</summary>
    public class ParsedPayload
    {
        public uint Timestamp { get; set; }
        public bool HasTimestamp { get; set; }
        public int PaddingLength { get; set; }
    }
}
