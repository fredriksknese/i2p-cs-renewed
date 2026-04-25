using System;

namespace I2PCore.Crypto;

/// <summary>
///     SHA3-256 implementation (FIPS 202)
///     Used by ML-KEM for hashing operations
/// </summary>
public class SHA3_256
{
    private const int StateSize = 200; // 1600 bits / 8
    private const int Rate = 136; // 1088 bits / 8 for SHA3-256
    private const int OutputLength = 32; // 256 bits / 8
    private const int Capacity = StateSize - Rate;

    // Keccak round constants
    private static readonly ulong[] RoundConstants = new[]
    {
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL,
        0x8000000080008000UL, 0x000000000000808BUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008AUL,
        0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
        0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL,
        0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800AUL, 0x800000008000000AUL, 0x8000000080008081UL,
        0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
    };

    // Rotation offsets
    private static readonly int[] RotationOffsets = new[]
    {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    };

    private readonly byte[] buffer = new byte[Rate];

    private readonly ulong[] state = new ulong[25];
    private int bufferPos;

    /// <summary>
    ///     Compute SHA3-256 hash of input data
    /// </summary>
    public static byte[] Hash(byte[] input)
    {
        var sha3 = new SHA3_256();
        sha3.Update(input);
        return sha3.Final();
    }

    /// <summary>
    ///     Update hash with more data
    /// </summary>
    public void Update(byte[] data)
    {
        Update(data, 0, data.Length);
    }

    /// <summary>
    ///     Update hash with data segment
    /// </summary>
    public void Update(byte[] data, int offset, int length)
    {
        var remaining = length;
        var dataOffset = offset;

        while (remaining > 0)
        {
            var copyLen = Math.Min(remaining, Rate - bufferPos);
            Array.Copy(data, dataOffset, buffer, bufferPos, copyLen);
            bufferPos += copyLen;
            dataOffset += copyLen;
            remaining -= copyLen;

            if (bufferPos == Rate)
            {
                AbsorbBlock();
                bufferPos = 0;
            }
        }
    }

    /// <summary>
    ///     Finalize hash and return digest
    /// </summary>
    public byte[] Final()
    {
        // SHA3 padding: append 0x06 then fill with zeros and final 0x80
        buffer[bufferPos] = 0x06;
        for (var i = bufferPos + 1; i < Rate; i++) buffer[i] = 0;
        buffer[Rate - 1] |= 0x80;

        AbsorbBlock();

        // Squeeze output
        var output = new byte[OutputLength];
        StateToBytes(output, 0, OutputLength);
        return output;
    }

    private void AbsorbBlock()
    {
        // XOR block into state
        for (var i = 0; i < Rate / 8; i++) state[i] ^= BytesToLane(buffer, i * 8);

        KeccakF1600();
    }

    private void KeccakF1600()
    {
        var b = new ulong[25];
        var c = new ulong[5];
        var d = new ulong[5];

        for (var round = 0; round < 24; round++)
        {
            // Theta step
            for (var i = 0; i < 5; i++) c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];

            for (var i = 0; i < 5; i++) d[i] = c[(i + 4) % 5] ^ RotateLeft(c[(i + 1) % 5], 1);

            for (var i = 0; i < 25; i++) state[i] ^= d[i % 5];

            // Rho and Pi steps
            for (var i = 0; i < 25; i++)
            {
                var j = i % 5 * 5 + i / 5; // transpose
                b[j] = RotateLeft(state[i], RotationOffsets[i]);
            }

            // Chi step
            for (var i = 0; i < 5; i++)
            for (var j = 0; j < 5; j++)
            {
                var idx = i * 5 + j;
                state[idx] = b[idx] ^ (~b[i * 5 + (j + 1) % 5] & b[i * 5 + (j + 2) % 5]);
            }

            // Iota step
            state[0] ^= RoundConstants[round];
        }
    }

    private static ulong RotateLeft(ulong value, int bits)
    {
        return (value << bits) | (value >> (64 - bits));
    }

    private static ulong BytesToLane(byte[] data, int offset)
    {
        ulong result = 0;
        for (var i = 0; i < 8; i++) result |= (ulong)data[offset + i] << (8 * i);
        return result;
    }

    private void StateToBytes(byte[] output, int offset, int length)
    {
        var laneCount = (length + 7) / 8;
        for (var i = 0; i < laneCount && i * 8 < length; i++)
            LaneToBytes(state[i], output, offset + i * 8, Math.Min(8, length - i * 8));
    }

    private static void LaneToBytes(ulong lane, byte[] output, int offset, int length)
    {
        for (var i = 0; i < length; i++) output[offset + i] = (byte)((lane >> (8 * i)) & 0xFF);
    }
}

/// <summary>
///     SHAKE128 and SHAKE256 XOF (Extendable-Output Functions) (FIPS 202)
///     Used by ML-KEM for key generation and other operations
/// </summary>
public class SHAKE
{
    private const int StateSize = 200;
    private readonly byte[] buffer;

    private readonly int rate;
    private readonly ulong[] state = new ulong[25];
    private int bufferPos;
    private bool squeezing;

    private SHAKE(int rate)
    {
        this.rate = rate;
        buffer = new byte[rate];
    }

    /// <summary>
    ///     Create SHAKE128 instance (rate = 168 bytes)
    /// </summary>
    public static SHAKE CreateShake128()
    {
        return new SHAKE(168); // 1344 bits / 8
    }

    /// <summary>
    ///     Create SHAKE256 instance (rate = 136 bytes)
    /// </summary>
    public static SHAKE CreateShake256()
    {
        return new SHAKE(136); // 1088 bits / 8
    }

    /// <summary>
    ///     Absorb input data
    /// </summary>
    public void Absorb(byte[] input)
    {
        if (squeezing)
            throw new InvalidOperationException("Cannot absorb after squeezing");

        Absorb(input, 0, input.Length);
    }

    /// <summary>
    ///     Absorb input data segment
    /// </summary>
    public void Absorb(byte[] input, int offset, int length)
    {
        if (squeezing)
            throw new InvalidOperationException("Cannot absorb after squeezing");

        var remaining = length;
        var dataOffset = offset;

        while (remaining > 0)
        {
            var copyLen = Math.Min(remaining, rate - bufferPos);
            Array.Copy(input, dataOffset, buffer, bufferPos, copyLen);
            bufferPos += copyLen;
            dataOffset += copyLen;
            remaining -= copyLen;

            if (bufferPos == rate)
            {
                AbsorbBlock();
                bufferPos = 0;
            }
        }
    }

    /// <summary>
    ///     Squeeze output bytes
    /// </summary>
    public byte[] Squeeze(int outputLength)
    {
        var output = new byte[outputLength];
        Squeeze(output, 0, outputLength);
        return output;
    }

    /// <summary>
    ///     Squeeze output bytes into buffer
    /// </summary>
    public void Squeeze(byte[] output, int offset, int length)
    {
        if (!squeezing)
        {
            // Finalize absorption with SHAKE padding (0x1F)
            buffer[bufferPos] = 0x1F;
            for (var i = bufferPos + 1; i < rate; i++) buffer[i] = 0;
            buffer[rate - 1] |= 0x80;
            AbsorbBlock();
            bufferPos = 0;
            squeezing = true;
        }

        var remaining = length;
        var outOffset = offset;

        while (remaining > 0)
        {
            if (bufferPos == 0) StateToBytes(buffer, 0, rate);

            var copyLen = Math.Min(remaining, rate - bufferPos);
            Array.Copy(buffer, bufferPos, output, outOffset, copyLen);
            bufferPos += copyLen;
            outOffset += copyLen;
            remaining -= copyLen;

            if (bufferPos == rate)
            {
                KeccakF1600();
                bufferPos = 0;
            }
        }
    }

    private void AbsorbBlock()
    {
        for (var i = 0; i < rate / 8; i++) state[i] ^= BytesToLane(buffer, i * 8);
        KeccakF1600();
    }

    private void KeccakF1600()
    {
        var b = new ulong[25];
        var c = new ulong[5];
        var d = new ulong[5];

        for (var round = 0; round < 24; round++)
        {
            // Theta
            for (var i = 0; i < 5; i++) c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];

            for (var i = 0; i < 5; i++) d[i] = c[(i + 4) % 5] ^ RotateLeft(c[(i + 1) % 5], 1);

            for (var i = 0; i < 25; i++) state[i] ^= d[i % 5];

            // Rho and Pi
            for (var i = 0; i < 25; i++)
            {
                var j = i % 5 * 5 + i / 5;
                b[j] = RotateLeft(state[i], KeccakConstants.RotationOffsets[i]);
            }

            // Chi
            for (var i = 0; i < 5; i++)
            for (var j = 0; j < 5; j++)
            {
                var idx = i * 5 + j;
                state[idx] = b[idx] ^ (~b[i * 5 + (j + 1) % 5] & b[i * 5 + (j + 2) % 5]);
            }

            // Iota
            state[0] ^= KeccakConstants.RoundConstants[round];
        }
    }

    private static ulong RotateLeft(ulong value, int bits)
    {
        return (value << bits) | (value >> (64 - bits));
    }

    private static ulong BytesToLane(byte[] data, int offset)
    {
        ulong result = 0;
        for (var i = 0; i < 8; i++) result |= (ulong)data[offset + i] << (8 * i);
        return result;
    }

    private void StateToBytes(byte[] output, int offset, int length)
    {
        var laneCount = (length + 7) / 8;
        for (var i = 0; i < laneCount && i * 8 < length; i++)
            LaneToBytes(state[i], output, offset + i * 8, Math.Min(8, length - i * 8));
    }

    private static void LaneToBytes(ulong lane, byte[] output, int offset, int length)
    {
        for (var i = 0; i < length; i++) output[offset + i] = (byte)((lane >> (8 * i)) & 0xFF);
    }

    // Make RotationOffsets accessible
    private static class RotationOffsetsHolder
    {
        public static readonly int[] Values = new[]
        {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
        };
    }
}

// Helper class to expose rotation offsets
internal static class KeccakConstants
{
    public static readonly int[] RotationOffsets = new[]
    {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    };

    public static readonly ulong[] RoundConstants = new[]
    {
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL,
        0x8000000080008000UL, 0x000000000000808BUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008AUL,
        0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
        0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL,
        0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800AUL, 0x800000008000000AUL, 0x8000000080008081UL,
        0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
    };
}