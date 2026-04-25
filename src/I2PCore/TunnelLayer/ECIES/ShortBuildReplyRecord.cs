using System;
using System.Buffers;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.ECIES;

/// <summary>
///     Short ECIES Tunnel Build Reply Record
///     Cleartext: 202 bytes (options + padding + status byte at position 201)
///     On-wire (AEAD encrypted): 218 bytes (202 cleartext + 16 Poly1305 MAC)
///     Per Java BuildReplyHandler: status byte at offset rec.length() - 17 = 218 - 17 = 201
/// </summary>
public class ShortBuildReplyRecord
{
    public enum TunnelBuildReplyStatus : byte
    {
        Accept = 0x00,
        RejectBandwidth = 30
    }

    public const int ClearTextSize = 202; // plaintext before AEAD
    public const int OnWireRecordSize = 218; // ClearTextSize + 16 MAC
    public const int StatusByteOffset = 201; // last byte of cleartext

    // Backward compat aliases
    public const int UnencryptedRecordSize = ClearTextSize;
    public const int EncryptedRecordSize = OnWireRecordSize;

    public ShortBuildReplyRecord()
    {
        Options = new I2PMapping();
        Status = TunnelBuildReplyStatus.Accept;
    }

    public ShortBuildReplyRecord(TunnelBuildReplyStatus status)
    {
        Options = new I2PMapping();
        Status = status;
    }

    public ShortBuildReplyRecord(TunnelBuildReplyStatus status, I2PMapping options)
    {
        Options = options ?? new I2PMapping();
        Status = status;
    }

    /// <summary>
    ///     Parse from cleartext bytes (202 bytes)
    /// </summary>
    public ShortBuildReplyRecord(byte[] cleartext)
    {
        if (cleartext == null || cleartext.Length < ClearTextSize)
        {
            Options = new I2PMapping();
            Status = TunnelBuildReplyStatus.RejectBandwidth;
            return;
        }

        // Status byte at position 201
        Status = (TunnelBuildReplyStatus)cleartext[StatusByteOffset];
        Options = new I2PMapping();
    }

    public I2PMapping Options { get; set; }
    public TunnelBuildReplyStatus Status { get; set; }

    /// <summary>
    ///     Write cleartext record (202 bytes): options + padding + status
    /// </summary>
    public byte[] ToByteArray()
    {
        var result = new byte[ClearTextSize];

        // Write options mapping at the beginning
        var stream = new ArrayBufferWriter<byte>();
        Options.Write(stream);
        var optionsBytes = stream.WrittenSpan.ToArray();
        Array.Copy(optionsBytes, 0, result, 0, Math.Min(optionsBytes.Length, StatusByteOffset));

        // Fill padding with random bytes (between options and status)
        var paddingStart = Math.Min(optionsBytes.Length, StatusByteOffset);
        if (paddingStart < StatusByteOffset)
        {
            var padding = BufUtils.RandomBytes(StatusByteOffset - paddingStart);
            Array.Copy(padding, 0, result, paddingStart, padding.Length);
        }

        // Status byte at position 201
        result[StatusByteOffset] = (byte)Status;

        return result;
    }

    public bool IsAccepted()
    {
        return Status == TunnelBuildReplyStatus.Accept;
    }

    public bool IsRejected()
    {
        return Status != TunnelBuildReplyStatus.Accept;
    }

    /// <summary>
    ///     AEAD encrypt: ChaChaPoly(replyKey, nonce=slotNumber, AD=handshakeHash, plaintext)
    ///     Returns 218 bytes (202 cleartext + 16 MAC)
    /// </summary>
    public byte[] EncryptAEAD(byte[] replyKey, byte[] replyAD, int slotNumber)
    {
        if (replyKey == null || replyKey.Length != 32)
            throw new ArgumentException("Reply key must be 32 bytes");

        var plaintext = ToByteArray(); // 202 bytes
        var nonce = ChaCha20Poly1305.CreateNonce((ulong)slotNumber);

        return ChaCha20Poly1305.Encrypt(replyKey, nonce, plaintext, replyAD);
    }

    /// <summary>
    ///     AEAD decrypt: ChaChaPoly(replyKey, nonce=slotNumber, AD=handshakeHash, ciphertext+MAC)
    ///     Input: 218 bytes. Returns parsed reply record, or null on auth failure.
    /// </summary>
    public static ShortBuildReplyRecord DecryptAEAD(
        byte[] ciphertextWithTag, byte[] replyKey, byte[] replyAD, int slotNumber)
    {
        if (ciphertextWithTag == null || ciphertextWithTag.Length != OnWireRecordSize)
            throw new ArgumentException($"Ciphertext must be {OnWireRecordSize} bytes");
        if (replyKey == null || replyKey.Length != 32)
            throw new ArgumentException("Reply key must be 32 bytes");

        var nonce = ChaCha20Poly1305.CreateNonce((ulong)slotNumber);

        var plaintext = ChaCha20Poly1305.Decrypt(replyKey, nonce, ciphertextWithTag, replyAD);
        if (plaintext == null) return null;

        return new ShortBuildReplyRecord(plaintext);
    }

    /// <summary>
    ///     Legacy encrypt (plain ChaCha20, no AEAD). Kept for backward compat.
    /// </summary>
    public byte[] Encrypt(byte[] replyKey, byte[] replyIV)
    {
        // Redirect to AEAD with no AD for legacy callers
        var plaintext = ToByteArray();
        var nonce = new byte[12];
        if (replyIV != null && replyIV.Length >= 12)
            Array.Copy(replyIV, 0, nonce, 0, 12);

        return ChaCha20Poly1305.Encrypt(replyKey, nonce, plaintext);
    }

    /// <summary>
    ///     Legacy decrypt. Kept for backward compat.
    /// </summary>
    public static ShortBuildReplyRecord Decrypt(byte[] ciphertext, byte[] replyKey, byte[] replyIV)
    {
        var nonce = new byte[12];
        if (replyIV != null && replyIV.Length >= 12)
            Array.Copy(replyIV, 0, nonce, 0, 12);

        var plaintext = ChaCha20Poly1305.Decrypt(replyKey, nonce, ciphertext);
        if (plaintext == null) return null;

        return new ShortBuildReplyRecord(plaintext);
    }

    public override string ToString()
    {
        return $"ShortBuildReplyRecord: Status={Status}, Options={Options.Mappings.Count} entries";
    }
}