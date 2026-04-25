using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.Streaming;

/// <summary>
///     I2P Datagram Protocol - unreliable message delivery.
///     Supports repliable datagrams (with sender identity) and raw datagrams.
///     Repliable datagram format (DSA signature):
///     [destination] [signature] [payload]
///     Raw datagram format:
///     [payload]
/// </summary>
public static class I2PDatagramDissector
{
    /// <summary>
    ///     Create a repliable datagram with sender identity and signature
    /// </summary>
    public static byte[] CreateRepliableDatagram(
        I2PDestination sender,
        I2PSigningPrivateKey signingKey,
        byte[] payload)
    {
        if (sender == null) throw new ArgumentNullException(nameof(sender));
        if (payload == null) throw new ArgumentNullException(nameof(payload));

        var senderBytes = sender.ToByteArray();
        var signatureSize = signingKey?.Certificate?.SignatureLength ?? 40;

        // Build the data to sign: destination + payload
        var toSign = new byte[senderBytes.Length + payload.Length];
        Array.Copy(senderBytes, 0, toSign, 0, senderBytes.Length);
        Array.Copy(payload, 0, toSign, senderBytes.Length, payload.Length);

        // Sign
        byte[] signature;
        if (signingKey != null)
            signature = I2PSignature.DoSign(signingKey, new I2PByteBlock(toSign));
        else
            signature = new byte[signatureSize];

        // Build datagram: destination + signature + payload
        var result = new byte[senderBytes.Length + signature.Length + payload.Length];
        var offset = 0;
        Array.Copy(senderBytes, 0, result, offset, senderBytes.Length);
        offset += senderBytes.Length;
        Array.Copy(signature, 0, result, offset, signature.Length);
        offset += signature.Length;
        Array.Copy(payload, 0, result, offset, payload.Length);

        return result;
    }

    /// <summary>
    ///     Parse a received repliable datagram
    /// </summary>
    public static (I2PDestination sender, byte[] payload, bool verified) ParseRepliableDatagram(byte[] data)
    {
        if (data == null || data.Length < 387) // Min destination size + signature
            throw new ArgumentException("Datagram too short");

        try
        {
            var reader = new I2PBufferCursor(data);
            var sender = new I2PDestination(reader);
            var senderBytes = sender.ToByteArray();

            var signatureSize = sender.Certificate.SignatureLength;
            var signatureData = reader.ReadBlock(signatureSize);

            var payloadLen = data.Length - reader.BaseArrayOffset;
            var payload = reader.ReadBytes(payloadLen);

            // Verify signature
            var toVerify = new byte[senderBytes.Length + payload.Length];
            Array.Copy(senderBytes, 0, toVerify, 0, senderBytes.Length);
            Array.Copy(payload, 0, toVerify, senderBytes.Length, payload.Length);

            var signature = new I2PSignature
            {
                Certificate = sender.Certificate,
                Sig = signatureData
            };
            var sigPubKey = sender.SigningPublicKey;
            var verified = I2PSignature.DoVerify(
                new I2PSigningPublicKey(new I2PBufferCursor(sigPubKey.ToByteArray()), sender.Certificate),
                signature,
                new I2PByteBlock(toVerify));

            return (sender, payload, verified);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"I2PDatagramDissector: Parse failed: {ex.Message}");
            return (null, null, false);
        }
    }

    /// <summary>
    ///     Create a v3 repliable datagram with offline signature support.
    ///     Format: destination + offlineSignature + signature + fromPort(2) + toPort(2) + payload
    ///     The offline signature contains a transient signing key that was signed by the
    ///     destination's primary key, allowing delegated signing.
    /// </summary>
    public static byte[] CreateRepliableDatagramV3(
        I2PDestination sender,
        I2PSigningPrivateKey signingKey,
        I2POfflineSignature offlineSignature,
        byte[] payload,
        ushort fromPort = 0,
        ushort toPort = 0)
    {
        if (sender == null) throw new ArgumentNullException(nameof(sender));
        if (payload == null) throw new ArgumentNullException(nameof(payload));

        var senderBytes = sender.ToByteArray();

        // Build port data
        var portData = new byte[4];
        portData[0] = (byte)(fromPort >> 8);
        portData[1] = (byte)(fromPort & 0xFF);
        portData[2] = (byte)(toPort >> 8);
        portData[3] = (byte)(toPort & 0xFF);

        // Offline signature data (if present)
        byte[] offlineSigBytes;
        if (offlineSignature != null)
        {
            var sigStream = new ArrayBufferWriter<byte>();
            offlineSignature.Write(sigStream);
            offlineSigBytes = sigStream.WrittenSpan.ToArray();
        }
        else
        {
            offlineSigBytes = Array.Empty<byte>();
        }

        // Data to sign: destination + payload + fromPort + toPort
        var toSign = new byte[senderBytes.Length + payload.Length + 4];
        Array.Copy(senderBytes, 0, toSign, 0, senderBytes.Length);
        Array.Copy(payload, 0, toSign, senderBytes.Length, payload.Length);
        Array.Copy(portData, 0, toSign, senderBytes.Length + payload.Length, 4);

        // Sign with the transient key (if offline signature present) or primary key
        byte[] signature;
        if (signingKey != null)
            signature = I2PSignature.DoSign(signingKey, new I2PByteBlock(toSign));
        else
            signature = new byte[sender.Certificate.SignatureLength];

        // Build v3 datagram:
        // Flag byte (1): bit 0 = offline signature present
        // destination + [offlineSignature] + signature + fromPort + toPort + payload
        var flags = offlineSignature != null ? (byte)0x01 : (byte)0x00;
        var result = new byte[1 + senderBytes.Length + offlineSigBytes.Length + signature.Length + 4 + payload.Length];
        var offset = 0;
        result[offset++] = flags;
        Array.Copy(senderBytes, 0, result, offset, senderBytes.Length);
        offset += senderBytes.Length;
        if (offlineSigBytes.Length > 0)
        {
            Array.Copy(offlineSigBytes, 0, result, offset, offlineSigBytes.Length);
            offset += offlineSigBytes.Length;
        }

        Array.Copy(signature, 0, result, offset, signature.Length);
        offset += signature.Length;
        Array.Copy(portData, 0, result, offset, 4);
        offset += 4;
        Array.Copy(payload, 0, result, offset, payload.Length);

        return result;
    }

    /// <summary>
    ///     Parse a v3 repliable datagram with optional offline signature.
    /// </summary>
    public static (I2PDestination sender, byte[] payload, bool verified, ushort fromPort, ushort toPort)
        ParseRepliableDatagramV3(byte[] data)
    {
        if (data == null || data.Length < 2)
            throw new ArgumentException("V3 datagram too short");

        try
        {
            var reader = new I2PBufferCursor(data);
            var flags = reader.ReadByte();
            var hasOfflineSig = (flags & 0x01) != 0;

            var sender = new I2PDestination(reader);
            var senderBytes = sender.ToByteArray();

            // Parse offline signature if present
            I2POfflineSignature offlineSig = null;
            I2PSigningPublicKey verifyKey;
            if (hasOfflineSig)
            {
                offlineSig = new I2POfflineSignature(reader, sender.Certificate);
                verifyKey = offlineSig.TransientPublicKey;
            }
            else
            {
                verifyKey = sender.SigningPublicKey;
            }

            var signatureSize = hasOfflineSig
                ? offlineSig.TransientPublicKey.Certificate.SignatureLength
                : sender.Certificate.SignatureLength;
            var signatureData = reader.ReadBlock(signatureSize);

            // Read ports
            var fromPort = reader.ReadUInt16BigEndian();
            var toPort = reader.ReadUInt16BigEndian();

            // Remaining is payload
            var payloadLen = data.Length - reader.BaseArrayOffset;
            var payload = reader.ReadBytes(payloadLen);

            // Build port data for verification
            var portData = new byte[4];
            portData[0] = (byte)(fromPort >> 8);
            portData[1] = (byte)(fromPort & 0xFF);
            portData[2] = (byte)(toPort >> 8);
            portData[3] = (byte)(toPort & 0xFF);

            // Verify signature
            var toVerify = new byte[senderBytes.Length + payload.Length + 4];
            Array.Copy(senderBytes, 0, toVerify, 0, senderBytes.Length);
            Array.Copy(payload, 0, toVerify, senderBytes.Length, payload.Length);
            Array.Copy(portData, 0, toVerify, senderBytes.Length + payload.Length, 4);

            var signature = new I2PSignature
            {
                Certificate = verifyKey.Certificate,
                Sig = signatureData
            };
            var verified = I2PSignature.DoVerify(verifyKey, signature, new I2PByteBlock(toVerify));

            return (sender, payload, verified, fromPort, toPort);
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"I2PDatagramDissector: V3 parse failed: {ex.Message}");
            return (null, null, false, 0, 0);
        }
    }

    /// <summary>
    ///     Create a raw (unsigned) datagram - just the payload
    /// </summary>
    public static byte[] CreateRawDatagram(byte[] payload)
    {
        return (byte[])payload.Clone();
    }
}