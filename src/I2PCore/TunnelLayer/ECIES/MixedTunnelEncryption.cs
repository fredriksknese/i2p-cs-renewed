using System;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.TunnelLayer.ECIES;

/// <summary>
///     Mixed Tunnel Encryption Support
///     Handles tunnels containing both ECIES and ElGamal routers
///     ECIES routers use ChaCha20/Poly1305 for tunnel data
///     ElGamal routers use AES-256-CBC for tunnel data
///     When building mixed tunnels, encryption must be layered properly:
///     - ECIES layers use ChaCha20
///     - ElGamal layers use AES-256-CBC
///     - Each layer encrypts the entire message including subsequent layers
/// </summary>
public class MixedTunnelEncryption
{
    /// <summary>
    ///     Tunnel hop encryption type
    /// </summary>
    public enum EncryptionType
    {
        ECIES,
        ElGamal
    }

    private readonly List<TunnelLayer> _layers;

    public MixedTunnelEncryption()
    {
        _layers = new List<TunnelLayer>();
    }

    /// <summary>
    ///     Get the number of encryption layers
    /// </summary>
    public int LayerCount => _layers.Count;

    /// <summary>
    ///     Add an encryption layer for a tunnel hop
    ///     Layers should be added in order from gateway to endpoint
    /// </summary>
    public void AddLayer(TunnelLayer layer)
    {
        if (layer == null)
            throw new ArgumentNullException(nameof(layer));

        if (layer.LayerKey == null || layer.LayerKey.Length != 32)
            throw new ArgumentException("Layer key must be 32 bytes", nameof(layer));

        if (layer.IVKey == null || layer.IVKey.Length != 32)
            throw new ArgumentException("IV key must be 32 bytes", nameof(layer));

        _layers.Add(layer);
    }

    /// <summary>
    ///     Encrypt tunnel data through all layers
    ///     Encryption is applied in reverse order (endpoint to gateway)
    ///     so that the gateway can decrypt first, then pass to next hop
    /// </summary>
    public byte[] EncryptTunnelData(byte[] plaintext)
    {
        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));

        var data = (byte[])plaintext.Clone();

        // Apply encryption layers in reverse order (endpoint first)
        for (var i = _layers.Count - 1; i >= 0; i--)
        {
            var layer = _layers[i];

            if (layer.Type == EncryptionType.ECIES)
                data = EncryptChaCha20(data, layer.LayerKey, layer.IVKey);
            else // ElGamal
                data = EncryptAES256CBC(data, layer.LayerKey, layer.IVKey);
        }

        return data;
    }

    /// <summary>
    ///     Decrypt tunnel data through layers
    ///     Decryption is applied in forward order (gateway to endpoint)
    ///     Used when this router is receiving tunnel data
    /// </summary>
    public byte[] DecryptTunnelData(byte[] ciphertext, int layerIndex)
    {
        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));

        if (layerIndex < 0 || layerIndex >= _layers.Count)
            throw new ArgumentOutOfRangeException(nameof(layerIndex));

        var layer = _layers[layerIndex];
        byte[] plaintext;

        if (layer.Type == EncryptionType.ECIES)
            plaintext = DecryptChaCha20(ciphertext, layer.LayerKey, layer.IVKey);
        else // ElGamal
            plaintext = DecryptAES256CBC(ciphertext, layer.LayerKey, layer.IVKey);

        return plaintext;
    }

    /// <summary>
    ///     Encrypt data using ChaCha20 (for ECIES hops)
    ///     Uses IV derived from tunnel message IV
    /// </summary>
    private byte[] EncryptChaCha20(byte[] plaintext, byte[] key, byte[] ivKey)
    {
        if (key == null || key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));

        // Derive IV from ivKey (use first 12 bytes for ChaCha20 nonce)
        var nonce = new byte[12];
        Array.Copy(ivKey, 0, nonce, 0, 12);

        var cipher = new ChaCha7539Engine();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(true, parameters);

        var ciphertext = new byte[plaintext.Length];
        cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

        return ciphertext;
    }

    /// <summary>
    ///     Decrypt data using ChaCha20 (for ECIES hops)
    /// </summary>
    private byte[] DecryptChaCha20(byte[] ciphertext, byte[] key, byte[] ivKey)
    {
        if (key == null || key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));

        // Derive IV from ivKey (use first 12 bytes for ChaCha20 nonce)
        var nonce = new byte[12];
        Array.Copy(ivKey, 0, nonce, 0, 12);

        var cipher = new ChaCha7539Engine();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(false, parameters);

        var plaintext = new byte[ciphertext.Length];
        cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, plaintext, 0);

        return plaintext;
    }

    /// <summary>
    ///     Encrypt data using AES-256-CBC (for ElGamal hops)
    /// </summary>
    private byte[] EncryptAES256CBC(byte[] plaintext, byte[] key, byte[] ivKey)
    {
        if (key == null || key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));

        // Use first 16 bytes of ivKey as AES IV
        var iv = new byte[16];
        Array.Copy(ivKey, 0, iv, 0, 16);

        // Pad plaintext to AES block size (16 bytes)
        var paddedLength = (plaintext.Length + 15) / 16 * 16;
        var paddedPlaintext = new byte[paddedLength];
        Array.Copy(plaintext, 0, paddedPlaintext, 0, plaintext.Length);

        // PKCS7 padding
        var paddingLength = paddedLength - plaintext.Length;
        for (var i = plaintext.Length; i < paddedLength; i++) paddedPlaintext[i] = (byte)paddingLength;

        var cipher = new CbcBlockCipher(new AesEngine());
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.Init(true, parameters);

        var ciphertext = new byte[paddedLength];
        for (var i = 0; i < paddedLength; i += 16) cipher.ProcessBlock(paddedPlaintext, i, ciphertext, i);

        return ciphertext;
    }

    /// <summary>
    ///     Decrypt data using AES-256-CBC (for ElGamal hops)
    /// </summary>
    private byte[] DecryptAES256CBC(byte[] ciphertext, byte[] key, byte[] ivKey)
    {
        if (key == null || key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));

        if (ciphertext.Length % 16 != 0)
            throw new ArgumentException("Ciphertext length must be multiple of 16", nameof(ciphertext));

        // Use first 16 bytes of ivKey as AES IV
        var iv = new byte[16];
        Array.Copy(ivKey, 0, iv, 0, 16);

        var cipher = new CbcBlockCipher(new AesEngine());
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.Init(false, parameters);

        var plaintext = new byte[ciphertext.Length];
        for (var i = 0; i < ciphertext.Length; i += 16) cipher.ProcessBlock(ciphertext, i, plaintext, i);

        // Remove PKCS7 padding
        var paddingLength = plaintext[plaintext.Length - 1];
        if (paddingLength > 0 && paddingLength <= 16)
        {
            var unpaddedLength = plaintext.Length - paddingLength;
            var unpaddedPlaintext = new byte[unpaddedLength];
            Array.Copy(plaintext, 0, unpaddedPlaintext, 0, unpaddedLength);
            return unpaddedPlaintext;
        }

        return plaintext;
    }

    /// <summary>
    ///     Check if tunnel contains mixed encryption types
    /// </summary>
    public bool IsMixed()
    {
        if (_layers.Count <= 1)
            return false;

        var firstType = _layers[0].Type;
        return _layers.Any(l => l.Type != firstType);
    }

    /// <summary>
    ///     Check if all hops are ECIES
    /// </summary>
    public bool IsAllECIES()
    {
        return _layers.All(l => l.Type == EncryptionType.ECIES);
    }

    /// <summary>
    ///     Check if all hops are ElGamal
    /// </summary>
    public bool IsAllElGamal()
    {
        return _layers.All(l => l.Type == EncryptionType.ElGamal);
    }

    /// <summary>
    ///     Get layer information for a specific hop
    /// </summary>
    public TunnelLayer GetLayer(int index)
    {
        if (index < 0 || index >= _layers.Count)
            throw new ArgumentOutOfRangeException(nameof(index));

        return _layers[index];
    }

    /// <summary>
    ///     Clear all layers
    /// </summary>
    public void Clear()
    {
        _layers.Clear();
    }

    /// <summary>
    ///     Information about a tunnel hop's encryption layer
    /// </summary>
    public class TunnelLayer
    {
        public EncryptionType Type { get; set; }
        public byte[] LayerKey { get; set; }
        public byte[] IVKey { get; set; }
        public I2PIdentHash RouterHash { get; set; }
        public I2PTunnelId TunnelId { get; set; }
    }
}

/// <summary>
///     Helper for building mixed tunnel encryption configurations
/// </summary>
public class MixedTunnelBuilder
{
    /// <summary>
    ///     Create encryption layers from tunnel build hops
    /// </summary>
    /// <summary>
    ///     Create encryption layers from tunnel build hops.
    ///     The LayerKey and IvKey must be populated on each hop before calling this.
    ///     For ECIES hops, keys are derived from the Noise handshake ChainingKey
    ///     during the build process. For ElGamal hops, keys are randomly generated
    ///     and included in the ElGamal-encrypted build request record.
    /// </summary>
    public static MixedTunnelEncryption CreateFromHops(List<TunnelBuildHop> hops)
    {
        if (hops == null || hops.Count == 0)
            throw new ArgumentException("At least one hop is required", nameof(hops));

        var encryption = new MixedTunnelEncryption();

        foreach (var hop in hops)
        {
            var encType = hop.IsECIES
                ? MixedTunnelEncryption.EncryptionType.ECIES
                : MixedTunnelEncryption.EncryptionType.ElGamal;

            if (hop.LayerKey == null || hop.IvKey == null)
                throw new InvalidOperationException(
                    $"LayerKey and IvKey must be set on hop {hop.RouterHash?.Id32Short} before creating encryption layers");

            var layer = new MixedTunnelEncryption.TunnelLayer
            {
                Type = encType,
                LayerKey = hop.LayerKey,
                IVKey = hop.IvKey,
                RouterHash = hop.RouterHash,
                TunnelId = hop.ShortRequest?.ReceiveTunnelId ?? hop.LongRequest?.ReceiveTunnelId
            };

            encryption.AddLayer(layer);
        }

        return encryption;
    }
}