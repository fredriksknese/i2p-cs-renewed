namespace I2PCore.TransportLayer.NTCP2;

/// <summary>
///     NTCP2 Protocol Constants
///     Per NTCP2 specification
/// </summary>
public static class NTCP2Constants
{
    /// <summary>
    ///     Noise protocol name for NTCP2
    ///     Per spec: "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256" (48 bytes)
    ///     Extensions:
    ///     - aesobfse: AES obfuscation for ephemeral keys
    ///     - hs2: Header as associated data in message 2
    ///     - hs3: Header as associated data in message 3
    /// </summary>
    public const string PROTOCOL_NAME = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

    /// <summary>
    ///     NTCP2 protocol version
    /// </summary>
    public const byte VERSION = 2;

    /// <summary>
    ///     Network ID (2 for mainnet)
    /// </summary>
    public const byte NETWORK_ID = 2;

    /// <summary>
    ///     Minimum message sizes
    /// </summary>
    public const int MIN_MESSAGE_SIZE = 64; // 32 bytes X + 32 bytes encrypted payload

    /// <summary>
    ///     Maximum message size for dual NTCP/NTCP2 ports
    /// </summary>
    public const int MAX_MESSAGE_SIZE_COMPAT = 287;
}