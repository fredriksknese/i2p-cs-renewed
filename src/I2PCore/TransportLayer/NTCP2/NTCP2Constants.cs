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

    // Batch 4-0d-fix: NETWORK_ID = 2 was removed here. Netid 2 is the live I2P network,
    // and a constant naming it is a defect that batch 4-0d's guard could not see -- it
    // matched `NetId = 2` only. never referenced, but a live-network literal waiting to be picked up.
    // Use (byte)I2PConstants.I2PNetworkId, which honours --netid.

    /// <summary>
    ///     Minimum message sizes
    /// </summary>
    public const int MIN_MESSAGE_SIZE = 64; // 32 bytes X + 32 bytes encrypted payload

    /// <summary>
    ///     Maximum message size for dual NTCP/NTCP2 ports
    /// </summary>
    public const int MAX_MESSAGE_SIZE_COMPAT = 287;
}