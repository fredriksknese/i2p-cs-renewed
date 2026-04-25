namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     SSU2 Protocol Constants
///     Per SSU2 specification
/// </summary>
public static class SSU2Constants
{
    /// <summary>
    ///     Noise protocol name for SSU2
    ///     Per spec line 154: "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256" (52 bytes)
    ///     Extensions:
    ///     - chaobfse: ChaCha20 obfuscation for ephemeral keys
    ///     - hs1: Header as associated data in message 1
    ///     - hs2: Header as associated data in message 2
    ///     - hs3: Header as associated data in message 3
    ///     Note: Different from NTCP2 because ALL handshake messages use header as AD
    /// </summary>
    public const string PROTOCOL_NAME = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256";

    /// <summary>
    ///     SSU2 protocol version
    /// </summary>
    public const byte VERSION = 2;

    /// <summary>
    ///     Network ID (2 for mainnet)
    /// </summary>
    public const byte NETWORK_ID = 2;

    /// <summary>
    ///     Minimum packet size (per spec line 299)
    /// </summary>
    public const int MIN_PACKET_SIZE = 40;

    /// <summary>
    ///     Maximum packet sizes
    /// </summary>
    public const int MAX_PACKET_SIZE_IPV4 = 1472;

    public const int MAX_PACKET_SIZE_IPV6 = 1452;

    /// <summary>
    ///     MTU values
    /// </summary>
    public const int MIN_MTU = 1280;

    public const int DEFAULT_MTU = 1500;

    /// <summary>
    ///     Message types (per spec lines 310-321)
    /// </summary>
    public const byte MSG_TYPE_SESSION_REQUEST = 0;

    public const byte MSG_TYPE_SESSION_CREATED = 1;
    public const byte MSG_TYPE_SESSION_CONFIRMED = 2;
    public const byte MSG_TYPE_DATA = 6;
    public const byte MSG_TYPE_PEER_TEST = 7;
    public const byte MSG_TYPE_RETRY = 9;
    public const byte MSG_TYPE_TOKEN_REQUEST = 10;
    public const byte MSG_TYPE_HOLE_PUNCH = 11;

    /// <summary>
    ///     Header sizes
    /// </summary>
    public const int SHORT_HEADER_SIZE = 16;

    public const int LONG_HEADER_SIZE = 32;

    /// <summary>
    ///     Ephemeral key size
    /// </summary>
    public const int EPHEMERAL_KEY_SIZE = 32;

    /// <summary>
    ///     Minimum payload size (per spec line 2545)
    ///     Required because header encryption uses last 24 bytes of packet as IV
    /// </summary>
    public const int MIN_PAYLOAD_SIZE = 8;
}