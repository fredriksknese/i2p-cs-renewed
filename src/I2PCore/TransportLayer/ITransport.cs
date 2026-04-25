using System;
using System.Net;
using I2PCore.Data;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TransportLayer;

public interface ITransport
{
    bool IsTerminated { get; }

    I2PKeysAndCert RemoteRouterIdentity { get; }
    IPAddress RemoteAddress { get; }

    long BytesSent { get; }
    long BytesReceived { get; }

    /// <summary>
    ///     Instance unique identifier for debugging.<!--
    /// </summary>
    string DebugId { get; }

    /// <summary>
    ///     Abbriviated unique name of the protocol implemented.
    /// </summary>
    string Protocol { get; }

    bool IsOutgoing { get; }
    bool IsPQ { get; }
    event Action<ITransport, Exception> ConnectionException;
    event Action<ITransport> ConnectionShutDown;

    /// <summary>
    ///     Protocol initial handshake is finished, and data can be sent.
    /// </summary>
    event Action<ITransport, I2PIdentHash> ConnectionEstablished;

    event Action<ITransport, Ii2NpHeader> DataBlockReceived;

    void Connect();

    void Send(I2NpMessage msg);

    void Terminate(string reason = null);

    /// <summary>
    ///     Called by TransportProvider if a DatabaseStoreMessage for this transport was received.
    /// </summary>
    void DatabaseStoreMessageReceived(DatabaseStoreMessage dsm);

    /// <summary>
    ///     Periodic background task for the transport.
    /// </summary>
    void Tick();
}