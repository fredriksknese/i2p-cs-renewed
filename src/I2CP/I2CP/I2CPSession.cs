using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using I2P.I2CP.Messages;
using I2P.I2CP.States;
using I2PCore;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using static I2P.I2CP.Messages.I2CpMessage;
using static I2PCore.SessionLayer.ClientDestination;

namespace I2P.I2CP;

public class SessionInfo
{
    private uint MessageIdField;

    public SessionInfo(ushort id)
    {
        SessionId = id;
    }

    public ushort SessionId { get; }
    public uint MessageId => ++MessageIdField;

    public I2PSessionConfig Config { get; set; }

    public ClientDestination MyDestination { get; internal set; }
}

public class I2CpSession
{
    private static int _instanceCounter;

    private readonly CancellationTokenSource CtSource = new();
    internal readonly I2CpHost Host;
    private readonly string InstanceInfo;
    private readonly NetworkStream MyStream;

    private readonly PendingLeaseUpdateInfo PendingLeaseUpdate = new();

    private readonly byte[] RecvBuf = new byte[65536];

    private readonly ConcurrentQueue<I2CpMessage> SendQueue = new();

    internal I2CpState CurrentState;

    internal TickCounter LastReception = TickCounter.Now;
    internal TcpClient MyTcpClient;

    private ushort PrevSessionId;
    private bool SendInProgress;

    public ushort SessionId = 1;

    internal ConcurrentDictionary<ushort, SessionInfo> SessionIds = new();

    // We are host
    public I2CpSession(I2CpHost host, TcpClient client)
    {
        Host = host;
        MyTcpClient = client;

        CurrentState = new WaitGetDateState(this);
        MyStream = MyTcpClient.GetStream();

        InstanceInfo = $"{++_instanceCounter}";
    }

    public bool Terminated { get; private set; }
    public string DebugId => $"--{InstanceInfo}:{SessionId}--";

    internal async Task Run()
    {
        try
        {
            var recvbuf = new I2PByteBlock(RecvBuf);

            var readlen = await MyStream.ReadAsync(RecvBuf, 0, 1, CtSource.Token).ConfigureAwait(false);
            if (readlen != 1) throw new FailedToConnectException("I2CPSession. Failed to read protocol version");

            if (RecvBuf[0] != I2PConstants.ProtocolByte)
                throw new FailedToConnectException($"I2CPSession. Wrong protocol version {RecvBuf[0]}");

            while (!(CurrentState is null))
            {
                readlen = await MyStream.ReadAsync(RecvBuf, 0, 5, CtSource.Token).ConfigureAwait(false);
                if (readlen != 5)
                {
                    Logging.LogDebug($"{this}: Failed to read message header 5. Got {readlen} bytes.");
                    break;
                }

                var msglen = recvbuf.ReadUInt32BigEndian(0);
                var msgtype = recvbuf[4];

                if (msglen + 5 >= RecvBuf.Length)
                {
                    Logging.LogWarning($"{this}: Failed to read message {msglen}. Receivebuffer too small. Quitting.");
                    break;
                }

                if (msglen == 0) continue;

                var startpos = 5;
                var toread = (int)msglen;
                again:
                readlen = await MyStream.ReadAsync(RecvBuf, startpos, toread, CtSource.Token).ConfigureAwait(false);

                if (readlen == 0)
                {
                    Logging.LogInformation($"{this}: Failed to read message {msglen}. Got end of stream.");
                    break;
                }

                if (readlen != msglen)
                {
                    Logging.LogDebug($"{this}: Failed to read message {msglen}. Got {readlen} bytes.");

                    startpos += readlen;
                    toread -= readlen;

                    goto again;
                }

                LastReception.SetNow();

                try
                {
                    var msg = GetMessage(
                        new I2PBufferCursor(recvbuf.Slice(0, readlen + 5).Clone()));

                    var nextstate = CurrentState.MessageReceived(msg);
                    if (nextstate != CurrentState)
                    {
                        Logging.LogDebug($"{this}: Changed state from {CurrentState} to {nextstate}");
                        CurrentState = nextstate;
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogWarning($"{this} {ex}");
                }
            }
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{this} {ex}");
        }
        finally
        {
            Terminate();

            foreach (var session in SessionIds)
            {
                DetachDestination(session.Value.MyDestination);
                session.Value.MyDestination?.Shutdown();
            }

            Logging.LogInformation($"{this}: Session closed.");
        }
    }

    internal void AttachDestination(ClientDestination dest)
    {
        dest.DataReceived += MyDestination_DataReceived;
        dest.SignLeasesRequest += MyDestination_SignLeasesRequest;
        dest.ClientStateChanged += MyDestination_ClientStateChanged;
    }

    internal void DetachDestination(ClientDestination dest)
    {
        dest.DataReceived -= MyDestination_DataReceived;
        dest.SignLeasesRequest -= MyDestination_SignLeasesRequest;
        dest.ClientStateChanged -= MyDestination_ClientStateChanged;
    }

    internal void Terminate([CallerMemberName] string caller = "")
    {
        try
        {
            CurrentState = null;

            if (Terminated) return;

            CtSource?.Cancel(false);

            Logging.LogInformation(
                $"{this}: Terminating {DebugId} from {MyTcpClient.Client.RemoteEndPoint} by {caller}.");

            try
            {
                MyTcpClient?.Close();
            }
            catch (Exception ex)
            {
                Logging.LogDebug(ex);
            }

            try
            {
                MyTcpClient?.Dispose();
                MyTcpClient = null;
            }
            catch (Exception ex)
            {
                Logging.LogDebug(ex);
            }

            foreach (var destsid in SessionIds)
                try
                {
                    var dest = destsid.Value.MyDestination;

                    if (dest != null)
                    {
                        DetachDestination(dest);
                        dest?.Shutdown();
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogDebug(ex);
                }

            Terminated = true;
        }
        catch (Exception ex)
        {
            Logging.LogDebug(ex);
        }
    }

    internal SessionInfo GenerateNewSessionId()
    {
        var newid = ++PrevSessionId;
        if (PrevSessionId > 30000) PrevSessionId = 0;

        var result = new SessionInfo(newid);

        SessionIds[newid] = result;
        return result;
    }

    internal void Send(I2CpMessage msg)
    {
        lock (SendQueue)
        {
            if (SendInProgress)
            {
                SendQueue.Enqueue(msg);
                return;
            }

            SendInProgress = true;
            SendOneMessage(msg);
        }
    }

    private void SendOneMessage(I2CpMessage msg)
    {
        try
        {
            var header = new byte[5];
            var writer = new I2PBufferCursor(header);
            var data = msg.ToByteArray();
            writer.WriteUInt32BigEndian((uint)data.Length);
            writer.WriteByte((byte)msg.MessageType);

            Logging.LogDebug(
                $"{this} SendOneMessage: {msg.MessageType} {new I2PByteBlock(header):h} {new I2PByteBlock(data):20}");

            MyTcpClient.Client.BeginSend(
                new List<ArraySegment<byte>>
                {
                    new(header),
                    new(data)
                },
                SocketFlags.None, ar =>
                {
                    try
                    {
                        MyTcpClient?.Client?.EndSend(ar);

                        lock (SendQueue)
                        {
                            if (SendQueue.IsEmpty || !SendQueue.TryDequeue(out var newmsg))
                            {
                                SendInProgress = false;
                                return;
                            }

                            SendOneMessage(newmsg);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logging.LogDebug(ex);
                        Terminate();
                    }
                },
                this);
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"{this} {ex}");
            Terminate();
        }
    }

    internal void MyDestination_ClientStateChanged(ClientDestination dest, ClientStates state)
    {
        if (Terminated) return;

        var sessid = SessionIds
            .FirstOrDefault(s => s.Value.MyDestination == dest);
        if (Equals(sessid, default(KeyValuePair<ushort, SessionInfo>))) return;

        Logging.LogDebug($"{this} MyDestination_ClientStateChanged: {sessid.Key}, {state}");

        if (sessid.Value.MyDestination.Terminated) Terminate();
    }

    private SessionInfo FindSession(ClientDestination dest, [CallerMemberName] string caller = "NA")
    {
        var sessid = SessionIds
            .SingleOrDefault(s => s.Value.MyDestination == dest);
        if (Equals(sessid, default(KeyValuePair<ushort, SessionInfo>)))
        {
            Logging.LogWarning($"{this} FindSession {caller}: Cannot find session id of {dest}");
            return null;
        }

        return sessid.Value;
    }

    private SessionInfo FindSession(I2PDestination dest, [CallerMemberName] string caller = "NA")
    {
        var sessid = SessionIds
            .SingleOrDefault(s => s.Value.MyDestination.Destination.IdentHash == dest.IdentHash);
        if (Equals(sessid, default(KeyValuePair<ushort, SessionInfo>)))
        {
            Logging.LogWarning($"{this} FindSession {caller}: Cannot find session id of destination {dest}");
            return null;
        }

        return sessid.Value;
    }

    internal void MyDestination_DataReceived(ClientDestination dest, I2PByteBlock data, I2PDestination sender)
    {
        if (Terminated) return;

        var ldata = data;
        var sessid = FindSession(dest);

        Logging.LogDebugData(
            $"{this} MyDestination_DataReceived: Received message {sessid.SessionId} {dest} {(PayloadFormat)ldata[9]}, {ldata}");

        if (sessid.MyDestination.Terminated)
        {
            Terminate();
            return;
        }

        Send(new MessagePayloadMessage(
            sessid.SessionId,
            sessid.MessageId,
            ldata));
    }

    internal void MyDestination_SignLeasesRequest(ClientDestination dest, IEnumerable<ILease> leases)
    {
        Logging.LogDebug($"{this} MyDestination_SignLeasesRequest: Received sign leases {leases?.Count()}");

        lock (PendingLeaseUpdate)
        {
            var sessid = FindSession(dest);
            if (sessid == null)
            {
                PendingLeaseUpdate.PendingUpdate = new List<ILease>(leases);
                PendingLeaseUpdate.PendingSessionUpdate = 0;
                return;
            }

            if (sessid.MyDestination.Terminated)
            {
                Terminate();
                return;
            }

            if (PendingLeaseUpdate.UpdateInProgress)
            {
                PendingLeaseUpdate.PendingUpdate = new List<ILease>(leases);
                PendingLeaseUpdate.PendingSessionUpdate = sessid.SessionId;
                return;
            }

            Send(new RequestVariableLeaseSetMessage(
                sessid.SessionId,
                sessid.MyDestination.EstablishedLeases));

            PendingLeaseUpdate.UpdateInProgress = true;
        }
    }

    internal void SendPendingLeaseUpdates(bool nooutstanding = false)
    {
        lock (PendingLeaseUpdate)
        {
            if (nooutstanding)
            {
                PendingLeaseUpdate.UpdateInProgress = false;
                PendingLeaseUpdate.PendingUpdate = null;
            }

            if (PendingLeaseUpdate.UpdateInProgress
                || PendingLeaseUpdate.PendingUpdate is null)
                return;

            var ls = PendingLeaseUpdate.PendingUpdate;
            var sessionid = PendingLeaseUpdate.PendingSessionUpdate;
            if (sessionid == 0) sessionid = SessionIds.First().Key;

            Logging.LogDebug($"{this} SendPendingLeaseUpdates: Sending leases {ls?.Count()}");

            Send(new RequestVariableLeaseSetMessage(
                sessionid,
                ls));

            PendingLeaseUpdate.UpdateInProgress = true;
        }
    }

    public I2CpMessage GetMessage(I2PBufferCursor data)
    {
        var pmt = (ProtocolMessageType)data[4];
        data.Seek(5);

        Logging.LogDebug($"{this} GetMessage: Received message {pmt}, {data.Remaining} bytes.");

        switch (pmt)
        {
            case ProtocolMessageType.CreateSession:
                return new CreateSessionMessage(data);

            case ProtocolMessageType.ReconfigSession:
                return new ReconfigureSessionMessage(data);

            case ProtocolMessageType.DestroySession:
                return new DestroySessionMessage(data);

            case ProtocolMessageType.CreateLs:
                return new CreateLeaseSetMessage(data, this);

            case ProtocolMessageType.CreateLeaseSet2Message:
                return new CreateLeaseSet2Message(data, this);

            case ProtocolMessageType.SendMessage:
                break;

            case ProtocolMessageType.RecvMessageBegin:
                break;

            case ProtocolMessageType.RecvMessageEnd:
                return new ReceiveMessageEndMessage(data);

            case ProtocolMessageType.GetBwLimits:
                break;

            case ProtocolMessageType.SessionStatus:
                break;

            case ProtocolMessageType.RequestLs:
                break;

            case ProtocolMessageType.MessageStatus:
                break;

            case ProtocolMessageType.BwLimits:
                break;

            case ProtocolMessageType.ReportAbuse:
                break;

            case ProtocolMessageType.Disconnect:
                break;

            case ProtocolMessageType.MessagePayload:
                break;

            case ProtocolMessageType.GetDate:
                return new GetDateMessage(data);

            case ProtocolMessageType.SetDate:
                return null;

            case ProtocolMessageType.DestLookup:
                return new DestLookupMessage(data);

            case ProtocolMessageType.DestReply:
                return null;

            case ProtocolMessageType.SendMessageExpires:
                return new SendMessageExpiresMessage(data);

            case ProtocolMessageType.RequestVarLs:
                return null;

            case ProtocolMessageType.HostLookup:
                return new HostLookupMessage(data);

            case ProtocolMessageType.HostLookupReply:
                Logging.LogDebug("I2CPSession: HostLookupReply received (client-to-router)");
                return null;

            default:
                Logging.LogWarning($"I2CPSession:GetMessage I2CP message of type {(byte)pmt} is unknown");
                return null;
        }

        return null;
    }

    public override string ToString()
    {
        return $"{GetType().Name} {DebugId}";
    }

    private class PendingLeaseUpdateInfo
    {
        public TickCounter LockedAt = TickCounter.Now;

        public ushort PendingSessionUpdate;
        public List<ILease> PendingUpdate;
        private bool UpdateInProgressField;

        public bool UpdateInProgress
        {
            get
            {
                if (LockedAt.DeltaToNow > TickSpan.Minutes(1)) UpdateInProgressField = false;

                return UpdateInProgressField;
            }
            set
            {
                UpdateInProgressField = value;
                if (UpdateInProgressField) LockedAt = TickCounter.Now;
            }
        }
    }
}