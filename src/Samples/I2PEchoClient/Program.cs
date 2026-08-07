using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using I2P.Streaming;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;
using static I2P.Streaming.StreamingPacket;
using static I2P.I2CP.Messages.I2CpMessage;
using static System.Configuration.ConfigurationManager;

namespace I2PEchoClient;

internal class Program
{
    private static I2PDestinationInfo _myDestinationInfo;
    private static ClientDestination _unpublishedDestination;

    private static bool _connected;

    private static void Main(string[] args)
    {
        Logging.ReadAppConfig();
        Logging.LogToDebug = false;
        Logging.LogToConsole = true;

        RouterContext.RouterSettingsFile = "EchoClientRouter.bin";
        RouterContext.Inst = new RouterContext(
            new I2PCertificate(
                I2PSigningKey.SigningKeyTypes.DsaSha1));

        for (var i = 0; i < args.Length; ++i)
            switch (args[i])
            {
                case "--addr":
                case "--address":
                    if (args.Length > i + 1)
                    {
                        RouterContext.Inst.DefaultExtAddress = IPAddress.Parse(args[++i]);
                        Console.WriteLine($"addr {RouterContext.Inst.DefaultExtAddress}");
                    }
                    else
                    {
                        Console.WriteLine("--addr require ip number");
                        return;
                    }

                    break;

                case "--port":
                    if (args.Length > i + 1)
                    {
                        var port = int.Parse(args[++i]);
                        RouterContext.Inst.DefaultTcpPort = port;
                        RouterContext.Inst.DefaultUdpPort = port;
                        Console.WriteLine($"port {port}");
                    }
                    else
                    {
                        Console.WriteLine("--port require port number");
                        return;
                    }

                    break;

                case "--nofw":
                    RouterContext.Inst.IsFirewalled = false;
                    Console.WriteLine($"Firewalled {RouterContext.Inst.IsFirewalled}");
                    break;

                default:
                    Console.WriteLine(args[i]);
                    Console.WriteLine("Usage: I2P.exe --addr 12.34.56.78 --port 8081 --nofw");
                    break;
            }

        RouterContext.Inst.ApplyNewSettings();
        Router.Start();

        var destb32 = AppSettings["RemoteDestination"];
        var remotedest = new I2PIdentHash(destb32);

        _myDestinationInfo = new I2PDestinationInfo(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);

        _unpublishedDestination = Router.CreateDestination(
            _myDestinationInfo,
            false,
            out _);

        _unpublishedDestination.DataReceived += MyDestination_DataReceived;
        _unpublishedDestination.Name = "UnpublishedDestination";

        Logging.LogInformation(
            $"MyDestination: {_unpublishedDestination.Destination.IdentHash} {_myDestinationInfo.Destination.Certificate}");

        var interval = new PeriodicAction(TickSpan.Seconds(40));

        // Batch 2-3 (docs/PRODUCTION-PLAN.md): DaemonHelper had signal handling implemented and
        // no caller, so Ctrl+C killed the process and Router.Stop() never ran. Setting
        // e.Cancel = true lets the process survive the signal and shut down properly.
        using var daemon = new DaemonHelper();
        daemon.OnReload(Router.ReloadConfig);
        daemon.RegisterSignalHandlers();

        while (!daemon.IsShuttingDown)
            try
            {
                _connected = true;

                while (_connected && !daemon.IsShuttingDown)
                {
                    Thread.Sleep(2000);

                    var recvid = BufUtils.RandomUintNz();

                    interval.Do(() =>
                    {
                        Logging.LogInformation($"Program {_unpublishedDestination}: Looking for {remotedest}.");
                        _unpublishedDestination.LookupDestination(remotedest, (hash, ls, tag) =>
                        {
                            if (ls is null)
                            {
                                Logging.LogInformation(
                                    $"Program {_unpublishedDestination}: Failed to lookup {hash.Id32Short}.");
                                return;
                            }

                            var test = new I2PIdentHash(ls.Destination);
                            Logging.LogInformation(
                                $"Program {_unpublishedDestination}: Found {remotedest}, test: {test.Id32Short}.");

                            var s = new ArrayBufferWriter<byte>();
                            var sh = new StreamingPacket(
                                PacketFlags.Synchronize
                                | PacketFlags.FromIncluded
                                | PacketFlags.SignatureIncluded
                                | PacketFlags.MaxPacketSizeIncluded
                                | PacketFlags.NoAck)
                            {
                                From = _unpublishedDestination.Destination,
                                SigningKey = _myDestinationInfo.PrivateSigningKey,
                                ReceiveStreamId = recvid,
                                NacKs = new List<uint>(),
                                Payload = new I2PByteBlock(new byte[0])
                            };

                            sh.Write(s);
                            var buf = s.WrittenSpan.ToArray();
                            var zipped = LzUtils.BcgZipCompressNew(new I2PByteBlock(buf));
                            zipped.WriteUInt16BigEndian(4353, 4); // source port
                            zipped.WriteUInt16BigEndian(25, 6); // dest port
                            zipped[9] = (byte)PayloadFormat.Streaming; // streaming

                            Logging.LogInformation($"Program {_unpublishedDestination}: Sending {zipped:20}.");

                            _unpublishedDestination.Send(ls.Destination, zipped);
                        });
                    });
                }
            }
            catch (SocketException ex)
            {
                Logging.Log(ex);
            }
            catch (IOException ex)
            {
                Logging.Log(ex);
            }
            catch (Exception ex)
            {
                Logging.Log(ex);
            }

        Logging.LogInformation("Shutdown requested, stopping router...");
        Router.Stop();
    }

    private static void MyDestination_DataReceived(ClientDestination dest, I2PByteBlock data, I2PDestination sender)
    {
        Logging.LogInformation($"Program {_unpublishedDestination}: data received {data:20}");

        var unzip = LzUtils.BcgZipDecompressNew(data);
        var packet = new StreamingPacket(new I2PBufferCursor(unzip));

        Logging.LogInformation($"Program {_unpublishedDestination}: {packet}");
    }
}