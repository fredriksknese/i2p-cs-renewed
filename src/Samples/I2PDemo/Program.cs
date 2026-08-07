#define NOMANUAL_SIGN

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;

namespace I2PDemo;

internal class Program
{
    private static I2PDestinationInfo _myDestinationInfo;
    private static I2PDestination _myDestination;

    private static ClientDestination _publishedDestination;

    private static I2PDestinationInfo _myOriginInfo;
    private static ClientDestination _myOrigin;

    private static ILeaseSet _lookedUpLeaseSet;
    private static I2PByteBlock _dataSent;

    private static bool _connected;

    private static void Main(string[] args)
    {
        var sendInterval = new PeriodicAction(TickSpan.Seconds(20));

        Logging.LogToDebug = false;
        Logging.LogToConsole = true;
        Logging.ReadAppConfig();

        RouterContext.RouterSettingsFile = "I2PDemo.bin";

        _myDestinationInfo = new I2PDestinationInfo(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);

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

                case "--ipv6":
                    RouterContext.UseIpV6 = true;
                    Console.WriteLine("Using IPV6");
                    break;

                case "--mkdest":
                case "--create-destination":
                    var certtype = 0;
                    if (args.Length > i + 1) certtype = int.Parse(args[++i]);

                    I2PSigningKey.SigningKeyTypes ct;
                    I2PDestinationInfo d;

                    switch (certtype)
                    {
                        default:
                        case 0:
                            ct = I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519;
                            d = new I2PDestinationInfo(ct);
                            break;

                        case 1:
                            ct = I2PSigningKey.SigningKeyTypes.DsaSha1;
                            d = new I2PDestinationInfo(ct);
                            break;

                        case 2:
                            ct = I2PSigningKey.SigningKeyTypes.EcdsaSha256P256;
                            d = new I2PDestinationInfo(ct);
                            break;

                        case 3:
                            ct = I2PSigningKey.SigningKeyTypes.EcdsaSha384P384;
                            d = new I2PDestinationInfo(ct);
                            break;
                    }

                    Console.WriteLine($"New destination {ct}: {d.ToBase64()}");
                    return;

                case "--destination":
                    if (args.Length > i + 1)
                    {
                        _myDestinationInfo = new I2PDestinationInfo(args[++i]);
                        Console.WriteLine($"Destination {_myDestinationInfo}");
                    }
                    else
                    {
                        Console.WriteLine("Base64 encoded Destination required");
                        return;
                    }

                    break;

                default:
                    Console.WriteLine(args[i]);
                    Console.WriteLine(
                        "Usage: I2P.exe --addr 12.34.56.78 --port 8081 --nofw --create-destination [0-3] --destination b64...");
                    break;
            }

        RouterContext.Inst.ApplyNewSettings();

        var pnp = new UPnp();

        Router.Start();

        // Create new identities for this run

        _myDestination = _myDestinationInfo.Destination;

#if MANUAL_SIGN
            PublishedDestination = Router.CreateDestination(
                    MyDestination, 
                    true,
                    out _ ); // Publish our destinaiton
            PublishedDestination.SignLeasesRequest += MyDestination_SignLeasesRequest;
            
            PublishedDestination.GenerateTemporaryKeys();
#else
        // Publish our destinaiton
        _publishedDestination = Router.CreateDestination(
            _myDestinationInfo,
            true, out _);
#endif
        _publishedDestination.Name = "PublishedDestination";
        _publishedDestination.ClientStateChanged += MyDestination_ClientStateChanged;
        _publishedDestination.DataReceived += MyDestination_DataReceived;

        var ls = new I2PLeaseSet(_myDestinationInfo.Destination, null,
            _myDestinationInfo.Destination.PublicKey,
            _myDestinationInfo.Destination.SigningPublicKey,
            _myDestinationInfo.PrivateSigningKey);

        // Caller

        _myOriginInfo = new I2PDestinationInfo(I2PSigningKey.SigningKeyTypes.DsaSha1);

        _myOrigin = Router.CreateDestination(
            _myOriginInfo,
            false,
            out _);

        _myOrigin.Name = "MyOrigin";
        _myOrigin.ClientStateChanged += MyOrigin_ClientStateChanged;
        _myOrigin.DataReceived += MyOrigin_DataReceived;

        Logging.LogInformation(
            $"MyDestination: {_publishedDestination.Destination.IdentHash} {_myDestinationInfo.Destination.Certificate}");

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

                var sendevents = 0;

                while (_connected && !daemon.IsShuttingDown)
                {
                    Thread.Sleep(2000);

                    if (_myOrigin.ClientState == ClientDestination.ClientStates.Established)
                        sendInterval.Do(() =>
                        {
                            if (sendevents < 20)
                            {
                                if (_lookedUpLeaseSet == null)
                                {
                                    _myOrigin.LookupDestination(_publishedDestination.Destination.IdentHash,
                                        LookupResult);
                                    return;
                                }

                                // Send some data to the MyDestination
                                _dataSent = new I2PByteBlock(
                                    BufUtils.RandomBytes(
                                        (int)(1 + BufUtils.RandomDouble(25) * 1024)));

                                var ok = _myOrigin.Send(_lookedUpLeaseSet.Destination, _dataSent);
                                Logging.LogInformation($"Program {_myOrigin}: Send[{sendevents}] to " +
                                                       $"{_lookedUpLeaseSet.Destination.IdentHash.Id32Short} {ok}, {_dataSent}");

                                if (ok == ClientDestination.ClientStates.Established) ++sendevents;
                            }
                            else
                            {
                                if (++sendevents > 50) sendevents = 0;
                            }
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

    private static void MyOrigin_ClientStateChanged(ClientDestination dest, ClientDestination.ClientStates state)
    {
        Logging.LogInformation($"Program {dest}: Client state {state}");
    }

    private static void MyDestination_ClientStateChanged(ClientDestination dest, ClientDestination.ClientStates state)
    {
        Logging.LogInformation($"Program {dest}: Client state {state}");
    }

    private static void MyDestination_DataReceived(ClientDestination dest, I2PByteBlock data, I2PDestination sender)
    {
        var compareok = _dataSent.IsEmpty ? false : _dataSent == data;
        Logging.LogInformation($"Program {dest}: MyDestination data received. Matches send: {compareok} {data}");
        var ok = _publishedDestination.Send(_myOrigin.Destination, data);
        Logging.LogInformation($"Program {dest}: Send to {_myOrigin.Destination.IdentHash.Id32Short} {ok}");
    }

    private static void MyOrigin_DataReceived(ClientDestination dest, I2PByteBlock data, I2PDestination sender)
    {
        Logging.LogInformation($"Program {dest}: data received. {data}");
    }

    private static void MyDestination_SignLeasesRequest(ClientDestination dest, IEnumerable<ILease> ls)
    {
        Logging.LogInformation($"Program {dest}: Signing {ls} for publishing");
        _publishedDestination.PrivateKeys = new List<I2PPrivateKey>(new[] { _myDestinationInfo.PrivateKey });
        _publishedDestination.SignedLeases = new I2PLeaseSet(
            _myDestination,
            ls.Select(l => new I2PLease(l.TunnelGw, l.TunnelId, new I2PDate(l.Expire))),
            _myDestination.PublicKey,
            _myDestination.SigningPublicKey,
            _myDestinationInfo.PrivateSigningKey);
    }

    private static void LookupResult(I2PIdentHash hash, ILeaseSet ls, object o)
    {
        Logging.LogInformation($"Program {_myOrigin}: LookupResult {hash.Id32Short} {ls}");

        if (ls is null && _lookedUpLeaseSet is null)
        {
            // Try again
            _myOrigin.LookupDestination(_publishedDestination.Destination.IdentHash, LookupResult);
            return;
        }

        _lookedUpLeaseSet = ls;
    }
}