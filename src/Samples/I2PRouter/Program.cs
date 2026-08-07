using System;
using System.Net;
using System.Threading;
using I2P.I2CP;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.Utils;

namespace I2PRouter;

internal class Program
{
    private static bool _connected;

    private static void Main(string[] args)
    {
        Logging.ReadAppConfig();
        Logging.LogToDebug = false;
        Logging.LogToConsole = true;

        RouterContext.RouterSettingsFile = "I2PRouter.bin";

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

                /*
                    case "--if":
                    case "--interface":
                        if ( args.Length > i + 1 )
                        {
                            RouterContext.Inst.LocalInterface = IPAddress.Parse( args[++i] );
                            Console.WriteLine( $"if {RouterContext.Inst.LocalInterface}" );
                        }
                        else
                        {
                            Console.WriteLine( "--if require ip number" );
                            return;
                        }
                        break;*/
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

                default:
                    Console.WriteLine(args[i]);
                    Console.WriteLine(
                        "Usage: I2P.exe --addr 12.34.56.78 --port 8081 --nofw --create-destination [0-3]");
                    break;
            }

        RouterContext.Inst.ApplyNewSettings();

        Router.Start();

        Logging.LogInformation("I2P router starting");

        // Batch 2-3 (docs/PRODUCTION-PLAN.md): DaemonHelper had signal handling implemented and
        // no caller, so Ctrl+C killed the process and Router.Stop() never ran. Setting
        // e.Cancel = true lets the process survive the signal and shut down properly.
        using var daemon = new DaemonHelper();
        daemon.OnReload(Router.ReloadConfig);
        daemon.RegisterSignalHandlers();

        while (!daemon.IsShuttingDown)
            try
            {
                var i2Cp = new I2CpHost();

                _connected = true;

                while (_connected && !daemon.IsShuttingDown) Thread.Sleep(2000);
            }
            catch (Exception ex)
            {
                Logging.Log(ex);
            }

        Logging.LogInformation("Shutdown requested, stopping router...");
        Router.Stop();
    }
}