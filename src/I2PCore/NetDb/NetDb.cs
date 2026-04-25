using System.Buffers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using I2PCore.Data;
using System.IO;
using I2PCore.Utils;
using System.Threading;
using System.Diagnostics;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TransportLayer;
using System.Collections.Concurrent;

namespace I2PCore
{
    public partial class NetDb
    {
        // From HandleDatabaseLookupMessageJob.java
        public static readonly TickSpan RouterInfoExpiryTime = TickSpan.Days( 1 );

        private const int RouterInfoCountLowWaterMark = 100;
        private static int _rouletteIncludeTopField = 3000;
        public static int RouletteIncludeTop
        {
            get
            {
                return _rouletteIncludeTopField;
            }
            set
            {
                var elitism = RouletteElitism;
                _rouletteIncludeTopField = value;
                RouletteElitism = elitism;
            }
        }

        
        /// <summary>
        /// The how many times more probable the highest scoring router is choosen than the lowest
        /// scoring router, if the number of routers are equal to RouletteIncludeTop.
        /// If the number of routers are less than RouletteIncludeTop, the elitism is reduced
        /// linearely. See: "Fitness proportionate selection"
        /// </summary>
        public static double RouletteElitism
        {
            get
            {
                return Math.Pow( RouletteElitismIncrement, ( RouletteIncludeTop - 1 ) );
            }
            set
            {
                RouletteElitismIncrement = Math.Pow( value, 1.0 / ( RouletteIncludeTop - 1 ) );
            }
        }

        // Defaults to 50000x
        public static double RouletteElitismIncrement = Math.Pow( 50000.0, 1.0 / RouletteIncludeTop );

        private ConcurrentDictionary<I2PIdentHash, RouterEntry> RouterInfos = new();

        private ConcurrentDictionary<I2PIdentHash, RouterEntry> FloodfillInfos = new();

        private TimeWindowDictionary<I2PIdentHash, ILeaseSet> LeaseSets = new(I2PLease.LeaseLifetime * 2);

        private Dictionary<I2PString, I2PString> ConfigurationSettings = new();

        protected static Thread Worker;
        public static NetDb Inst { get; protected set; }

        public RoutersStatistics Statistics = new();

        private RouletteSelection<I2PRouterInfo, I2PIdentHash> Roulette;
        private RouletteSelection<I2PRouterInfo, I2PIdentHash> RouletteFloodFill;
        private RouletteSelection<I2PRouterInfo, I2PIdentHash> RouletteNonFloodFill;

        public delegate void NetworkDatabaseRouterInfoUpdated( I2PRouterInfo info );
        public delegate void NetworkDatabaseRouterInfoRemoved( I2PIdentHash hash );
        public delegate void NetworkDatabaseLeaseSetUpdated( ILeaseSet ls );
        public delegate void NetworkDatabaseDatabaseSearchReplyReceived( DatabaseSearchReplyMessage dsm );
        public enum DatabaseLookupResult { RouterInfoFound, LeaseSetFound, ClosestFloodfillsSent, NotFound }
        public delegate void NetworkDatabaseDatabaseLookupReceived( DatabaseLookupMessage lookup, I2PIdentHash from, DatabaseLookupResult result );

        public event NetworkDatabaseRouterInfoUpdated RouterInfoUpdates;
        public event NetworkDatabaseRouterInfoRemoved RouterInfoRemovals;
        public event NetworkDatabaseLeaseSetUpdated LeaseSetUpdates;
        public event NetworkDatabaseDatabaseSearchReplyReceived DatabaseSearchReplies;
        public event NetworkDatabaseDatabaseLookupReceived DatabaseLookupReceived;

        internal void InvokeDatabaseLookupReceived( DatabaseLookupMessage lookup, I2PIdentHash from, DatabaseLookupResult result )
        {
            DatabaseLookupReceived?.Invoke( lookup, from, result );
        }

        public readonly IdentResolver IdentHashLookup;

        public readonly FloodfillUpdater FloodfillUpdate = new();

        protected NetDb()
        {
            var dirname = RouterContext.RouterPath;
            if ( !Directory.Exists( dirname ) )
            {
                Directory.CreateDirectory( dirname );
            }
            dirname = NetDbPath;
            if ( !Directory.Exists( dirname ) )
            {
                Directory.CreateDirectory( dirname );
            }

            Worker = new Thread( Run )
            {
                Name = "NetDb",
                IsBackground = true
            };

            IdentHashLookup = new IdentResolver( this );
            Worker.Start();
        }

        private ManualResetEvent LoadFinished = new( false );
        private bool Terminated = false;
        private void Run()
        {
            try
            {
                Logging.LogInformation( $"NetDb: Path: {NetDbPath}" );
                Logging.Log( "Reading NetDb..." );
                var sw1 = new Stopwatch();
                sw1.Start();
                Load();
                sw1.Stop();
                Logging.Log( $"Done reading NetDb. {sw1.Elapsed}. {RouterInfos.Count} entries." );

                LoadFinished.Set();
                while ( TransportProvider.Inst == null ) Thread.Sleep( 500 );

                var periodicSave = new PeriodicAction( TickSpan.Minutes( 2 ) );
                var periodicUpdateRoulette = new PeriodicAction( TickSpan.Minutes( 1 ) );
                var periodicFfUpdate = new PeriodicAction( TickSpan.Seconds( 5 ) );

                while ( !Terminated )
                {
                    try
                    {
                        periodicSave.Do( () => Save( true ) );
                        periodicUpdateRoulette.Do( UpdateSelectionProbabilities );
                        periodicFfUpdate.Do( FloodfillUpdate.Run );
                        IdentHashLookup.Run();
                        Thread.Sleep( 2000 );
                    }
                    catch ( ThreadAbortException ex )
                    {
                        Logging.Log( ex );
                        Terminated = true;
                    }
                    catch ( Exception ex )
                    {
                        Logging.Log( ex );
                    }
                }
            }
            finally
            {
                Terminated = true;
            }
        }

        public static void Start()
        {
            if ( Inst != null ) return;

            Inst = new NetDb();

            if ( !Inst.LoadFinished.WaitOne( 450000 ) )
            {
                Inst.Terminated = true;
                throw new Exception( "NetDb Load did not finish in 450 sec!" );
            }
        }

        /// <summary>
        /// Stop the network database, terminate worker thread, and clear state.
        /// </summary>
        public static void Stop()
        {
            var inst = Inst;
            if ( inst == null ) return;

            inst.Terminated = true;

            try { Worker?.Join( 5000 ); } catch { }

            inst.RouterInfos.Clear();
            inst.FloodfillInfos.Clear();
            inst.LeaseSets.Clear();

            Worker = null;
            Inst = null;
        }

        private void UpdateSelectionProbabilities()
        {
            Statistics.UpdateScore();

            var havehost = RouterInfos.Values.Where( rp =>
                !rp.Meta.Deleted &&
                rp.Router.Addresses.Any( a =>
                    ( a.Options.Contains( "host" ) || a.Options.Contains( "h" ) ) &&
                    ( RouterContext.UseIpV6 || 
                      I2PRouterAddress.IpTestHostName( a.Options.TryGet( "host" )?.ToString() ?? a.Options.TryGet( "h" )?.ToString() ) != AddressFamily.InterNetworkV6 ) ) );

            Roulette = new RouletteSelection<I2PRouterInfo, I2PIdentHash>( 
                    havehost.Select( p => p.Router ),
                    ih => ih.Identity.IdentHash, 
                    i => Statistics[i].Score,
                    RouletteIncludeTop,
                    RouletteElitismIncrement );

            RouletteFloodFill = new RouletteSelection<I2PRouterInfo, I2PIdentHash>(
                    FloodfillInfos.Values
                        .Where( rp => !rp.Meta.Deleted )
                        .Select( rp => rp.Router ),
                    ih => ih.Identity.IdentHash, 
                    i => Statistics[i].Score,
                    RouletteIncludeTop,
                    RouletteElitismIncrement );

            RouletteNonFloodFill = new RouletteSelection<I2PRouterInfo, I2PIdentHash>(
                    havehost.Where( ri => !ri.IsFloodfill )
                        .Select( ri => ri.Router ),
                    ih => ih.Identity.IdentHash, 
                    i => Statistics[i].Score,
                    RouletteIncludeTop,
                    RouletteElitismIncrement );

            Logging.LogInformation( "All routers" );
            ShowRouletteStatistics( Roulette );
            Logging.LogInformation( "Floodfill routers" );
            ShowRouletteStatistics( RouletteFloodFill );
            Logging.LogInformation( "Non floodfill routers" );
            ShowRouletteStatistics( RouletteNonFloodFill );

            Logging.LogDebug( $"Our address: {RouterContext.Inst.ExtIpv4Address} {RouterContext.Inst.TcpPort}/{RouterContext.Inst.UdpPort} {RouterContext.Inst.MyRouterInfo}" );
        }

        private static bool ValidateRi( I2PRouterInfo one )
        {
            return one != null 
                && ( one.Options.Mappings.Count > 0 || one.Addresses.Any() );
        }

        public bool AddRouterInfo( I2PRouterInfo info )
        {
            if ( !ValidateRi( info ) )
            {
                Logging.LogDebugData( $"NetDb: RouterInfo failed validation: {info}" );
                return false;
            }

            Statistics.IsFirewalledUpdate( info.Identity.IdentHash,
                info.Addresses.Any( a =>
                    a.Options.Any( o =>
                        o.Key.ToString() == "ihost0" ) ) );

            if ( RouterInfos.TryGetValue( info.Identity.IdentHash, out var indb ) )
            {
                if ( ( (DateTime)info.PublishedDate - (DateTime)indb.Router.PublishedDate ).TotalSeconds > 2 )
                {
                    if ( !info.VerifySignature() )
                    {
                        Logging.LogDebug( $"NetDb: RouterInfo failed signature check: {info.Identity.IdentHash.Id32}" );
                        return false;
                    }

                    var meta = indb.Meta;
                    meta.Deleted = false;
                    meta.Updated = true;
                    var re = new RouterEntry( info, meta );
                    RouterInfos[info.Identity.IdentHash] = re;

                    if ( re.IsFloodfill )
                    {
                        FloodfillInfos[info.Identity.IdentHash] = re;
                    }
                    else
                    {
                        FloodfillInfos.TryRemove( info.Identity.IdentHash, out _ );
                    }

                    Logging.LogDebugData( $"NetDb: Updated RouterInfo for: {info.Identity.IdentHash}" );
                }
                else
                {
                    return true;
                }
            }
            else
            {
                if ( !info.VerifySignature() )
                {
                    Logging.LogDebug( $"NetDb: RouterInfo failed signature check: {info.Identity.IdentHash.Id32}" );
                    return false;
                }

                var meta = new RouterInfoMeta( info.Identity.IdentHash )
                {
                    Updated = true
                };
                var re = new RouterEntry( info, meta );
                RouterInfos[info.Identity.IdentHash] = re;

                if ( re.IsFloodfill )
                {
                    FloodfillInfos[info.Identity.IdentHash] = re;
                }
                else
                {
                    FloodfillInfos.TryRemove( info.Identity.IdentHash, out _ );
                }

                Logging.LogDebugData( $"NetDb: Added RouterInfo for: {info.Identity.IdentHash}" );

                // Diagnostic: dump first few received RouterInfos for format comparison
                DumpReceivedRouterInfo( info );

                Statistics.IsFirewalledUpdate(
                        info.Identity.IdentHash,
                        info.Addresses
                            .Any( a =>
                                a.Options.Any( o =>
                                    o.Key.ToString() == "ihost0" ) ) );
            }

            if ( RouterInfoUpdates != null ) ThreadPool.QueueUserWorkItem( a => RouterInfoUpdates( info ) );

            // Log the total count of known routers as requested
            Logging.LogInformation( $"NetDb: Total known routers: {RouterInfos.Count}" );

            return true;
        }

        private static int _riDumpCount = 0;
        private void DumpReceivedRouterInfo( I2PRouterInfo info )
        {
            if ( _riDumpCount >= 3 ) return; // Only dump first 3
            try
            {
                var dumpDir = System.IO.Path.Combine( SessionLayer.RouterContext.RouterPath, "debug" );
                System.IO.Directory.CreateDirectory( dumpDir );

                var riStream = new ArrayBufferWriter<byte>();
                info.Write( riStream );
                var riBytes = riStream.WrittenSpan.ToArray();

                var hash = info.Identity.IdentHash.Id32Short;
                var dumpPath = System.IO.Path.Combine( dumpDir, $"peer_routerinfo_{hash}.dat" );
                System.IO.File.WriteAllBytes( dumpPath, riBytes );

                Logging.LogInformation( $"NetDb: Dumped peer RI [{hash}]: {riBytes.Length} bytes, " +
                    $"sigType={info.Identity.Certificate.SignatureType}, " +
                    $"keyType={info.Identity.Certificate.PublicKeyType}, " +
                    $"published={info.PublishedDate}, " +
                    $"addresses={info.Addresses?.Length ?? 0}, " +
                    $"sigVerify={info.VerifySignature()}" );

                _riDumpCount++;
            }
            catch ( Exception ex )
            {
                Logging.LogDebug( $"NetDb: RI dump failed: {ex.Message}" );
            }
        }

        public bool AddRouterInfo( string file )
        {
            using ( var s = new FileStream( file, FileMode.Open, FileAccess.Read ) )
            {
                return AddRouterInfo( s );
            }
        }

        public bool AddRouterInfo( Stream s )
        {
            var buf = StreamUtils.Read( s );
            var ri = new I2PRouterInfo( new I2PBufferCursor( buf ), false );

            return AddRouterInfo( ri );
        }

        public bool Contains( I2PIdentHash key )
        {
            if ( RouterInfos.TryGetValue( key, out var pair ) )
            {
                return !pair.Meta.Deleted;
            }
            return false;
        }

        public I2PRouterInfo this[I2PIdentHash key]
        {
            get
            {
                if ( key is null ) return null;

                if ( RouterInfos.TryGetValue( key, out var pair ) )
                {
                    if ( pair?.Meta?.Deleted ?? true )
                    {
                        Logging.LogDebug( $"NetDb[]: Meta is null." );
                        return null;
                    }

                    return pair.Router;
                }
                return null;
            }
        }

        public IEnumerable<I2PIdentHash> GetRouters()
        {
            return RouterInfos.Keys.ToArray();
        }

        public string GetRouterInfoDebug( I2PIdentHash hash )
        {
            if ( RouterInfos.TryGetValue( hash, out var pair ) )
            {
                return $"Found: Deleted={pair.Meta?.Deleted}, Updated={pair.Meta?.Updated}, MetaIsNull={pair.Meta == null}, RouterIsNull={pair.Router == null}";
            }
            return "Not found in RouterInfos";
        }

        public void AddLeaseSet( ILeaseSet leaseset )
        {
            if ( LeaseSets.TryGetValue( leaseset.Destination.IdentHash, out var extls ) )
            {
                if ( extls.Expire > leaseset.Expire )
                {
                    Logging.LogDebug( $"NetDb: AddLeaseSet: Discarding as we already have a later version" );
                    return;
                }
            }

#if DEBUG
            var lifetime = leaseset.Expire - DateTime.UtcNow;
            if ( lifetime.TotalMinutes < 2 )
            {
                Logging.LogDebug( $"NetDb: AddLeaseSet: Leases are about to expire in ({lifetime})" );
            }
#endif

            LeaseSets[leaseset.Destination.IdentHash] = leaseset;

            if ( LeaseSetUpdates != null ) ThreadPool.QueueUserWorkItem( a => LeaseSetUpdates( leaseset ) );
        }

        public ILeaseSet FindLeaseSet( I2PIdentHash dest )
        {
            return LeaseSets[dest];
        }

        /// <summary>
        /// Get all stored lease sets (for web console display).
        /// </summary>
        public IEnumerable<ILeaseSet> GetAllLeaseSets()
        {
            return LeaseSets.Select( kv => kv.Value ).Where( ls => ls != null );
        }

        public static bool AreLeasesGood( ILeaseSet ls )
        {
            if ( ls?.Leases?.Any() ?? false )
            {
                return ls.Expire > DateTime.UtcNow + TimeSpan.FromMinutes( 4 );
            }

            return false;
        }

        public IEnumerable<I2PRouterInfo> Find( IEnumerable<I2PIdentHash> hashes )
        {
            foreach ( var key in hashes )
            {
                if ( RouterInfos.TryGetValue( key, out var result ) ) yield return result.Router;
            }
        }

        public void RemoveRouterInfo( I2PIdentHash hash )
        {
            if ( RouterInfos.TryGetValue( hash, out var p ) )
            {
                p.Meta.Deleted = true;
            }
            FloodfillInfos.TryRemove( hash, out _ );

            if ( RouterInfoRemovals != null ) ThreadPool.QueueUserWorkItem( a => RouterInfoRemovals( hash ) );
        }

        public void RemoveRouterInfo( IEnumerable<I2PIdentHash> hashes )
        {
            foreach ( var hash in hashes )
            {
                if ( RouterInfos.TryGetValue( hash, out var p ) )
                {
                    p.Meta.Deleted = true;
                }
                FloodfillInfos.TryRemove( hash, out _ );

                if ( RouterInfoRemovals != null ) ThreadPool.QueueUserWorkItem( a => RouterInfoRemovals( hash ) );
            }
        }

        public void AddDatabaseSearchReply( DatabaseSearchReplyMessage dbsr )
        {
            if ( DatabaseSearchReplies != null ) ThreadPool.QueueUserWorkItem( a => DatabaseSearchReplies( dbsr ) );
        }

        public delegate void ConfigAccessFunction( Dictionary<I2PString, I2PString> settings );
        public void AccessConfig( ConfigAccessFunction fcn )
        {
            try
            {
                lock ( ConfigurationSettings )
                {
                    fcn( ConfigurationSettings );
                }
            }
            catch ( Exception ex )
            {
                Logging.Log( "Exception in AccessConfig callback" );
                Logging.Log( ex );
            }
        }

        public IEnumerable<I2PRouterInfo> FindRouterInfo( Func<I2PIdentHash,I2PRouterInfo,bool> filter )
        {
            return RouterInfos
                .Where( ri => filter( ri.Key, ri.Value.Router ) )
                .Select( ri => ri.Value.Router )
                .ToArray();
        }
    }
}