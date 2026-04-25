using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.SessionLayer;
using System.Collections.Concurrent;
using I2PCore.TransportLayer;

namespace I2PCore
{
    public partial class NetDb
    {
        public int RouterCount { get => RouterInfos.Count; }
        public int FloodfillCount { get => FloodfillInfos.Count; }

        private I2PIdentHash GetRandomRouter(
            RouletteSelection<I2PRouterInfo, I2PIdentHash> r,
            ICollection<I2PIdentHash> exclude,
            bool exploratory )
        {
            I2PIdentHash result;
            var me = RouterContext.Inst.MyRouterIdentity.IdentHash;

            var retries = 0;

            if ( exploratory )
            {
                var subset = RouterInfos.Values
                    .Where( rp =>
                    {
                        var ok = !rp.Meta.Deleted &&
                        ( exclude is null || !exclude.Contains( rp.Router.Identity.IdentHash ) ) &&
                        rp.Router.Addresses.Any( a =>
                            ( a.Options.Contains( "host" ) || a.Options.Contains( "h" ) ) &&
                            ( a.TransportStyle == "SSU2" || ( a.TransportStyle == "NTCP2" && a.Options.Contains( "s" ) ) ) &&
                            ( RouterContext.UseIpV6 || 
                              I2PRouterAddress.IpTestHostName( a.Options.TryGet( "host" )?.ToString() ?? a.Options.TryGet( "h" )?.ToString() ) != AddressFamily.InterNetworkV6 ) );
                        return ok;
                    } )
                    // Filter for active/good routers to match Java's selectActiveNotFailingPeers
                    // especially for exploratory tunnels when we are bootstrapping.
                    // include untested routers for exploratory tunnels.
                    .Where( rp => {
                        var st = Statistics[rp.Router.Identity.IdentHash];
                        // Relax filter during bootstrapping (connected count < 10)
                        // or if we have no exploratory tunnels yet.
                        var established = SessionLayer.Router.ExplorationTunnelMgr?.InboundExploratory.EstablishedCount ?? 0;
                        if ( TransportProvider.Inst.ConnectedRoutersCount < 10 || established < 2 ) return true;

                        // Use NodeInactive for exploratory to allow more routers
                        return !Statistics.NodeInactive( st );
                    })
                    .OrderByDescending( rp => {
                        var established = SessionLayer.Router.ExplorationTunnelMgr?.InboundExploratory.EstablishedCount ?? 0;
                        return ( established < 2 ) && TransportProvider.Inst.IsRouterConnected( rp.Router.Identity.IdentHash, out _ );
                    })
                    .ThenBy( rp => BufUtils.RandomInt( 1000 ) )
                    .Take( 100 )
                    .ToArray();

                if ( subset.Length == 0 )
                {
                    // Fallback to anything if we have no good routers
                    subset = RouterInfos.Values
                        .Where( rp =>
                            !rp.Meta.Deleted &&
                            ( exclude is null || !exclude.Contains( rp.Router.Identity.IdentHash ) ) &&
                            rp.Router.Addresses.Any( a =>
                                ( a.Options.Contains( "host" ) || a.Options.Contains( "h" ) ) &&
                                ( a.TransportStyle == "SSU2" || ( a.TransportStyle == "NTCP2" && a.Options.Contains( "s" ) ) ) ) )
                        .ToArray();
                }

                if ( subset.Length == 0 ) return null;

                do
                {
                    result = subset
                        .Random()
                        .Router.Identity.IdentHash;
                } while ( result == me && ++retries < 20 );

                return result;
            }

            bool tryagain;
            do
            {
                result = r?.GetWeightedRandom( exclude );
                tryagain = result == me;
            } while ( tryagain && ++retries < 20 );

            if ( result == null )
            {
                // Fallback for non-exploratory if roulette failed
                var subset = RouterInfos.Values
                    .Where( rp =>
                        !rp.Meta.Deleted &&
                        ( exclude is null || !exclude.Contains( rp.Router.Identity.IdentHash ) ) &&
                        rp.Router.Identity.IdentHash != me )
                    .ToArray();
                if ( subset.Length > 0 )
                {
                    result = subset.Random().Router.Identity.IdentHash;
                }
            }

            if ( result == null && !exploratory )
            {
                 Logging.LogDebug( $"GetRandomRouter: FAILED to find any non-exploratory router. Total known: {RouterInfos.Count}. Excluded: {exclude?.Count() ?? 0}" );
            }

            return result;
        }

        private I2PRouterInfo GetRandomRouterInfo( RouletteSelection<I2PRouterInfo, I2PIdentHash> r, bool exploratory )
        {
            return this[GetRandomRouter( r, null, exploratory )];
        }

        public I2PRouterInfo GetRandomRouterInfo( bool exploratory )
        {
            return GetRandomRouterInfo( Roulette, exploratory );
        }

#if LOG_ROUTER_SELECTION_HISTORY && DEBUG
        ConcurrentDictionary<I2PIdentHash, int> RouterSelectionHistory =
            new ConcurrentDictionary<I2PIdentHash, int>();

        PeriodicAction LogRouterSelectionHistory = new PeriodicAction( TickSpan.Minutes( 5 ) );
#endif        

        public I2PIdentHash GetRandomRouterForTunnelBuild( bool exploratory, IEnumerable<I2PIdentHash> exclude = null )
        {
            return GetRandomRouter( Roulette, ( exclude is null ) ? null : exclude.ToHashSet(), exploratory );
        }

        public IEnumerable<I2PIdentHash> GetRandomRoutersForTunnelBuild( bool exploratory, int hops, IEnumerable<I2PIdentHash> initialExclude = null )
        {
            if ( hops <= 0 ) throw new ArgumentException( "Hops must be > 0" );

            var exclude = ( initialExclude is null ) 
                ? new HashSet<I2PIdentHash>() 
                : initialExclude.ToHashSet();

            var excludeFamilies = new HashSet<string>( StringComparer.OrdinalIgnoreCase );
            foreach( var ex in exclude )
            {
                var fam = GetRouterFamily( ex );
                if ( fam != null ) excludeFamilies.Add( fam );
            }

            for ( int i = 0; i < hops; ++i )
            {
                var retry = 0;
                I2PIdentHash ih = null;
                bool acceptable = false;

                while ( !acceptable && ++retry < 100 )
                {
                    ih = NetDb.Inst.GetRandomRouterForTunnelBuild( exploratory, exclude );
                    acceptable = ih != null && !exclude.Contains( ih );

                    // Family-based exclusion: don't put two routers from the same family
                    // in a single tunnel to reduce correlation attacks
                    if ( acceptable )
                    {
                        var family = GetRouterFamily( ih );
                        if ( family != null && excludeFamilies.Contains( family ) )
                        {
                            acceptable = false;
                        }
                    }
                }

                if ( acceptable )
                {
                    exclude.Add( ih );

                    // Track this router's family for exclusion
                    var routerFamily = GetRouterFamily( ih );
                    if ( routerFamily != null )
                    {
                        excludeFamilies.Add( routerFamily );
                    }

                    yield return ih;
                }
                else
                {
                    Logging.LogDebug( $"GetRandomRoutersForTunnelBuild: Failed to find hop {i+1}/{hops} after 100 retries." );
                }
            }
        }

        /// <summary>
        /// Get the family name for a router, or null if the router has no family.
        /// Uses TryGet to safely handle routers without a "family" option.
        /// </summary>
        private static string GetRouterFamily( I2PIdentHash ih )
        {
            var ri = NetDb.Inst[ih];
            return ri?.Options?.TryGet( "family" )?.ToString();
        }

        public I2PRouterInfo GetRandomNonFloodfillRouterInfo( bool exploratory )
        {
            return GetRandomRouterInfo( RouletteNonFloodFill, exploratory );
        }

        public I2PRouterInfo GetRandomFloodfillRouterInfo( bool exploratory )
        {
            return GetRandomRouterInfo( RouletteFloodFill, exploratory );
        }

        private readonly ItemFilterWindow<I2PIdentHash> RecentlyUsedForFf = new( TickSpan.Minutes( 15 ), 2 );

        public I2PIdentHash GetRandomFloodfillRouter( bool exploratory )
        {
            return GetRandomRouter( RouletteFloodFill, RecentlyUsedForFf.ToHashSet(), exploratory );
        }

        public IEnumerable<I2PIdentHash> GetRandomFloodfillRouter( bool exploratory, int count )
        {
            for ( int i = 0; i < count; ++i )
            {
                yield return GetRandomFloodfillRouter( exploratory );
            }
        }

        public IEnumerable<I2PRouterInfo> GetRandomFloodfillRouterInfo( bool exploratory, int count )
        {
            for ( int i = 0; i < count; ++i )
            {
                yield return GetRandomFloodfillRouterInfo( exploratory );
            }
        }

        public IEnumerable<I2PRouterInfo> GetRandomNonFloodfillRouterInfo( bool exploratory, int count )
        {
            for ( int i = 0; i < count; ++i )
            {
                yield return GetRandomNonFloodfillRouterInfo( exploratory );
            }
        }

        public IEnumerable<I2PIdentHash> GetClosestFloodfill(
                I2PIdentHash dest,
                int count,
                ICollection<I2PIdentHash> exclude,
                bool useIpDiversity = false )
        {
            return GetClosestFloodfill( dest, DateTime.UtcNow, count, exclude, useIpDiversity );
        }

        public IEnumerable<I2PIdentHash> GetClosestFloodfill(
                I2PIdentHash dest,
                DateTime targetDate,
                int count,
                ICollection<I2PIdentHash> exclude,
                bool useIpDiversity = false )
        {
            var subset = FloodfillInfos.Where( inf => 
                ( exclude == null || !exclude.Contains( inf.Key ) ) &&
                !Statistics.NodeInactive( Statistics[inf.Key] ) );

            if ( !subset.Any() )
            {
                subset = ( exclude != null && exclude.Any() )
                    ? FloodfillInfos.Where( inf => !exclude.Contains( inf.Key ) )
                    : FloodfillInfos;
            }

            var refkey = dest.GetRoutingKey( targetDate );

            var sorted = subset
                .Select( ri => new
                {
                    Id = ri.Key,
                    Dist = ri.Key ^ refkey,
                } )
                .OrderBy( p => p.Dist );

            if ( !useIpDiversity )
            {
                return sorted
                    .Take( count )
                    .Select( p => p.Id )
                    .ToArray();
            }

            var result = new List<I2PIdentHash>();
            var usedSubnets = new HashSet<uint>();

            foreach ( var p in sorted )
            {
                var subnet = GetIpSubnet( p.Id );
                if ( subnet == 0 || usedSubnets.Add( subnet ) )
                {
                    result.Add( p.Id );
                    if ( result.Count >= count ) break;
                }
            }

            return result;
        }

        private static uint GetIpSubnet( I2PIdentHash ih )
        {
            var ri = NetDb.Inst[ih];
            if ( ri == null ) return 0;
            foreach ( var addr in ri.Addresses )
            {
                var ip = addr.Host;
                if ( ip != null && ip.AddressFamily == AddressFamily.InterNetwork )
                {
                    var bytes = ip.GetAddressBytes();
                    return (uint)( ( bytes[0] << 24 ) | ( bytes[1] << 16 ) | ( bytes[2] << 8 ) );
                }
            }
            return 0;
        }

        public IEnumerable<I2PRouterInfo> GetClosestFloodfillInfo(
            I2PIdentHash reference,
            int count,
            ICollection<I2PIdentHash> exclude )
        {
            return Find( GetClosestFloodfill( reference, count, exclude ) );
        }
    }
}
