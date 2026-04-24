using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.Utils;
using I2PCore.TransportLayer;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Messages;

namespace I2PCore.TunnelLayer
{
    public class TunnelPoolManager
    {
        private readonly TunnelPool _inboundExploratory;
        private readonly TunnelPool _outboundExploratory;
        
        private readonly ConcurrentDictionary<I2PIdentHash, TunnelPool> _clientInboundPools = new();
        private readonly ConcurrentDictionary<I2PIdentHash, TunnelPool> _clientOutboundPools = new();

        private readonly TunnelProvider _tunnelMgr;

        public TunnelPool InboundExploratory => _inboundExploratory;
        public TunnelPool OutboundExploratory => _outboundExploratory;

        public int EstablishedTunnels => _inboundExploratory.EstablishedCount + _outboundExploratory.EstablishedCount;

        public TunnelPoolManager( TunnelProvider tp )
        {
            _tunnelMgr = tp;

            var ibExplSettings = new TunnelPoolSettings( true );
            _inboundExploratory = new TunnelPool( tp, ibExplSettings );

            var obExplSettings = new TunnelPoolSettings( false );
            _outboundExploratory = new TunnelPool( tp, obExplSettings );
        }

        private PeriodicAction TunnelBuild = new( TickSpan.Seconds( 1 ) );
        private PeriodicAction LogStatus = new( TickSpan.Seconds( 30 ) );
        private readonly TickCounter _startTime = TickCounter.Now;

        /// <summary>
        /// Grace period after startup before attempting multi-hop tunnel builds.
        /// Allows time for NTCP2 connections to be established with peers.
        /// </summary>
        private static readonly TickSpan StartupGracePeriod = TickSpan.Seconds( 15 );

        public void Execute()
        {
            if ( _inboundExploratory.EstablishedCount == 0 && TransportProvider.Inst.ConnectedRoutersCount > 0 )
            {
                _inboundExploratory.CreateFallbackTunnel();
            }
            if ( _outboundExploratory.EstablishedCount == 0 && TransportProvider.Inst.ConnectedRoutersCount > 0 )
            {
                _outboundExploratory.CreateFallbackTunnel();
            }

            // Wait for peer connections to be established before building multi-hop tunnels
            if ( _startTime.DeltaToNow < StartupGracePeriod )
                return;

            TunnelBuild.Do( BuildNewTunnels );
            LogStatus.Do( LogStatusReport );
        }

        private void BuildNewTunnels()
        {
            if ( RouterContext.Inst.FloodfillEnabled )
            {
                // Java-like: Increase exploratory tunnel quantity for floodfills
                _inboundExploratory.Settings.Quantity = Math.Max( _inboundExploratory.Settings.Quantity, 6 );
                _outboundExploratory.Settings.Quantity = Math.Max( _outboundExploratory.Settings.Quantity, 6 );
            }

            var inNeeded = _inboundExploratory.CountHowManyToBuild();
            var outNeeded = _outboundExploratory.CountHowManyToBuild();

            var inProgress = _inboundExploratory.InProgressCount;
            var outProgress = _outboundExploratory.InProgressCount;

            if ( inNeeded <= 0 && outNeeded <= 0 ) return;

            // Use real (non-0-hop) counts to decide aggressiveness.
            // 0-hop fallback tunnels are useful but don't indicate healthy network participation.
            var realEstablished = _inboundExploratory.RealEstablishedCount + _outboundExploratory.RealEstablishedCount;
            var connectedCount = TransportProvider.Inst.ConnectedRoutersCount;

            // Panic mode: no real tunnels. Fire even if some are in-progress — they
            // may all be timing out and we shouldn't wait for them.
            if ( realEstablished == 0 && connectedCount > 0 )
            {
                Logging.LogDebug( $"TunnelPoolManager: Panic mode — no real tunnels (in-progress: {inProgress + outProgress}). Building aggressively." );
                _outboundExploratory.CreateTunnels( 5 );
                _inboundExploratory.CreateTunnels( 5 );
                return;
            }

            // Adjust frequency dynamically for bootstrapping
            TunnelBuild.Frequency = ( realEstablished < 2 || connectedCount < 10 )
                ? TickSpan.Milliseconds( 500 )
                : TickSpan.Seconds( 1 );

            // Proactive bootstrapping: build outbound first since inbound build
            // requests need to be sent via an outbound tunnel.
            if ( connectedCount < 3 || _outboundExploratory.RealEstablishedCount == 0 )
            {
                var targetBootstrap = ( connectedCount == 0 ) ? 5 : 2;
                _outboundExploratory.CreateTunnels( targetBootstrap );
                _inboundExploratory.CreateTunnels( targetBootstrap );
            }

            // Max tunnels to build per cycle
            var maxTunnels = ( realEstablished < 2 || connectedCount < 10 ) ? 20 : 5;

            // Build both directions fairly — outbound first since inbound
            // build requests are sent through outbound tunnels.
            var toBuildTotal = Math.Min( inNeeded + outNeeded, maxTunnels );
            if ( toBuildTotal > 0 )
            {
                var outToBuild = ( inNeeded > 0 && outNeeded > 0 ) ? ( toBuildTotal + 1 ) / 2 : ( outNeeded > 0 ? toBuildTotal : 0 );
                var inToBuild = toBuildTotal - outToBuild;

                if ( outToBuild > 0 ) _outboundExploratory.CreateTunnels( outToBuild );
                if ( inToBuild > 0 ) _inboundExploratory.CreateTunnels( inToBuild );
            }
        }

        private void LogStatusReport()
        {
            var ei = _inboundExploratory.EstablishedCount;
            var pi = _inboundExploratory.InProgressCount;
            var eo = _outboundExploratory.EstablishedCount;
            var po = _outboundExploratory.InProgressCount;

            var status = RouterContext.Inst.IsFirewalled ? "Firewalled" : "Reachable";
            Logging.LogInformation(
                $"Exploratory Tunnels: in {ei,2} ({pi,2}), out {eo,2} ({po,2}) IB:{_inboundExploratory.BuildSuccessRatio} OB:{_outboundExploratory.BuildSuccessRatio} Status: {status} Conns: {TransportProvider.Inst.ConnectedRoutersCount}" );
        }
    }
}
