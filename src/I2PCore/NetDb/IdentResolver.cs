using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;
using I2PCore.TunnelLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.SessionLayer;
using I2PCore.SessionLayer.ECIES;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.TransportLayer;
using I2PCore.TransportLayer.Crypto;
using I2PCore.Data;
using System.Threading;
using System.Collections.Concurrent;

namespace I2PCore
{
    public class IdentResolver
    {
        public const int DatabaseLookupRetriesRi = 4;
        public const int DatabaseLookupRetriesLs = 20;
        public const int DatabaseLookupSelectFloodfillCountRi = 3;
        public const int DatabaseLookupSelectFloodfillCountLs = 3;
        public static TickSpan WaitForRouterInfo = TickSpan.Seconds( 10 );
        public static TickSpan WaitForLeaseSet = TickSpan.Seconds( 10 );

        private PeriodicAction CheckForTimouts = new( TickSpan.Seconds( 3 ) );
        private PeriodicAction ExploreNewRouters = new( TickSpan.Seconds( 15 ) );

        public delegate void IdentResolverResultFail( I2PIdentHash key );
        public delegate void IdentResolverResultRouterInfo( I2PRouterInfo ri );
        public delegate void IdentResolverResultLeaseSet( ILeaseSet ls );

        public delegate void IdentResolverResultFailEx( I2PIdentHash key, IdentUpdateRequestInfo info );
        public delegate void IdentResolverResultRouterInfoEx( I2PRouterInfo ri, IdentUpdateRequestInfo info );
        public delegate void IdentResolverResultLeaseSetEx( ILeaseSet ls, IdentUpdateRequestInfo info );

        public event IdentResolverResultFail LookupFailure;
        public event IdentResolverResultRouterInfo RouterInfoReceived;
        public event IdentResolverResultLeaseSet LeaseSetReceived;

        public event IdentResolverResultFailEx LookupFailureEx;
        public event IdentResolverResultRouterInfoEx RouterInfoReceivedEx;
        public event IdentResolverResultLeaseSetEx LeaseSetReceivedEx;

        public enum ReceivedFloodfillResponses { NoResponse, Timeout, SearchReply, DatabaseStore }
        public class FloodfillResponse
        {
            public ReceivedFloodfillResponses Response = ReceivedFloodfillResponses.NoResponse;
            public I2PIdentHash Floodfill;
        }

        public class LookupAttempt
        {
            public readonly TickCounter Start = TickCounter.Now;
            public I2PIdentHash OutboundTunnelGateway;
            public uint? OutboundTunnelId;
            public I2PIdentHash InboundTunnelGateway;
            public uint? InboundTunnelId;
            public string Details;
            public ConcurrentDictionary<I2PIdentHash, FloodfillResponse> FloodfillResponses = new();
        }

        public class IdentUpdateRequestInfo
        {
            public readonly TickCounter Start = TickCounter.Now;
            public readonly TickSpan DatabaseLookupWaitTime;
            public readonly I2PIdentHash LookupIdent;
            public readonly DatabaseLookupMessage.LookupTypes LookupType;

            public SessionLayer.ClientDestination ClientContext;

            public int Retries;
            public ConcurrentDictionary<I2PIdentHash,FloodfillResponse> FloodfillResponses { get; set; }
            public List<LookupAttempt> Attempts = new();

            public static TimeWindowDictionary<I2PIdentHash,object> AlreadyQueried = new(TickSpan.Minutes(3));

            public IdentUpdateRequestInfo( 
                I2PIdentHash id,
                DatabaseLookupMessage.LookupTypes lookuptype )
            {
                FloodfillResponses = new ConcurrentDictionary<I2PIdentHash,FloodfillResponse>();
                LookupIdent = id;
                LookupType = lookuptype;
                Retries = 0;

                switch ( lookuptype )
                {
                    case DatabaseLookupMessage.LookupTypes.RouterInfo:
                        DatabaseLookupWaitTime = WaitForRouterInfo;
                        break;

                    case DatabaseLookupMessage.LookupTypes.Normal:
                    case DatabaseLookupMessage.LookupTypes.LeaseSet:
                        DatabaseLookupWaitTime = WaitForLeaseSet;
                        break;
                }
            }

            public void StartLookup( 
                IEnumerable<I2PIdentHash> floodfills,
                TunnelLayer.OutboundTunnel outtunnel = null,
                TunnelLayer.InboundTunnel intunnel = null )
            {
                lock ( Attempts )
                {
                    if ( Attempts.Any() )
                    {
                        var last = Attempts.Last();
                        foreach ( var resp in FloodfillResponses )
                        {
                            last.FloodfillResponses[resp.Key] = resp.Value;
                        }
                    }
                }

                FloodfillResponses = new ConcurrentDictionary<I2PIdentHash,FloodfillResponse>(
                    floodfills.Select( ff => new KeyValuePair<I2PIdentHash, FloodfillResponse>(
                        ff,
                        new FloodfillResponse() ) ) );

                var attempt = new LookupAttempt
                {
                    OutboundTunnelGateway = outtunnel?.Destination,
                    OutboundTunnelId = outtunnel?.SendTunnelId is not null ? (uint)outtunnel.SendTunnelId : (uint?)null,
                    InboundTunnelGateway = intunnel?.Destination,
                    InboundTunnelId = intunnel?.GatewayTunnelId is not null ? (uint)intunnel.GatewayTunnelId : (uint?)null,
                };
                foreach ( var ff in floodfills )
                {
                    attempt.FloodfillResponses[ff] = new FloodfillResponse { Floodfill = ff };
                }
                lock ( Attempts )
                {
                    Attempts.Add( attempt );
                }

                Start.SetNow();
            }

            public void RecordError( string error )
            {
                lock ( Attempts )
                {
                    Attempts.Add( new LookupAttempt
                    {
                        Details = error
                    } );
                }
            }
        }

        private ConcurrentDictionary<I2PIdentHash, IdentUpdateRequestInfo> OutstandingQueries = new();
        private TimeWindowDictionary<I2PIdentHash, IdentUpdateRequestInfo> FinishedLookups = new( TickSpan.Minutes( 5 ) );

        public IdentUpdateRequestInfo GetQueryInfo( I2PIdentHash key )
        {
            if ( OutstandingQueries.TryGetValue( key, out var info ) ) return info;
            if ( FinishedLookups.TryGetValue( key, out info ) ) return info;
            return null;
        }

        public IdentResolver( NetDb db )
        {
            db.RouterInfoUpdates += NetDb_RouterInfoUpdates;
            db.LeaseSetUpdates += NetDb_LeaseSetUpdates;
            db.DatabaseSearchReplies += NetDb_DatabaseSearchReplies;
        }

        public bool LookupRouterInfo( I2PIdentHash ident )
        {
            bool inprogress = true;

            var updateinfo = OutstandingQueries.GetOrAdd(
                    ident,
                    ( id ) =>
                    {
                        inprogress = false;
                        return new IdentUpdateRequestInfo(
                                ident,
                                DatabaseLookupMessage.LookupTypes.RouterInfo );
                    } );

            if ( inprogress )
            {
#if LOG_ALL_IDENT_LOOKUPS
                Logging.LogDebug( $"IdentResolver: Lookup of RouterInfo {ident.Id32Short} already in progress." );
#endif
                return false;
            }

#if LOG_ALL_IDENT_LOOKUPS
            Logging.Log( $"IdentResolver: Starting lookup of RouterInfo for {ident.Id32Short}." );
#endif

            SendRiDatabaseLookup( ident, updateinfo );

            return true;
        }

        public bool LookupLeaseSet( I2PIdentHash ident, SessionLayer.ClientDestination clientContext = null )
        {
            bool inprogress = true;

            var updateinfo = OutstandingQueries.GetOrAdd(
                    ident,
                    ( id ) =>
                    {
                        inprogress = false;
                        return new IdentUpdateRequestInfo(
                                ident,
                                DatabaseLookupMessage.LookupTypes.LeaseSet )
                        {
                            ClientContext = clientContext
                        };
                    } );

            if ( inprogress )
            {
                Logging.LogDebug( $"IdentResolver: Lookup of LeaseSet {ident.Id32Short} already in progress." );
                return false;
            }

            Logging.LogDebug( $"IdentResolver: Starting lookup of LeaseSet for {ident.Id32Short}." );
            SendLsDatabaseLookup( ident, updateinfo );

            return true;
        }

        private void NetDb_DatabaseSearchReplies( DatabaseSearchReplyMessage dsm )
        {
            if ( dsm == null || dsm.From == null ) return;
            var peerCount = dsm.Peers?.Count ?? 0;
            var newCount = 0;

            Logging.LogDebug( $"IdentResolver: SearchReply for {dsm.Key.Id32Short} from {dsm.From.Id32Short}: {peerCount} peers" );

            foreach ( var router in dsm.Peers )
            {
                if ( NetDb.Inst.Contains( router ) )
                {
                    continue;
                }
                newCount++;
                LookupRouterInfo( router );
            }

            if ( newCount > 0 )
            {
                Logging.LogInformation( $"IdentResolver: Exploration found {newCount} new routers (of {peerCount} total) from {dsm.From.Id32Short}" );
            }

            if ( !OutstandingQueries.TryGetValue( dsm.Key, out var info ) ) return;

            var isleaseset = info.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet;

            // Collect router performance
            if ( info.FloodfillResponses.TryGetValue( dsm.From, out var resp )
                    && resp.Response == ReceivedFloodfillResponses.NoResponse )
            {
                NetDb.Inst.Statistics.IdentResolveReply( dsm.From );

                var update = new FloodfillResponse()
                {
                    Floodfill = dsm.From,
                    Response = ReceivedFloodfillResponses.SearchReply
                };
                lock ( info.Attempts )
                {
                    if ( info.Attempts.Any() ) info.Attempts.Last().FloodfillResponses[dsm.From] = update;
                }
            }
            else
            {
                // Response from someone we didn't directly query (or already recorded)?
                // Just record it and continue without failing others.
                var update = new FloodfillResponse()
                {
                    Floodfill = dsm.From,
                    Response = ReceivedFloodfillResponses.SearchReply
                };
                info.FloodfillResponses[dsm.From] = update;
                lock ( info.Attempts )
                {
                    if ( info.Attempts.Any() ) info.Attempts.Last().FloodfillResponses[dsm.From] = update;
                }
            }

            ++info.Retries;

            if ( info.Retries <= ( isleaseset ? DatabaseLookupRetriesLs : DatabaseLookupRetriesRi ) )
            {
#if LOG_ALL_IDENT_LOOKUPS
                Logging.Log( string.Format( "IdentResolver: Lookup of {0} {1} resulted in alternative servers to query '{2}'. Retrying.",
                    ( isleaseset ? "LeaseSet" : "RouterInfo" ),
                    dsm.Key.Id32Short, peerCount ) );
#endif

                if ( isleaseset )
                {
                    SendLsDatabaseLookup( info.LookupIdent, info );
                }
                else
                {
                    SendRiDatabaseLookup( info.LookupIdent, info );
                }
            }
            else
            {
                Logging.Log( string.Format( "IdentResolver: Lookup of {0} {1} resulted in alternative servers to query '{2}'. Lookup failed.",
                    ( isleaseset ? "LeaseSet" : "RouterInfo" ),
                    dsm.Key.Id32Short, peerCount ) );

                OutstandingQueries.TryRemove( dsm.Key, out _ );
                FinishedLookups[dsm.Key] = info;
                if ( LookupFailure != null ) ThreadPool.QueueUserWorkItem( a => LookupFailure( dsm.Key ) );
            }
        }

        private void NetDb_LeaseSetUpdates( ILeaseSet ls )
        {
            if ( !OutstandingQueries.TryRemove( ls.Destination.IdentHash, out var info ) )
            {
                return;
            }
            FinishedLookups[ls.Destination.IdentHash] = info;

            // Collect router performance
            var noresponse = info.FloodfillResponses
                    .Where( r => r.Value.Response == ReceivedFloodfillResponses.NoResponse );

            // Give all the credit
            foreach( var one in noresponse )
            {
                var from = one.Key;

                NetDb.Inst.Statistics.IdentResolveSuccess( from );

                var update = new FloodfillResponse()
                {
                    Floodfill = from,
                    Response = ReceivedFloodfillResponses.DatabaseStore
                };
                info.FloodfillResponses[from] = update;
                lock ( info.Attempts )
                {
                    if ( info.Attempts.Any() ) info.Attempts.Last().FloodfillResponses[from] = update;
                }
            }

            if ( ls.Expire < DateTime.UtcNow )
            {
                Logging.LogDebug( $"IdentResolver: Lookup of LeaseSet " +
                    $"{ls} succeeded, but has expired. {info.Start.DeltaToNow}" );

                SendRetries( new IdentUpdateRequestInfo[] { info } );

                return;
            }

            Logging.Log( $"IdentResolver: Lookup of LeaseSet " +
                $"{ls.Destination.IdentHash.Id32Short} succeeded. {info.Start.DeltaToNow}" );

            if ( LeaseSetReceived != null ) ThreadPool.QueueUserWorkItem( a => LeaseSetReceived( ls ) );
            if ( LeaseSetReceivedEx != null ) ThreadPool.QueueUserWorkItem( a => LeaseSetReceivedEx( ls, info ) );
        }

        private void NetDb_RouterInfoUpdates( I2PRouterInfo ri )
        {
            if ( !OutstandingQueries.TryRemove( ri.Identity.IdentHash, out var info ) )
            {
                return;
            }
            FinishedLookups[ri.Identity.IdentHash] = info;

            // Collect router performance
            var noresponse = info.FloodfillResponses
                    .Where( r => r.Value.Response == ReceivedFloodfillResponses.NoResponse );

            // Give all the credit
            foreach( var one in noresponse )
            {
                var from = one.Key;
                
                NetDb.Inst.Statistics.IdentResolveSuccess( from );

                var update = new FloodfillResponse()
                {
                    Floodfill = from,
                    Response = ReceivedFloodfillResponses.DatabaseStore
                };
                info.FloodfillResponses[from] = update;
                lock ( info.Attempts )
                {
                    if ( info.Attempts.Any() ) info.Attempts.Last().FloodfillResponses[from] = update;
                }
            }

            Logging.Log( $"IdentResolver: Lookup of RouterInfo " +
                $"{ri.Identity.IdentHash.Id32Short} succeeded. {info.Start.DeltaToNow}" );

            if ( RouterInfoReceived != null ) ThreadPool.QueueUserWorkItem( a => RouterInfoReceived( ri ) );
            if ( RouterInfoReceivedEx != null ) ThreadPool.QueueUserWorkItem( a => RouterInfoReceivedEx( ri, info ) );
        }

        public void Run()
        {
            CheckForTimouts.Do( CheckTimeouts );
            ExploreNewRouters.Do( ExplorationRouterLookup );
        }

        private void SendRiDatabaseLookup( I2PIdentHash ident, IdentUpdateRequestInfo info )
        {
            var excluded = IdentUpdateRequestInfo.AlreadyQueried.Select( d => d.Key ).ToHashSet();

            // For firewalled routers, prefer connected floodfills for direct delivery
            var connectedRouters = TransportProvider.Inst.GetConnectedRouterHashes().ToHashSet();
            var allFf = NetDb.Inst.GetClosestFloodfill(
                ident, 10 + 3 * info.Retries, excluded );

            if ( !allFf.Any() )
            {
                var err = $"failed to find a floodfill router to lookup ({ident.Id32Short})";
                Logging.Log( $"IdentResolver: {err}" );
                info.RecordError( err );
                return;
            }

            // Always try to use exploratory tunnels first (even when firewalled).
            // Only fall back to direct transport if no tunnels are available.
            var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel( TunnelPoolSelection.RequireExploratory )
                ?? TunnelProvider.Inst.GetEstablishedOutboundTunnel( TunnelPoolSelection.AllowExploratory );
            var replytunnel = TunnelProvider.Inst.GetEstablishedInboundTunnel( TunnelPoolSelection.RequireExploratory )
                ?? TunnelProvider.Inst.GetEstablishedInboundTunnel( TunnelPoolSelection.AllowExploratory );
            bool useTunnels = outtunnel != null && replytunnel != null;

            // Prefer connected floodfills for reliable delivery
            I2PIdentHash[] ff;
            if ( RouterContext.Inst.IsFirewalled && !useTunnels )
            {
                var connFf = allFf.Where( f => connectedRouters.Contains( f ) ).ToArray();
                ff = connFf.Length > 0
                    ? new[] { connFf[BufUtils.RandomInt( connFf.Length )] }
                    : BufUtils.Shuffle( allFf ).Take( DatabaseLookupSelectFloodfillCountRi ).ToArray();
            }
            else
            {
                ff = BufUtils.Shuffle( allFf ).Take( DatabaseLookupSelectFloodfillCountRi ).ToArray();
            }

            foreach ( var oneff in ff )
            {
                try
                {
                    DatabaseLookupMessage msg;

                    if ( useTunnels )
                    {
                        msg = new DatabaseLookupMessage(
                            ident,
                            replytunnel.Destination,
                            replytunnel.GatewayTunnelId,
                            DatabaseLookupMessage.LookupTypes.RouterInfo,
                            excluded );
                        outtunnel.Send( new TunnelMessageRouter( msg, oneff ) );
                    }
                    else if ( connectedRouters.Contains( oneff ) )
                    {
                        // Direct to connected floodfill - reply on same connection
                        msg = new DatabaseLookupMessage(
                            ident,
                            RouterContext.Inst.MyRouterIdentity.IdentHash,
                            DatabaseLookupMessage.LookupTypes.RouterInfo,
                            excluded );
                        TransportProvider.Send( oneff, msg );
                    }
                    else
                    {
                        // Direct to unconnected floodfill - less reliable
                        msg = new DatabaseLookupMessage(
                            ident,
                            RouterContext.Inst.MyRouterIdentity.IdentHash,
                            DatabaseLookupMessage.LookupTypes.RouterInfo,
                            excluded );
                        TransportProvider.Send( oneff, msg );
                    }
                }
                catch ( Exception ex )
                {
                    Logging.Log( "SendRIDatabaseLookup", ex );
                }

                IdentUpdateRequestInfo.AlreadyQueried[oneff] = 1;
            }

            info.StartLookup( ff, outtunnel, replytunnel );
        }

        private void SendLsDatabaseLookup( I2PIdentHash ident, IdentUpdateRequestInfo info )
        {
            // LeaseSet lookups MUST ALWAYS go through tunnels - NEVER direct transport.
            // Direct contact with floodfills for LS lookups is a deanonymization vulnerability.
            //
            // Java I2P IterativeSearchJob.sendQuery() always:
            // 1. Sets reply encryption (session key + ratchet tag) on the DLM
            // 2. Garlic-wraps the DLM to the floodfill's ECIES public key
            // Without garlic wrapping, modern floodfills may ignore LS lookups.

            try
            {
                // Select tunnels: prefer client's own tunnels, fall back to exploratory tunnels.
                OutboundTunnel outtunnel = null;
                InboundTunnel replytunnel = null;

                if ( info.ClientContext != null )
                {
                    // Use the client destination's own tunnel pool (most anonymous)
                    outtunnel = info.ClientContext.SelectOutboundTunnel();
                    replytunnel = info.ClientContext.SelectInboundTunnel();
                }

                outtunnel ??= TunnelProvider.Inst.GetEstablishedOutboundTunnel( TunnelPoolSelection.RequireExploratory )
                    ?? TunnelProvider.Inst.GetEstablishedOutboundTunnel( TunnelPoolSelection.AllowExploratory );

                replytunnel ??= TunnelProvider.Inst.GetEstablishedInboundTunnel( TunnelPoolSelection.RequireExploratory )
                    ?? TunnelProvider.Inst.GetEstablishedInboundTunnel( TunnelPoolSelection.AllowExploratory );

                if ( outtunnel == null || replytunnel == null )
                {
                    var err = $"LS lookup {ident.Id32Short} deferred - no tunnels available yet";
                    Logging.LogDebug( $"IdentResolver: {err}" );
                    info.RecordError( err );
                    return;
                }

                // For LS lookups, exclude only FFs we've already queried for THIS specific lookup.
                // Using the global AlreadyQueried set contaminates LS lookups with RI/exploration
                // queries and causes "no floodfills available" even when FFs exist.
                var excluded = info.FloodfillResponses.Keys.ToHashSet();
                var allFf = NetDb.Inst.GetClosestFloodfill(
                    ident,
                    DatabaseLookupSelectFloodfillCountLs + 2 * info.Retries,
                    excluded );

                if ( !allFf.Any() )
                {
                    // Fall back to no exclusions (shouldn't happen with 200+ routers)
                    allFf = NetDb.Inst.GetClosestFloodfill( ident, DatabaseLookupSelectFloodfillCountLs, null );
                    if ( !allFf.Any() )
                    {
                        var err = $"No floodfills available for LS lookup ({ident.Id32Short})";
                        Logging.Log( $"IdentResolver: {err}" );
                        info.RecordError( err );
                        return;
                    }
                }

                var selectedFf = BufUtils.Shuffle( allFf )
                    .Take( DatabaseLookupSelectFloodfillCountLs )
                    .ToArray();

                foreach ( var oneffid in selectedFf )
                {
                    try
                    {
                        var ri = NetDb.Inst[oneffid];
                        if ( ri == null )
                        {
                            Logging.LogDebug( $"IdentResolver: LS lookup {ident.Id32Short} -> ff {oneffid.Id32Short}: no RouterInfo, skipping" );
                            continue;
                        }

                        // Determine floodfill's encryption type
                        var ffKeyType = ri.Identity.Certificate.PublicKeyType;
                        var isEcies = ffKeyType == I2PKeyType.KeyTypes.X25519
                            || ffKeyType == I2PKeyType.KeyTypes.MLKEM512_X25519
                            || ffKeyType == I2PKeyType.KeyTypes.MLKEM768_X25519
                            || ffKeyType == I2PKeyType.KeyTypes.MLKEM1024_X25519;

                        I2NpMessage outMsg;

                        if ( isEcies )
                        {
                            // ECIES floodfill: garlic-wrap the DLM using Noise N
                            // Java: MessageWrapper.wrap(ctx, dlm, ri) + dlm.setReplySession(key, rtag)
                            outMsg = CreateEciesWrappedLookup( ident, replytunnel, excluded, ri, oneffid );
                        }
                        else
                        {
                            // ElGamal floodfill: garlic-wrap using ElGamal encryption
                            outMsg = CreateElGamalWrappedLookup( ident, replytunnel, excluded, ri, oneffid );
                        }

                        if ( outMsg == null )
                        {
                            // Fallback: send plain DLM (should not normally happen)
                            Logging.LogWarning( $"IdentResolver: LS lookup {ident.Id32Short} -> ff {oneffid.Id32Short}: garlic wrap failed, sending plain DLM" );
                            var plainMsg = new DatabaseLookupMessage(
                                ident,
                                replytunnel.Destination,
                                replytunnel.GatewayTunnelId,
                                DatabaseLookupMessage.LookupTypes.LeaseSet,
                                excluded );
                            outMsg = plainMsg;
                        }

                        outtunnel.Send( new TunnelMessageRouter( outMsg, oneffid ) );

                        Logging.LogInformation( $"IdentResolver: LS lookup {ident.Id32Short} -> ff {oneffid.Id32Short} ({(isEcies ? "ECIES" : "ElG")} garlic-wrapped)" );
                        IdentUpdateRequestInfo.AlreadyQueried[oneffid] = 1;
                    }
                    catch ( Exception ex )
                    {
                        Logging.Log( "SendLSDatabaseLookup", ex );
                    }
                }

                info.StartLookup( selectedFf, outtunnel, replytunnel );
            }
            catch ( Exception ex )
            {
                Logging.Log( "SendLSDatabaseLookup2", ex );
            }
        }

        /// <summary>
        /// Create an ECIES garlic-wrapped DatabaseLookupMessage for LS lookups.
        /// Mirrors Java I2P IterativeSearchJob.sendQuery() for ECIES floodfills:
        /// 1. Generate reply session (ratchet tag + key) so FF encrypts the reply
        /// 2. Set the reply session on the DLM
        /// 3. Garlic-wrap the DLM to the floodfill's X25519 public key using Noise N
        /// </summary>
        private I2NpMessage CreateEciesWrappedLookup(
            I2PIdentHash ident,
            InboundTunnel replytunnel,
            ICollection<I2PIdentHash> excluded,
            I2PRouterInfo ri,
            I2PIdentHash ffHash )
        {
            try
            {
                var ffPubKey = ri.GetECIESPublicKey();
                if ( ffPubKey == null || ffPubKey.Length != 32 )
                {
                    Logging.LogWarning( $"IdentResolver: ff {ffHash.Id32Short} has no ECIES public key" );
                    return null;
                }

                // Generate a one-time reply session (ratchet tag + key).
                // The floodfill will use these to encrypt its DatabaseStoreMessage reply.
                // Java: MessageWrapper.generateSession(ctx, skm, SINGLE_SEARCH_MSG_TIME, false)
                var replyKey = BufUtils.RandomBytes( 32 );
                var ratchetTag = SessionTag.Generate();

                // Register the one-time session so we can decrypt the reply when it arrives
                var eciesProcessor = Router.EciesRouterProcessor;
                eciesProcessor?.SessionManager?.RegisterOneTimeSession( ratchetTag, replyKey );

                // Build the DLM with ECIES reply encryption.
                // The DLM includes: Ecies flag + reply key (our X25519 pub) + ratchet tag
                // Java: dlm.setReplySession(sess.key, sess.rtag)
                var replyKeyInfo = new DatabaseLookupKeyInfo
                {
                    EncryptionFlag = false,
                    EciesFlag = true,
                    ReplyKey = new BufLen( replyKey ),
                    Tags = new BufLen[] { new BufLen( ratchetTag.ToByteArray() ) }
                };

                var dlm = new DatabaseLookupMessage(
                    ident,
                    replytunnel.Destination,
                    replytunnel.GatewayTunnelId,
                    DatabaseLookupMessage.LookupTypes.LeaseSet,
                    excluded,
                    replyKeyInfo );

                // Garlic-wrap the DLM to the floodfill's ECIES public key using Noise N.
                // Java: outMsg = MessageWrapper.wrap(ctx, dlm, ri)
                // This creates a GarlicMessage containing the DLM as a local-delivery clove.
                var garlicMsg = WrapInEciesGarlic( dlm, ffPubKey );

                Logging.LogDebug( $"IdentResolver: ECIES garlic-wrapped DLM for {ident.Id32Short} to ff {ffHash.Id32Short}" );
                return garlicMsg;
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"IdentResolver: ECIES garlic wrap failed for ff {ffHash.Id32Short}: {ex.Message}" );
                return null;
            }
        }

        /// <summary>
        /// Wrap a DatabaseLookupMessage in an ECIES garlic message (Noise N).
        /// Uses the same ECIES block format as TunnelProvider.CreateECIESGarlicMessage().
        /// The clove uses local delivery instructions so the floodfill processes the DLM locally.
        /// </summary>
        private static GarlicMessage WrapInEciesGarlic( DatabaseLookupMessage dlm, byte[] ffPublicKey )
        {
            // Build the garlic clove with local delivery instructions.
            // ECIES clove format (per Proposal 144 / readBytesRatchet):
            //   DeliveryInstructions(1 byte: 0x00 = local) + type(1) + msgID(4) + expiration_secs(4) + payload
            var cloveStream = new BufRefStream();
            cloveStream.Write( (byte)0 ); // Local delivery
            cloveStream.Write( (byte)dlm.MessageType );
            cloveStream.Write( BufUtils.Flip32Bl( dlm.MessageId ) );
            var expirationSecs = (uint)( DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20 ); // 20s like Java SINGLE_SEARCH_MSG_TIME
            cloveStream.Write( BufUtils.Flip32Bl( expirationSecs ) );
            cloveStream.Write( dlm.Payload );

            // Build ECIES blocks: DateTime + GarlicClove + Padding
            var blocks = new List<SessionLayer.ECIES.Block>
            {
                new DateTimeBlock { Timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                new SessionLayer.ECIES.GarlicCloveBlock { Data = cloveStream.ToByteArray() },
                new PaddingBlock { Data = BufUtils.RandomBytes( 16 + BufUtils.RandomInt( 32 ) ) }
            };

            var plaintext = ECIESBlockFormat.BuildBlocks( blocks );

            // Encrypt using Noise N to the floodfill's X25519 public key
            var noiseN = NoiseN.CreateInitiator( ffPublicKey );
            var encrypted = noiseN.CreateMessage( plaintext );
            noiseN.Dispose();

            // The Noise N output IS the garlic payload (no tag prefix for new sessions).
            // Wrap in GarlicMessage which adds the 4-byte length prefix.
            return new GarlicMessage( encrypted );
        }

        /// <summary>
        /// Create an ElGamal garlic-wrapped DatabaseLookupMessage for legacy floodfills.
        /// Java: MessageWrapper.wrap(ctx, dlm, ri) with ElGamal encryption.
        /// </summary>
        private I2NpMessage CreateElGamalWrappedLookup(
            I2PIdentHash ident,
            InboundTunnel replytunnel,
            ICollection<I2PIdentHash> excluded,
            I2PRouterInfo ri,
            I2PIdentHash ffHash )
        {
            try
            {
                // For ElGamal floodfills, create a plain DLM without reply encryption
                // (ElGamal reply encryption uses AES session tags which is complex;
                // send the DLM garlic-wrapped but with unencrypted reply for now).
                var dlm = new DatabaseLookupMessage(
                    ident,
                    replytunnel.Destination,
                    replytunnel.GatewayTunnelId,
                    DatabaseLookupMessage.LookupTypes.LeaseSet,
                    excluded );

                // Garlic-wrap using ElGamal to the floodfill's public key
                var sessionkey = new I2PSessionKey();
                var clove = new TunnelLayer.I2NP.Data.GarlicClove( new GarlicCloveDeliveryLocal( dlm ) );
                var garlic = new Garlic(
                    new I2PDate( DateTime.UtcNow.AddSeconds( 20 ) ),
                    clove );

                var garlicMsg = Garlic.EgEncryptGarlic(
                    garlic,
                    ri.Identity.PublicKey,
                    sessionkey,
                    new List<I2PSessionTag>() );

                Logging.LogDebug( $"IdentResolver: ElGamal garlic-wrapped DLM for {ident.Id32Short} to ff {ffHash.Id32Short}" );
                return garlicMsg;
            }
            catch ( Exception ex )
            {
                Logging.LogWarning( $"IdentResolver: ElGamal garlic wrap failed for ff {ffHash.Id32Short}: {ex.Message}" );
                return null;
            }
        }

        /*
         Exploration

         Exploration is a special form of netdb lookup, where a router attempts to learn about new routers. 
         It does this by sending a floodfill router a I2NP DatabaseLookupMessage, looking for a random key. 
         As this lookup will fail, the floodfill would normally respond with a I2NP DatabaseSearchReplyMessage 
         containing hashes of floodfill routers close to the key. This would not be helpful, as the requesting 
         router probably already knows those floodfills, and it would be impractical to add ALL floodfill 
         routers to the "don't include" field of the lookup. For an exploration query, the requesting router 
         adds a router hash of all zeros to the "don't include" field of the DatabaseLookupMessage. 
         
         The floodfill will then respond only with non-floodfill routers close to the requested key.
         
         https://geti2p.net/en/docs/how/network-database
         * 
            11  => exploration lookup, return DatabaseSearchReplyMessage
                    containing non-floodfill routers only (replaces an
                    excludedPeer of all zeroes)   
         https://geti2p.net/spec/i2np#databaselookup
         */
        private void ExplorationRouterLookup()
        {
            // Adapt exploration frequency based on router count (matches Java I2P StartExplorersJob)
            var routerCount = NetDb.Inst.RouterCount;
            if ( routerCount > 1000 )
            {
                ExploreNewRouters.Frequency = TickSpan.Minutes( 3 );
            }
            else if ( routerCount > 500 )
            {
                ExploreNewRouters.Frequency = TickSpan.Seconds( 45 );
            }
            else
            {
                // Aggressive exploration when < 500 routers
                ExploreNewRouters.Frequency = TickSpan.Seconds( 15 );
            }

            // Get an inbound tunnel for receiving replies.
            // For firewalled routers, MUST use a real (non-zero-hop) tunnel because
            // floodfills can't connect directly to us to deliver the reply.
            InboundTunnel replytunnel;
            if ( RouterContext.Inst.IsFirewalled )
            {
                // Get only real (non-zero-hop) inbound tunnels
                var realTunnels = TunnelProvider.Inst.GetInboundTunnels()
                    .Where( t => t is not ZeroHopTunnel )
                    .ToArray();

                if ( realTunnels.Length == 0 )
                {
                    Logging.LogDebug( "IdentResolver: Exploration skipped - no real inbound tunnels (firewalled)" );
                    return;
                }

                replytunnel = realTunnels[BufUtils.RandomInt( realTunnels.Length )];
            }
            else
            {
                replytunnel = TunnelProvider.Inst.GetEstablishedInboundTunnel( TunnelPoolSelection.RequireExploratory )
                    ?? TunnelProvider.Inst.GetEstablishedInboundTunnel( TunnelPoolSelection.AllowExploratory );
            }

            if ( replytunnel == null )
            {
                Logging.LogDebug( "IdentResolver: Exploration skipped - no inbound tunnels" );
                return;
            }

            // For firewalled/hidden routers: prefer direct transport with reply tunnel.
            // This is more reliable than outbound tunnel delivery because:
            // Always prefer established exploratory tunnels for anonymity and reliability.
            // Firewalled routers MUST use tunnels for reliable NetDb updates, unless no tunnels 
            // are established yet (bootstrap).
            var outtunnel = TunnelProvider.Inst.GetEstablishedOutboundTunnel( TunnelPoolSelection.RequireExploratory )
                ?? TunnelProvider.Inst.GetEstablishedOutboundTunnel( TunnelPoolSelection.AllowExploratory );

            bool useTunnels = outtunnel != null && replytunnel != null;

            // Send exploration queries to multiple floodfills when our NetDb is small
            int queriesPerRound = routerCount < 200 ? 3 : routerCount < 500 ? 2 : 1;

            // For direct transport mode: STRONGLY prefer floodfills we're already connected to.
            // New connections fail ~85% of the time, so sending to unconnected floodfills usually
            // means the query never reaches the floodfill.
            var connectedRouters = TransportProvider.Inst.GetConnectedRouterHashes().ToHashSet();
            var allFloodfills = NetDb.Inst.GetClosestFloodfill( new I2PIdentHash( true ), 50, null );
            var connectedFloodfills = allFloodfills.Where( ff => connectedRouters.Contains( ff ) ).ToArray();

            for ( int q = 0; q < queriesPerRound; q++ )
            {
                I2PIdentHash ident = new I2PIdentHash( true );

                // Select floodfill: prefer connected, fall back to any
                I2PIdentHash[] ff;
                if ( RouterContext.Inst.IsFirewalled && !useTunnels )
                {
                    // Firewalled and NO tunnels: MUST use a connected floodfill
                    if ( connectedFloodfills.Length == 0 )
                    {
                        Logging.LogDebug( "IdentResolver: Exploration deferred - no connected floodfills" );
                        return;
                    }
                    var chosen = connectedFloodfills[BufUtils.RandomInt( connectedFloodfills.Length )];
                    ff = new[] { chosen };
                }
                else
                {
                    // Through tunnels or reachable: query multiple floodfills (standard)
                    ff = BufUtils.Shuffle( NetDb.Inst.GetClosestFloodfill( ident, 10, null ) )
                            .Take( DatabaseLookupSelectFloodfillCountRi )
                            .ToArray();
                }

                foreach ( var oneff in ff )
                {
                    DatabaseLookupMessage msg;
                    string mode;

                    if ( useTunnels )
                    {
                        // Through tunnels: specify reply tunnel
                        msg = new DatabaseLookupMessage(
                            ident,
                            replytunnel.Destination,
                            replytunnel.GatewayTunnelId,
                            DatabaseLookupMessage.LookupTypes.Exploration,
                            new I2PIdentHash[] { new( false ) } );
                        mode = "tunnels";
                    }
                    else if ( connectedRouters.Contains( oneff ) )
                    {
                        // Direct to connected floodfill: specify our IdentHash as "from"
                        // so the floodfill responds on the SAME NTCP2 connection.
                        // This is the most reliable method for firewalled routers.
                        msg = new DatabaseLookupMessage(
                            ident,
                            RouterContext.Inst.MyRouterIdentity.IdentHash,
                            DatabaseLookupMessage.LookupTypes.Exploration,
                            new I2PIdentHash[] { new( false ) } );
                        mode = "direct-connected";
                    }
                    else if ( replytunnel != null )
                    {
                        // Direct to unconnected floodfill: specify reply tunnel
                        msg = new DatabaseLookupMessage(
                            ident,
                            replytunnel.Destination,
                            replytunnel.GatewayTunnelId,
                            DatabaseLookupMessage.LookupTypes.Exploration,
                            new I2PIdentHash[] { new( false ) } );
                        mode = "direct+replyTunnel";
                    }
                    else
                    {
                        // Fallback: direct with our IdentHash (only works if not firewalled)
                        msg = new DatabaseLookupMessage(
                            ident,
                            RouterContext.Inst.MyRouterIdentity.IdentHash,
                            DatabaseLookupMessage.LookupTypes.Exploration,
                            new I2PIdentHash[] { new( false ) } );
                        mode = "direct";
                    }

                    Logging.LogDebug( $"IdentResolver: Exploration {ident.Id32Short} -> ff {oneff.Id32Short} ({mode})" );

                    try
                    {
                        if ( useTunnels )
                        {
                            outtunnel.Send( new TunnelMessageRouter( msg, oneff ) );
                        }
                        else
                        {
                            TransportProvider.Send( oneff, msg );
                        }
                    }
                    catch ( Exception ex )
                    {
                        Logging.Log( ex );
                    }
                }
            }
        }

        private void CheckTimeouts()
        {
            var retry = OutstandingQueries.Where( i =>
                    i.Value != null
                    && i.Value.Start.DeltaToNow > i.Value.DatabaseLookupWaitTime )
                .Select( i => i.Value )
                .ToArray();

            foreach( var info in retry )
            {
                // Collect router performance
                var noresponse = info.FloodfillResponses
                        .Where( r => r.Value.Response == ReceivedFloodfillResponses.NoResponse );

                // Give all the credit
                foreach( var one in noresponse )
                {
                    var from = one.Key;
                    
                    if ( info.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet )
                    {
                        NetDb.Inst.Statistics.IdentResolveLsTimeout( from );
                    }
                    else
                    {
                        NetDb.Inst.Statistics.IdentResolveRiTimeout( from );
                    }

                    var update = new FloodfillResponse()
                    {
                        Floodfill = from,
                        Response = ReceivedFloodfillResponses.Timeout
                    };
                    info.FloodfillResponses[from] = update;
                    lock ( info.Attempts )
                    {
                        if ( info.Attempts.Any() ) info.Attempts.Last().FloodfillResponses[from] = update;
                    }
                }
            }

            SendRetries( retry );
        }

        protected void SendRetries( IEnumerable<IdentUpdateRequestInfo> retry )
        {
            foreach ( var one in retry )
            {
                var isleaseset = one.LookupType == DatabaseLookupMessage.LookupTypes.LeaseSet;

                if ( one.Retries >= ( isleaseset ? DatabaseLookupRetriesLs : DatabaseLookupRetriesRi ) )
                {
                    OutstandingQueries.TryRemove( one.LookupIdent, out _ );
                    FinishedLookups[one.LookupIdent] = one;

                    Logging.Log( string.Format( "IdentResolver: Lookup of {0} {1} failed with timeout.",
                        ( isleaseset ? "LeaseSet" : "RouterInfo" ), 
                        one.LookupIdent.Id32Short ) );

                    if ( LookupFailure != null ) ThreadPool.QueueUserWorkItem( a => LookupFailure( one.LookupIdent ) );
                    if ( LookupFailureEx != null ) ThreadPool.QueueUserWorkItem( a => LookupFailureEx( one.LookupIdent, one ) );

                    continue;
                }

                ++one.Retries;
                one.Start.SetNow();

#if LOG_ALL_IDENT_LOOKUPS
                Logging.Log( string.Format( "IdentResolver: Lookup of {0} {1} failed with timeout Retry {2}.",
                    ( isleaseset ? "LeaseSet" : "RouterInfo" ), one.LookupIdent.Id32Short, one.Retries ) );
#endif
                if ( isleaseset )
                {
                    SendLsDatabaseLookup( one.LookupIdent, one );
                }
                else
                {
                    SendRiDatabaseLookup( one.LookupIdent, one );
                }
            }
        }
    }
}
