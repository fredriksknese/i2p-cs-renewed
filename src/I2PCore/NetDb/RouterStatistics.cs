using System;
using System.Text;
using I2PCore.Data;
using I2PCore.Utils;
using System.Globalization;
using I2PCore.TunnelLayer;

namespace I2PCore
{
    public class RouterStatistics: I2PType
    {
        public readonly I2PIdentHash Id;
        public I2PDate Created = I2PDate.Now;
        public I2PDate LastSeen = I2PDate.Now;

        public long SuccessfulConnects;
        public long FailedConnects;
        public long InformationFaulty;
        public long SlowHandshakeConnect;

        public long IdentResolveRiTimeout;
        public long IdentResolveLsTimeout;
        public long IdentResolveSuccess;
        public long IdentResolveReply;

        public long TunnelBuildTimeout;
        public long FloodfillUpdateTimeout;
        public long FloodfillUpdateSuccess;

        public long SuccessfulTunnelMember;
        public long DeclinedTunnelMember;
        public long SuccessfulTunnelTest;
        public long FailedTunnelTest;
        public long TunnelBuildTimeMsPerHop;

        public float MaxBandwidthSeen;

        public bool IsFirewalled;

        public int StoreIx;
        public bool Deleted = false;
        public bool Updated = false;

        public RouterStatistics( I2PIdentHash id )
        {
            Id = id;
            UpdateScore();
        }

        private const float MaxScore = 30f;
        private const float MedTargetPeriods = 30f;

        private float DiminishingReturns( float val )
        {
            return (float)( MaxScore * Math.Tanh( val / MedTargetPeriods ) );
        }

        private float CachedScore;
        public float ConnectScore { get; private set; }
        public float TunnelMemberScore { get; private set; }
        public float FloodfillScore { get; private set; }
        public float TunnelTestScore { get; private set; }
        public float IdentResolveScore { get; private set; }
        public float FirewallPenalty { get; private set; }
        public float BandwidthBonus { get; private set; }
        public float BuildTimePenalty { get; private set; }
        public float InfoFaultyPenalty { get; private set; }

        internal void UpdateScore()
        {
            ConnectScore = DiminishingReturns( SuccessfulConnects * 1.0f - FailedConnects * 5.00f 
                - SlowHandshakeConnect * 0.5f );
            
            TunnelMemberScore = DiminishingReturns( SuccessfulTunnelMember * 3.0f - DeclinedTunnelMember * 0.5f 
                - TunnelBuildTimeout * 1.0f );
            
            FloodfillScore = DiminishingReturns( FloodfillUpdateSuccess * 1.0f - FloodfillUpdateTimeout * 3.0f );
            
            TunnelTestScore = DiminishingReturns( SuccessfulTunnelTest * 0.3f - FailedTunnelTest * 0.1f );
            
            IdentResolveScore = DiminishingReturns( IdentResolveSuccess + IdentResolveReply * 0.3f - IdentResolveRiTimeout - IdentResolveLsTimeout );
            
            FirewallPenalty = IsFirewalled ? MaxScore / 4f : 0f;

            BandwidthBonus = MaxScore * ( MaxBandwidthSeen / RoutersStatistics.BandwidthMax );

            if ( TunnelBuildTimeMsPerHop == 0 )
            {
                // If we've never successfully built a tunnel with it, 
                // but we've tried and it either declined or timed out, 
                // then it's as bad as a slow router.
                if ( SuccessfulTunnelMember + DeclinedTunnelMember + TunnelBuildTimeout > 0 )
                {
                    BuildTimePenalty = 50f;
                }
                else
                {
                    // If we've never even tried it, don't penalize it!
                    BuildTimePenalty = 0f;
                }
            }
            else
            {
                BuildTimePenalty = TunnelBuildTimeMsPerHop / 100f;
            }

            InfoFaultyPenalty = 3f * DiminishingReturns( InformationFaulty * 10f );

            CachedScore = ConnectScore + TunnelMemberScore + FloodfillScore + TunnelTestScore + IdentResolveScore
                    - FirewallPenalty + BandwidthBonus - BuildTimePenalty - InfoFaultyPenalty;
        }

        public float Score
        {
            get
            {
                return CachedScore;
            }
        }

        private long TryGet( I2PMapping map, string ix )
        {
            try
            {
                return long.Parse( map[ix] );
            }
            catch ( Exception )
            {
                return 0;
            }
        }

        private long TryGet( I2PMapping map, string ix, long def )
        {
            try
            {
                return long.Parse( map[ix] );
            }
            catch ( Exception )
            {
                return def;
            }
        }

        private float TryGetFloat( I2PMapping map, string ix )
        {
            try
            {
                return float.Parse( map[ix], CultureInfo.InvariantCulture );
            }
            catch ( Exception )
            {
                return 0f;
            }
        }

        public RouterStatistics( BufRef buf )
        {
            Id = new I2PIdentHash( buf );
            LastSeen = new I2PDate( buf );
            Created = new I2PDate( buf );
            buf.Seek( 52 ); // Reserved space

            var mapping = new I2PMapping( buf );

            SuccessfulConnects = TryGet( mapping, "SuccessfulConnects" );
            FailedConnects = TryGet( mapping, "FailedConnects" );
            InformationFaulty = TryGet( mapping, "InformationFaulty" );
            SuccessfulTunnelMember = TryGet( mapping, "SuccessfulTunnelMember" );
            DeclinedTunnelMember = TryGet( mapping, "DeclinedTunnelMember" );
            SlowHandshakeConnect = TryGet( mapping, "SlowHandshakeConnect" );
            MaxBandwidthSeen = TryGetFloat( mapping, "MaxBandwidthSeen" );
            TunnelBuildTimeout = TryGet( mapping, "TunnelBuildTimeout" );
            TunnelBuildTimeMsPerHop = TryGet( mapping, "TunnelBuildTimeMsPerHop", 0 );
            FloodfillUpdateTimeout = TryGet( mapping, "FloodfillUpdateTimeout" );
            FloodfillUpdateSuccess = TryGet( mapping, "FloodfillUpdateSuccess" );
            SuccessfulTunnelTest = TryGet( mapping, "SuccessfulTunnelTest" );
            FailedTunnelTest = TryGet( mapping, "FailedTunnelTest" );
            IsFirewalled = TryGet( mapping, "IsFirewalled" ) != 0;
            IdentResolveRiTimeout = TryGet( mapping, "IdentResolveRITimeout" );
            IdentResolveLsTimeout = TryGet( mapping, "IdentResolveLSTimeout" );
            IdentResolveSuccess = TryGet( mapping, "IdentResolveSuccess" );
            IdentResolveReply = TryGet( mapping, "IdentResolveReply" );

            UpdateScore();
        }

        private I2PMapping CreateMapping()
        {
            var mapping = new I2PMapping();

            mapping["SuccessfulConnects"] = SuccessfulConnects.ToString();
            mapping["FailedConnects"] = FailedConnects.ToString();
            mapping["InformationFaulty"] = InformationFaulty.ToString();
            mapping["SuccessfulTunnelMember"] = SuccessfulTunnelMember.ToString();
            mapping["DeclinedTunnelMember"] = DeclinedTunnelMember.ToString();
            mapping["SlowHandshakeConnect"] = SlowHandshakeConnect.ToString();
            mapping["MaxBandwidthSeen"] = MaxBandwidthSeen.ToString( CultureInfo.InvariantCulture );
            mapping["TunnelBuildTimeout"] = TunnelBuildTimeout.ToString();
            mapping["TunnelBuildTimeMsPerHop"] = TunnelBuildTimeMsPerHop.ToString();
            mapping["FloodfillUpdateTimeout"] = FloodfillUpdateTimeout.ToString();
            mapping["FloodfillUpdateSuccess"] = FloodfillUpdateSuccess.ToString();
            mapping["SuccessfulTunnelTest"] = SuccessfulTunnelTest.ToString();
            mapping["FailedTunnelTest"] = FailedTunnelTest.ToString();
            mapping["IsFirewalled"] = IsFirewalled ? "1" : "0";
            mapping["IdentResolveRITimeout"] = IdentResolveRiTimeout.ToString();
            mapping["IdentResolveLSTimeout"] = IdentResolveLsTimeout.ToString();
            mapping["IdentResolveSuccess"] = IdentResolveSuccess.ToString();
            mapping["IdentResolveReply"] = IdentResolveReply.ToString();

            return mapping;
        }

        public void Write( BufRefStream dest )
        {
            Id.Write( dest );
            LastSeen.Write( dest );
            Created.Write( dest );
            dest.Write( BufUtils.RandomBytes( 52 ) ); // Reserved space

            var mapping = CreateMapping();

            mapping.Write( dest );
        }

        public override string ToString()
        {
            StringBuilder result = new StringBuilder();
            var mapping = CreateMapping();
            result.Append( "DestinationStatistics: " );
            result.Append( mapping.ToString() );
            return result.ToString();
        }
    }
}
