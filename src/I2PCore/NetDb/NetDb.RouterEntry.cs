using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore;

public partial class NetDb
{
    protected class RouterEntry
    {
        private RouterStatistics CachedStatisticsField;

        private TickCounter ScoreAge;

        public RouterEntry(I2PRouterInfo info, RouterInfoMeta meta)
        {
            Router = info;
            Meta = meta;
        }

        public I2PRouterInfo Router { get; protected set; }
        public RouterInfoMeta Meta { get; protected set; }

        public RouterStatistics CachedStatistics
        {
            get
            {
                if (ScoreAge is null || ScoreAge.DeltaToNow > TickSpan.Minutes(5))
                {
                    ScoreAge = TickCounter.Now;
                    CachedStatisticsField = Inst.Statistics[Router.Identity.IdentHash];
                }

                return CachedStatisticsField;
            }
        }

        public bool IsFloodfill => Router.Options["caps"].IndexOf('f') >= 0;
    }
}