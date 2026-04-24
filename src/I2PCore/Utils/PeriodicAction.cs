using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace I2PCore.Utils
{
    public class PeriodicAction
    {
        public delegate void PerformAction();

        private TickSpan MFrequency;
        private TickSpan MOriginalFrequency = null;

        public TickSpan Frequency 
        { 
            get 
            { 
                return MFrequency;
            } 
            set 
            {
                MOriginalFrequency = value;
                MFrequency = value;
            } 
        }

        public TickCounter LastAction { get; protected set; }
        public TickSpan TimeToAction
        {
            get => ( LastAction + MFrequency ).DeltaToNow;
            set
            {
                if ( MOriginalFrequency is null )
                {
                    MOriginalFrequency = MFrequency;
                }

                LastAction = TickCounter.Now;
                MFrequency = value;
            }
        }

        public bool Autotrigger { get; protected set; }

        public PeriodicAction( TickSpan freq, bool hastimedout = false )
        {
            MFrequency = freq;
            Autotrigger = hastimedout;
            LastAction = TickCounter.Now;
        }

        public void Reset()
        {
            LastAction = TickCounter.Now;
        }

        public void Start()
        {
            if ( LastAction == null ) 
                LastAction = new TickCounter();
            else
                LastAction.SetNow();
        }

        public void Stop()
        {
            LastAction = null;
        }

        public void Do( PerformAction action )
        {
            if ( LastAction == null ) return;

            if ( Autotrigger || LastAction.DeltaToNow > MFrequency )
            {
                LastAction.SetNow();
                Autotrigger = false;
                if ( MOriginalFrequency != null )
                {
                    MFrequency = MOriginalFrequency;
                    MOriginalFrequency = null;
                }

                action();
            }
        }
    }
}
