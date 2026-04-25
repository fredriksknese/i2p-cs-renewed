using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("I2PCore.NTests")]

namespace I2PCore.Utils;

public class RouletteSelection<T, TK>
{
    public readonly float AbsDevFit;

    public readonly float AverageFit;

    public readonly int Count;

    public readonly double Elitism;
    public readonly int IncludeTop;
    public readonly float MaxFit;

    public readonly float MinFit;
    public readonly float StdDevFit;
    public readonly double TotalSpaceSum;

    public readonly IEnumerable<RouletteSpace<TK>> Wheel;

    public RouletteSelection(
        IEnumerable<T> infos,
        Func<T, TK> selkey,
        Func<TK, float> selfit,
        int maxinfos,
        double elitism)
    {
        IncludeTop = maxinfos;
        Elitism = elitism;

        TotalSpaceSum = 0;

        Wheel = infos.Select(inf => new RouletteSpace<TK>(selkey(inf), selfit));

        if (!Wheel.Any())
        {
            MinFit = 0f;
            MaxFit = 0f;
            AverageFit = 0f;
            return;
        }

        // Makes OrderByDescending makes GetWeightedRandom faster
        Wheel = Wheel
            .OrderByDescending(rs => rs.Fit)
            .ToArray();
        Count = Wheel.Count();

        if (Count > IncludeTop)
        {
            Wheel = Wheel
                .Take(IncludeTop)
                .ToArray();
            Count = IncludeTop;
        }

        var fits = Wheel.Select(sp => sp.Fit);
        MinFit = fits.Min();
        MaxFit = fits.Max();
        AverageFit = fits.Average();
        AbsDevFit = fits.AbsDev();
        StdDevFit = fits.StdDev();

        var i = 0;

        foreach (var one in Wheel)
        {
            one.Space = Math.Pow(Elitism, Count - ++i);
            TotalSpaceSum += one.Space;
        }
    }

    public TK GetWeightedRandom(ICollection<TK> exclude)
    {
        lock (Wheel)
        {
            var pos = 0.0;

            var subset = Wheel;
            var subsetsum = TotalSpaceSum;

            if (exclude?.Any() ?? false)
            {
                subset = Wheel.Where(one => !exclude.Contains(one.Id));
                subsetsum = subset.Sum(one => one.Space);
            }

            var target = BufUtils.RandomDouble(subsetsum);

            foreach (var one in subset)
            {
                pos += one.Space;
                if (pos >= target)
                    // Roulette selection is too noisy for normal debug output
                    // Logging.LogDebugData( $"Roulette: {one.Id}" );
                    return one.Id;
            }

            if (subset.Any()) return subset.Random().Id;

            return Wheel.Random().Id;
        }
    }

    public class RouletteSpace<TK2>
    {
        public readonly float Fit;
        public readonly TK2 Id;
        public double Space;

        public RouletteSpace(TK2 id, Func<TK2, float> selfit)
        {
            Id = id;
            Fit = selfit(Id);
        }

        public override string ToString()
        {
            return $"RouletteSpace: Fit {Fit:0.00}, Space {Space:0.00}: {Id}";
        }
    }
}