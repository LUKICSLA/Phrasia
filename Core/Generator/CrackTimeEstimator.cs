using System.Globalization;
using System.Numerics;

namespace Phrasia;

/// <summary>
/// Rough "how long would it take to crack" estimates for a password of a given strength (bits), in several attack
/// scenarios. Average time = half of all 2^bits possibilities divided by the guessing rate. The bits come from
/// <see cref="PassphraseGenerator.EstimateEntropyBits"/>, which already assumes the attacker knows exactly how the
/// password was generated (word list and settings) – so these are worst-case, not "dictionary luck" numbers.
/// </summary>
internal static class CrackTimeEstimator
{
    /// <summary>One attack scenario: name, short explanation and guesses per second.</summary>
    public sealed record Scenario(string Name, string Description, double GuessesPerSecond);

    /// <summary>Estimate for one scenario: average time in seconds (may be +∞ for huge values).</summary>
    public sealed record Estimate(Scenario Scenario, double Seconds);

    /// <summary>Scenarios from the friendliest to the worst case for the defender.</summary>
    public static readonly IReadOnlyList<Scenario> Scenarios =
    [
        new("Online, rate-limited", "Guessing on a website or app that blocks or slows repeated attempts", 100.0 / 3600),
        new("Online, no limit", "Guessing on a poorly protected login with no rate limiting", 10),
        new("Leaked database, slow hash", "Offline, password stored with bcrypt, scrypt or Argon2 (good practice)", 1e4),
        new("Leaked database, fast hash", "Offline, password stored with a fast hash (MD5, SHA-1, NTLM) on a GPU rig", 1e10),
        new("Worst case: GPU farm", "Offline, fast hash, a large cluster of GPUs – the basis of the headline estimate", 1e12)
    ];

    /// <summary>The scenario used for the one-line estimate shown under the generated password.</summary>
    public static Scenario WorstCase => Scenarios[^1];

    /// <summary>Average seconds to find a password of <paramref name="bits"/> at <paramref name="guessesPerSecond"/>.</summary>
    public static double AverageSeconds(double bits, double guessesPerSecond) =>
        bits <= 0 ? 0 : Math.Pow(2, bits - 1) / guessesPerSecond;

    /// <summary>Estimates for every scenario.</summary>
    public static IReadOnlyList<Estimate> EstimateAll(double bits) =>
        Scenarios.Select(s => new Estimate(s, AverageSeconds(bits, s.GuessesPerSecond))).ToList();

    private const double Minute = 60, Hour = 3600, Day = 86400, Year = 365.25 * Day;

    /// <summary>Age of the universe in years (≈ 13.8 billion).</summary>
    public const double UniverseAgeYears = 1.38e10;

    /// <summary>Largest number of years written out in full (beyond it: "practically forever").</summary>
    private const double MaxWrittenYears = 1e60;

    /// <summary>Human-readable duration: "instantly", "3 hours", "2 million years", "20 000 000 000 000 000 years".</summary>
    public static string FormatDuration(double seconds)
    {
        var c = CultureInfo.InvariantCulture;
        if (double.IsNaN(seconds) || seconds < 1) return "instantly";
        if (seconds < Minute) return Plural(seconds, "second");
        if (seconds < Hour) return Plural(seconds / Minute, "minute");
        if (seconds < Day) return Plural(seconds / Hour, "hour");
        if (seconds < Year) return Plural(seconds / Day, "day");

        double years = seconds / Year;
        if (years < 1000) return Plural(years, "year");
        if (years < 1e6) return Round(years / 1e3) + " thousand years";
        if (years < 1e9) return Round(years / 1e6) + " million years";
        if (years < 1e12) return Round(years / 1e9) + " billion years";
        if (years < 1e15) return Round(years / 1e12) + " trillion years";
        return years > MaxWrittenYears ? "practically forever" : WholeNumber(years) + " years";

        static string Round(double v) => (v < 10 ? Math.Round(v, 1) : Math.Round(v)).ToString("0.#", CultureInfo.InvariantCulture);
        static string Plural(double v, string unit)
        {
            double r = Math.Round(v);
            return r.ToString("0", CultureInfo.InvariantCulture) + " " + unit + (r == 1 ? "" : "s");
        }
    }

    /// <summary>A huge number written out in full, rounded to 2 significant digits and grouped by spaces
    /// ("19 000 000 000 000 000"); spaces also let a long number wrap.</summary>
    public static string WholeNumber(double value)
    {
        int exponent = (int)Math.Floor(Math.Log10(value));
        double mantissa = Math.Round(value / Math.Pow(10, exponent - 1));   // 10..100
        if (mantissa >= 100) { mantissa /= 10; exponent++; }
        var number = new BigInteger(mantissa) * BigInteger.Pow(10, exponent - 1);
        return number.ToString("N0", CultureInfo.InvariantCulture).Replace(",", " ");
    }

    /// <summary>Human-readable guessing rate: "100 per hour", "10 per second", "1 trillion per second".</summary>
    public static string FormatRate(double guessesPerSecond)
    {
        var c = CultureInfo.InvariantCulture;
        if (guessesPerSecond < 1) return (guessesPerSecond * Hour).ToString("0", c) + " per hour";
        return guessesPerSecond switch
        {
            >= 1e12 => (guessesPerSecond / 1e12).ToString("0.#", c) + " trillion / s",
            >= 1e9 => (guessesPerSecond / 1e9).ToString("0.#", c) + " billion / s",
            >= 1e6 => (guessesPerSecond / 1e6).ToString("0.#", c) + " million / s",
            >= 1e3 => guessesPerSecond.ToString("N0", c) + " / s",
            _ => guessesPerSecond.ToString("0", c) + " / s"
        };
    }

    /// <summary>Severity 0–3 for coloring: 0 = under a day, 1 = under a year, 2 = under 1000 years, 3 = longer.</summary>
    public static int Severity(double seconds) => seconds switch
    {
        < Day => 0,
        < Year => 1,
        < 1000 * Year => 2,
        _ => 3
    };
}
