using System.Diagnostics;
using System.Security.Cryptography;

namespace Phrasia;

/// <summary>Argon2id parameters stored in the vault header (formats v5/v6/v7).</summary>
public sealed record Argon2Params(int MemoryKiB, int Passes, int Lanes)
{
    /// <summary>Floor – never weaker than format v4 (RFC 9106, second recommended option).</summary>
    public static readonly Argon2Params Floor = new(64 * 1024, 3, 4);

    /// <summary>Upper bound on memory read from a file (a tampered file must not exhaust RAM). 1 GiB.</summary>
    public const int MaxMemoryKiB = 1024 * 1024;
    /// <summary>Upper bound on passes read from a file.</summary>
    public const int MaxPasses = 20;
    /// <summary>Upper bound on lanes read from a file.</summary>
    public const int MaxLanes = 16;

    /// <summary>True if the parameters are within safe, sane ranges (validates untrusted header values).</summary>
    public bool IsPlausible =>
        MemoryKiB >= Floor.MemoryKiB && MemoryKiB <= MaxMemoryKiB && MemoryKiB % 1024 == 0 &&
        Passes >= Floor.Passes && Passes <= MaxPasses &&
        Lanes >= 1 && Lanes <= MaxLanes && MemoryKiB >= 8 * Lanes;

    /// <summary>Human-readable description, e.g. "Argon2id 256 MiB, 3 passes, 8 lanes".</summary>
    public override string ToString() => $"Argon2id {MemoryKiB / 1024} MiB, {Passes} passes, {Lanes} lanes";
}

/// <summary>Result of a calibration run: chosen parameters, estimated unlock time, and a reason string.</summary>
public sealed record CalibrationResult(Argon2Params Params, double EstimatedMs, string Reason);

/// <summary>
/// Tunes Argon2id to this computer: as much memory as RAM allows, lanes by core count, and enough passes
/// so unlocking takes about <see cref="TargetMs"/> (default 1 s, up to 10 s). Never goes below
/// <see cref="Argon2Params.Floor"/>.
/// </summary>
public static class Argon2Calibrator
{
    /// <summary>Default target unlock time in milliseconds.</summary>
    public const double DefaultTargetMs = 1000;
    /// <summary>Minimum target (shorter is disallowed – it would only weaken below the floor).</summary>
    public const double MinTargetMs = 1000;
    /// <summary>Maximum target unlock time in milliseconds.</summary>
    public const double MaxTargetMs = 10000;
    /// <summary>Target choices offered in the UI (seconds).</summary>
    public static readonly int[] TargetChoicesSeconds = { 1, 2, 3, 5, 10 };

    private static readonly int[] MemoryTiersMiB = { 1024, 512, 256, 128, 64 };
    private const int MaxCalibratedPasses = Argon2Params.MaxPasses;

    private static double _targetMs = DefaultTargetMs;

    /// <summary>Target unlock time in ms (clamped to 1–10 s). Used by create, upgrade, change-password and tune.</summary>
    public static double TargetMs
    {
        get { lock (Lock) return _targetMs; }
        set
        {
            var v = Math.Clamp(double.IsFinite(value) ? value : DefaultTargetMs, MinTargetMs, MaxTargetMs);
            lock (Lock)
            {
                if (v == _targetMs) return;
                _targetMs = v;
                _cached = null; // different target → re-measure
            }
        }
    }

    /// <summary>Timing function – real Argon2id in the app, a stub in tests.</summary>
    internal static Func<Argon2Params, double> Measure = MeasureArgon2;

    /// <summary>Available physical memory – overridable in tests.</summary>
    internal static Func<long> AvailableMemoryBytes = () => GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
    /// <summary>Logical processor count – overridable in tests.</summary>
    internal static Func<int> ProcessorCount = () => Environment.ProcessorCount;

    private static CalibrationResult? _cached;
    private static readonly object Lock = new();

    /// <summary>Returns the cached calibration for the current target; <paramref name="force"/> re-measures.</summary>
    public static CalibrationResult Calibrate(bool force = false)
    {
        lock (Lock)
        {
            if (_cached is not null && !force) return _cached;
            _cached = RunCalibration(_targetMs);
            return _cached;
        }
    }

    /// <summary>Picks memory/lanes/passes so a measured Argon2id run lands near <paramref name="targetMs"/>.</summary>
    private static CalibrationResult RunCalibration(double targetMs)
    {
        var floor = Argon2Params.Floor;
        int lanes = Math.Clamp(ProcessorCount(), floor.Lanes, 8);

        // memory: at most 1/16 of available RAM, so unlocking doesn't strain even a weaker machine
        long available = Math.Max(0, AvailableMemoryBytes());
        // 1 GiB only for a longer target time – at 1 s it wouldn't fit the budget anyway
        int memoryMiB = MemoryTiersMiB
            .Where(m => m < 1024 || targetMs >= 2000)
            .FirstOrDefault(m => (long)m * 1024 * 1024 * 16 <= available, 64);

        var reason = $"target {targetMs / 1000:0.#} s, {ProcessorCount()} CPU threads, " +
                     $"{available / (1024 * 1024 * 1024.0):F1} GiB RAM available";

        // measure at 3 passes; if too slow, halve memory (never below the floor)
        double ms;
        while (true)
        {
            ms = Measure(new Argon2Params(memoryMiB * 1024, floor.Passes, lanes));
            if (ms <= targetMs * 1.5 || memoryMiB <= 64) break;
            memoryMiB /= 2;
        }

        // passes: step up toward the target (time grows linearly with passes)
        double perPass = ms / floor.Passes;
        int passes = perPass <= 0 ? floor.Passes
            : Math.Clamp((int)Math.Floor(targetMs / perPass), floor.Passes, MaxCalibratedPasses);

        var result = new Argon2Params(memoryMiB * 1024, passes, lanes);
        return new CalibrationResult(result, perPass * passes, reason);
    }

    /// <summary>
    /// Hardest settings this computer can bear: as much memory as RAM allows (up to 1 GiB), lanes up to the
    /// core count (max 16) and the maximum passes. Ignores the target time – for very fast PCs where even
    /// 10 s is "too little". Unlocking then takes longer.
    /// </summary>
    public static CalibrationResult CalibrateMaximum()
    {
        var floor = Argon2Params.Floor;
        int lanes = Math.Clamp(ProcessorCount(), floor.Lanes, Argon2Params.MaxLanes);

        long available = Math.Max(0, AvailableMemoryBytes());
        // more aggressive than normal calibration: up to 1/4 of available RAM, capped at 1 GiB (MaxMemoryKiB)
        int maxTierMiB = Argon2Params.MaxMemoryKiB / 1024;
        int memoryMiB = MemoryTiersMiB
            .Where(m => m <= maxTierMiB)
            .FirstOrDefault(m => (long)m * 1024 * 1024 * 4 <= available, 64);

        int passes = Argon2Params.MaxPasses;
        var p = new Argon2Params(memoryMiB * 1024, passes, lanes);
        double ms = Measure(p);
        var reason = $"maximum for this PC: {ProcessorCount()} CPU threads, " +
                     $"{available / (1024 * 1024 * 1024.0):F1} GiB RAM available";
        return new CalibrationResult(p, ms, reason);
    }

    /// <summary>Measures the wall-clock time of one real Argon2id derivation with the given parameters.</summary>
    private static double MeasureArgon2(Argon2Params p)
    {
        var salt = RandomNumberGenerator.GetBytes(32);
        var sw = Stopwatch.StartNew();
        var r = Argon2Kdf.Derive("calibration", salt, p.MemoryKiB, p.Passes, p.Lanes, 32);
        sw.Stop();
        CryptographicOperations.ZeroMemory(r);
        return sw.Elapsed.TotalMilliseconds;
    }
}
