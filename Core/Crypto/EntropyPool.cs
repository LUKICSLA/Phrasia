using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Phrasia;

/// <summary>
/// Randomness for salts and secrets, VeraCrypt-style: output of the Windows CSPRNG mixed (HKDF-SHA512) with a pool of
/// user entropy collected from mouse movement (position + high-resolution time). The result is never weaker than the OS
/// generator alone; if the OS generator were weak or compromised, the user's entropy still protects it. The pool is
/// ratcheted after every extraction, so earlier outputs cannot be reconstructed from its current state.
/// Note: salts are public by design (stored in the vault file) – for them this is defense in depth, not extra secrecy.
/// </summary>
internal static class EntropyPool
{
    /// <summary>User entropy (bits, conservatively credited) required before a critical operation – twice the pool's
    /// 256-bit security level, so a long, irregular movement is needed.</summary>
    public const int TargetBits = 512;

    /// <summary>Minimum pointer travel (pixels, on either axis) since the last credited sample for a new sample to be credited.
    /// Tiny jitters and slow creeping are still mixed into the pool, but only real movement counts.</summary>
    public const int MinStepPixels = 4;

    private static readonly byte[] Info = "Phrasia entropy pool v1"u8.ToArray();
    private static readonly byte[] RatchetLabel = "Phrasia entropy pool ratchet"u8.ToArray();
    private static readonly object Gate = new();
    private static readonly byte[] Pool = new byte[64];
    private static long _extractions;
    private static int _credited;
    private static long _lastX = long.MinValue, _lastY = long.MinValue;

    /// <summary>Fills a buffer with random bytes (signature of the OS generator replacement used in tests).</summary>
    internal delegate void FillBytes(Span<byte> buffer);

    /// <summary>Test hook: replaces the OS generator. Never set by the app.</summary>
    internal static FillBytes? OsFillOverride;

    /// <summary>User entropy credited since the last critical operation (capped at <see cref="TargetBits"/>).</summary>
    public static int CreditedBits
    {
        get { lock (Gate) return Math.Min(_credited, TargetBits); }
    }

    /// <summary>True when enough fresh user entropy has been collected for the next critical operation.</summary>
    public static bool IsFresh => CreditedBits >= TargetBits;

    /// <summary>Mixes one mouse sample (screen position + high-resolution timestamps) into the pool. A sample at a new
    /// sample at least <see cref="MinStepPixels"/> away from the last credited one earns 1 bit – conservative, since timing jitter
    /// usually adds more; smaller moves and repeats are mixed in but not credited.</summary>
    public static void AddMouseSample(long x, long y)
    {
        Span<byte> sample = stackalloc byte[32];
        BinaryPrimitives.WriteInt64LittleEndian(sample, x);
        BinaryPrimitives.WriteInt64LittleEndian(sample[8..], y);
        BinaryPrimitives.WriteInt64LittleEndian(sample[16..], Stopwatch.GetTimestamp());
        BinaryPrimitives.WriteInt64LittleEndian(sample[24..], Environment.TickCount64);
        lock (Gate)
        {
            Mix(sample);
            if (_lastX == long.MinValue || Math.Abs(x - _lastX) >= MinStepPixels || Math.Abs(y - _lastY) >= MinStepPixels)
            {
                (_lastX, _lastY) = (x, y);
                if (_credited < int.MaxValue) _credited++;
            }
        }
        sample.Clear();
    }

    /// <summary>Marks the collected user entropy as used by a critical operation; the next one asks for fresh movement. The pool content itself is kept.</summary>
    public static void MarkConsumed()
    {
        lock (Gate) _credited = 0;
    }

    /// <summary>Returns <paramref name="count"/> random bytes (OS CSPRNG mixed with the user-entropy pool).</summary>
    public static byte[] GetBytes(int count)
    {
        var bytes = new byte[count];
        Fill(bytes);
        return bytes;
    }

    /// <summary>Fills <paramref name="output"/> with random bytes (OS CSPRNG mixed with the user-entropy pool).</summary>
    public static void Fill(Span<byte> output)
    {
        const int maxPerHkdf = 255 * 64; // HKDF-SHA512 output limit
        for (int offset = 0; offset < output.Length; offset += maxPerHkdf)
            FillChunk(output.Slice(offset, Math.Min(maxPerHkdf, output.Length - offset)));
    }

    /// <summary>Uniform random integer in [0, <paramref name="toExclusive"/>) from <see cref="Fill"/> (rejection sampling, no modulo bias).</summary>
    public static int GetInt32(int toExclusive)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(toExclusive);
        if (toExclusive == 1) return 0;
        ulong range = (ulong)toExclusive;
        ulong limit = (1UL << 32) - ((1UL << 32) % range);
        Span<byte> b = stackalloc byte[4];
        while (true)
        {
            Fill(b);
            uint v = BinaryPrimitives.ReadUInt32LittleEndian(b);
            if (v < limit) return (int)(v % range);
        }
    }

    /// <summary>One HKDF-SHA512 extraction: ikm = 64 fresh OS bytes ‖ pool snapshot, salt = extraction counter; then ratchets the pool.</summary>
    private static void FillChunk(Span<byte> output)
    {
        Span<byte> ikm = stackalloc byte[128];
        Span<byte> salt = stackalloc byte[8];
        if (OsFillOverride is { } os) os(ikm[..64]);
        else RandomNumberGenerator.Fill(ikm[..64]);
        lock (Gate)
        {
            Pool.CopyTo(ikm[64..]);
            BinaryPrimitives.WriteInt64LittleEndian(salt, ++_extractions);
            Mix(RatchetLabel);
        }
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, output, salt, Info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>pool = SHA-512(pool ‖ data). The caller must hold <see cref="Gate"/>.</summary>
    private static void Mix(ReadOnlySpan<byte> data)
    {
        Span<byte> buffer = stackalloc byte[Pool.Length + data.Length];
        Pool.CopyTo(buffer);
        data.CopyTo(buffer[Pool.Length..]);
        SHA512.HashData(buffer, Pool);
        CryptographicOperations.ZeroMemory(buffer);
    }
}
