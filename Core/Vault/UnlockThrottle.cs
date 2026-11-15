using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Phrasia;
/// <summary>
/// Throttle against guessing the master password through the app.
///
/// Rules: the 1st wrong attempt has no wait, then 30 s, and each further attempt triples the wait
/// (30 s → 1.5 min → 4.5 min → … → max 7 days).
///
/// Clock-independent: the wait is NOT computed from the date/time but counted down by a monotonic
/// timer (Stopwatch) only while the app runs. The remaining time is checkpointed, so a restart or a
/// system-clock change does not shorten it.
///
/// Tamper resistance: the state is stored in two places (a file + the HKCU registry). The registry
/// value is DPAPI-protected. The *.guard file is AES-256-GCM encrypted with a random key (stored in
/// the registry, DPAPI-protected) and padded to a fixed size – externally 284 random bytes with no
/// recognizable DPAPI header. A corrupted/altered record, or deleting just one of the two, counts as tampering.
/// </summary>
public sealed class UnlockThrottle
{
    public const int FreeAttempts = 2;          // the 1st wrong attempt has no wait, waiting starts from the 2nd
    private const double BaseDelaySeconds = 30;
    private const double Growth = 3;
    private const int TamperPenaltyAttempts = 8; // on tampering: as if after 8 wrong attempts (~6 h)
    private static readonly TimeSpan MaxDelay = TimeSpan.FromDays(7);
    private static readonly TimeSpan CheckpointInterval = TimeSpan.FromSeconds(15);

    private const string RegistryKeyPath = @"Software\PassphraseGen";
    private const string RegistryValueName = "UnlockGuard";
    private const string RegistryKeyValueName = "GuardKey";

    private const int GuardPlainSize = 256;
    private const int GuardFileSize = 12 + GuardPlainSize + 16; // nonce + ciphertext + tag
    private static readonly byte[] GuardAad = "PassphraseGen-guard-v2"u8.ToArray();
    private readonly byte[] _guardKey;

    private readonly string _filePath;
    private readonly byte[] _entropy;

    private double _remainingAtCheckpoint;   // sekundy
    private long _checkpointTimestamp;       // Stopwatch.GetTimestamp() – monotonic time
    private long _lastSaveTimestamp;

    public int FailedAttempts { get; private set; }
    public bool TamperDetected { get; private set; }

    /// <summary>Loads (or initializes) the throttle state for a vault, detecting tampering.</summary>
    public UnlockThrottle(string vaultPath)
    {
        _filePath = vaultPath + ".guard";
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes(
            "PassphraseGen-guard|" + Path.GetFullPath(vaultPath).ToUpperInvariant()));
        _guardKey = LoadOrCreateGuardKey();

        Load();
        SetRemaining(_remainingAtCheckpoint);
        if (TamperDetected) Save();
        _lastSaveTimestamp = Stopwatch.GetTimestamp();
    }

    /// <summary>The wait time after a given number of failed attempts (0 while within the free attempts).</summary>
    public static TimeSpan DelayFor(int failures) => failures < FreeAttempts
        ? TimeSpan.Zero
        : TimeSpan.FromSeconds(Math.Min(MaxDelay.TotalSeconds,
            BaseDelaySeconds * Math.Pow(Growth, failures - FreeAttempts)));

    /// <summary>The remaining wait before another unlock attempt is allowed.</summary>
    public TimeSpan RemainingLockout
    {
        get
        {
            double rem = _remainingAtCheckpoint - Stopwatch.GetElapsedTime(_checkpointTimestamp).TotalSeconds;
            return rem > 0 ? TimeSpan.FromSeconds(rem) : TimeSpan.Zero;
        }
    }

    /// <summary>How many more attempts are allowed before waiting begins.</summary>
    public int AttemptsBeforeDelay => Math.Max(0, FreeAttempts - FailedAttempts);

    /// <summary>Records a failed unlock attempt and extends the wait.</summary>
    public void RegisterFailure()
    {
        FailedAttempts++;
        SetRemaining(Math.Max(RemainingLockout.TotalSeconds, DelayFor(FailedAttempts).TotalSeconds));
        Save();
    }

    /// <summary>Clears the failure count and wait after a successful unlock (keeps the record present).</summary>
    public void Reset()
    {
        FailedAttempts = 0;
        TamperDetected = false;
        SetRemaining(0);
        Save(); // not deleted – a missing record could be abused
    }

    /// <summary>Saves the "served" time. Call periodically during the wait and on app close.</summary>
    /// <summary>Persists the currently served-down wait time.</summary>
    public void Checkpoint()
    {
        SetRemaining(RemainingLockout.TotalSeconds);
        Save();
    }

    /// <summary>Checkpoints the state if the checkpoint interval has elapsed.</summary>
    public void CheckpointIfDue()
    {
        if (Stopwatch.GetElapsedTime(_lastSaveTimestamp) >= CheckpointInterval) Checkpoint();
    }

    // ---------------- internal ----------------

    /// <summary>Sets the remaining wait (clamped to the maximum) and resets the monotonic reference point.</summary>
    private void SetRemaining(double seconds)
    {
        if (double.IsNaN(seconds) || seconds < 0) seconds = 0;
        _remainingAtCheckpoint = Math.Min(seconds, MaxDelay.TotalSeconds);
        _checkpointTimestamp = Stopwatch.GetTimestamp();
    }

    /// <summary>Reads the throttle state from the file and registry and flags tampering if they disagree or are missing.</summary>
    private void Load()
    {
        var file = ReadStore(() => File.Exists(_filePath) ? File.ReadAllBytes(_filePath) : null, UnprotectFile);
        var reg = ReadStore(() => ReadRegistry(RegistryValueName), UnprotectDpapi);

        var valid = new[] { file.State, reg.State }.OfType<State>().ToList();
        if (valid.Count > 0)
        {
            FailedAttempts = valid.Max(x => x.Failed);
            _remainingAtCheckpoint = valid.Max(x => x.RemainingSeconds);
        }

        bool corrupted = (file.Present && file.State is null) || (reg.Present && reg.State is null);
        bool registryKnownUnavailable = file.State?.NoRegistry == true;
        bool oneMissing = file.Present != reg.Present && !(registryKnownUnavailable && !reg.Present);

        if (corrupted || oneMissing)
        {
            TamperDetected = true;
            FailedAttempts = Math.Max(FailedAttempts, TamperPenaltyAttempts);
            _remainingAtCheckpoint = Math.Max(_remainingAtCheckpoint, DelayFor(TamperPenaltyAttempts).TotalSeconds);
        }
    }

    /// <summary>Writes the throttle state to both the registry (DPAPI) and the encrypted *.guard file.</summary>
    private void Save()
    {
        _lastSaveTimestamp = Stopwatch.GetTimestamp();
        var state = new State { Failed = FailedAttempts, RemainingSeconds = _remainingAtCheckpoint };

        bool registryOk = WriteRegistry(RegistryValueName, ProtectDpapi(JsonSerializer.SerializeToUtf8Bytes(state)));
        state.NoRegistry = !registryOk;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
            File.WriteAllBytes(_filePath, ProtectFile(state));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>DPAPI-protects data with this vaults entropy (CurrentUser).</summary>
    private byte[] ProtectDpapi(byte[] data) =>
        ProtectedData.Protect(data, _entropy, DataProtectionScope.CurrentUser);

    /// <summary>DPAPI-unprotects data with this vaults entropy (CurrentUser).</summary>
    private byte[] UnprotectDpapi(byte[] blob) =>
        ProtectedData.Unprotect(blob, _entropy, DataProtectionScope.CurrentUser);

    /// <summary>Layout: [nonce 12][AES-GCM(len 2 B + JSON + random padding to 256 B)][tag 16].</summary>
    private byte[] ProtectFile(State state)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(state);
        var plain = new byte[GuardPlainSize];
        BinaryPrimitives.WriteUInt16LittleEndian(plain, (ushort)json.Length);
        json.CopyTo(plain, 2);
        RandomNumberGenerator.Fill(plain.AsSpan(2 + json.Length));

        var output = new byte[GuardFileSize];
        RandomNumberGenerator.Fill(output.AsSpan(0, 12));
        using var aes = new AesGcm(_guardKey, 16);
        aes.Encrypt(output.AsSpan(0, 12), plain, output.AsSpan(12, GuardPlainSize), output.AsSpan(12 + GuardPlainSize), GuardAad);
        return output;
    }

    /// <summary>Decrypts and parses the *.guard file state (AES-256-GCM).</summary>
    private byte[] UnprotectFile(byte[] blob)
    {
        if (blob.Length != GuardFileSize)
            return UnprotectDpapi(blob); // file from an older version (plain DPAPI) – converted on the next save

        var plain = new byte[GuardPlainSize];
        using (var aes = new AesGcm(_guardKey, 16))
            aes.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(12, GuardPlainSize), blob.AsSpan(12 + GuardPlainSize), plain, GuardAad);

        int len = BinaryPrimitives.ReadUInt16LittleEndian(plain);
        if (len > GuardPlainSize - 2) throw new CryptographicException("Invalid length.");
        return plain.AsSpan(2, len).ToArray();
    }

    /// <summary>Random 256-bit key for the *.guard file, stored in the registry protected by DPAPI.</summary>
    private byte[] LoadOrCreateGuardKey()
    {
        try
        {
            var blob = ReadRegistry(RegistryKeyValueName);
            if (blob is not null)
            {
                var k = UnprotectDpapi(blob);
                if (k.Length == 32) return k;
            }
        }
        catch (Exception ex) when (ex is CryptographicException or IOException
                                      or UnauthorizedAccessException or System.Security.SecurityException) { }

        var key = RandomNumberGenerator.GetBytes(32);
        if (WriteRegistry(RegistryKeyValueName, ProtectDpapi(key))) return key;

        // registry unavailable – a fallback (non-secret) key, so the file at least stays structureless outwardly
        return SHA256.HashData(_entropy);
    }

    /// <summary>Reads one state store, reporting whether it was present and whether it parsed.</summary>
    private (bool Present, State? State) ReadStore(Func<byte[]?> read, Func<byte[], byte[]> unprotect)
    {
        byte[]? blob;
        try { blob = read(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return (false, null);
        }
        if (blob is null) return (false, null);

        try
        {
            var plain = unprotect(blob);
            var s = JsonSerializer.Deserialize<State>(plain);
            bool sane = s is not null && s.Failed >= 0 && s.RemainingSeconds >= 0
                        && s.RemainingSeconds <= MaxDelay.TotalSeconds + 1;
            return (true, sane ? s : null);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            return (true, null); // present, but altered/corrupted
        }
    }

    /// <summary>Reads a binary value from the apps HKCU registry key (null if missing).</summary>
    private static byte[]? ReadRegistry(string valueName)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RegistryKeyPath);
        return key?.GetValue(valueName) as byte[];
    }

    /// <summary>Writes a binary value to the apps HKCU registry key; returns false if the registry is unavailable.</summary>
    private static bool WriteRegistry(string valueName, byte[] blob)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RegistryKeyPath);
            key.SetValue(valueName, blob, RegistryValueKind.Binary);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    /// <summary>Serialized throttle state (failure count and remaining wait).</summary>
    private sealed class State
    {
        public int Failed { get; set; }
        public double RemainingSeconds { get; set; }
        public bool NoRegistry { get; set; }
    }
}
