using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Phrasia;

/// <summary>Saved generator settings (no passwords – only option values).</summary>
public sealed class GeneratorPreset
{
    public string Name { get; set; } = "";
    public string Lang { get; set; } = "sk-large";
    public string Case { get; set; } = "random";
    public string Separator { get; set; } = "period";
    public string CustomSeparator { get; set; } = "+";
    public string Symbols { get; set; } = "!@#$%^&*-_=+?";
    public string Numbers { get; set; } = "one";
    public int Words { get; set; } = 4;
    public int Digits { get; set; } = 2;
    public int MinLen { get; set; } = 3;
    public int MaxLen { get; set; } = 10;
    public bool Strip { get; set; } = true;
    public bool Unique { get; set; } = true;
    public bool Extra { get; set; }
    public int Variants { get; set; } = 6;

    /// <summary>Only for the "last settings" record: whether Recommended mode was on.</summary>
    public bool Recommended { get; set; }

    /// <summary>Returns the preset name (used for display in lists).</summary>
    public override string ToString() => Name;
}

/// <summary>On-disk preset document: saved presets, the last-used settings, and small UI flags.</summary>
public sealed class PresetFile
{
    public List<GeneratorPreset> Presets { get; set; } = new();

    /// <summary>Settings at the last app close – restored on next start.</summary>
    public GeneratorPreset? Last { get; set; }

    /// <summary>Reveal masked passwords on hover (off by default).</summary>
    public bool HoverReveal { get; set; }

    /// <summary>Ask GitHub at startup whether a newer release exists (on by default).</summary>
    public bool CheckForUpdates { get; set; } = true;

    /// <summary>A release the user chose to skip (e.g. "1.22.0"); it is not offered again.</summary>
    public string? SkippedVersion { get; set; }

    /// <summary>Color theme: "system" (follow Windows), "light" or "dark".</summary>
    public string Theme { get; set; } = "system";

    /// <summary>Target vault unlock time in seconds (Argon2id), 1–10 s, default 1 s.</summary>
    public int UnlockTargetSeconds { get; set; } = 1;

    // ---------------- Settings window (security & behaviour) ----------------

    /// <summary>Lock the vault after this many minutes without keyboard/mouse activity.</summary>
    public int AutoLockMinutes { get; set; } = AppSettings.DefaultAutoLockMinutes;

    /// <summary>Clear a copied password from the clipboard after this many seconds.</summary>
    public int ClipboardClearSeconds { get; set; } = AppSettings.DefaultClipboardClearSeconds;

    /// <summary>Hide generated passwords after this many minutes without activity.</summary>
    public int GeneratorIdleMinutes { get; set; } = AppSettings.DefaultGeneratorIdleMinutes;

    /// <summary>Lock the vault when the window is minimized.</summary>
    public bool LockOnMinimize { get; set; } = true;

    /// <summary>When the vault locks, also clear a password Phrasia copied (if it is still on the clipboard).</summary>
    public bool ClearClipboardOnLock { get; set; } = true;

    /// <summary>Exclude the window from screenshots, recording and screen sharing.</summary>
    public bool CaptureProtection { get; set; } = true;

    /// <summary>Tab shown at startup: "generator" or "vault".</summary>
    public string StartTab { get; set; } = "generator";

    /// <summary>The vault search also looks into notes.</summary>
    public bool SearchNotes { get; set; }

    // password health (used by the item list badges, the editor hint and Analyze)

    /// <summary>A normal account's password below this many bits is "weak".</summary>
    public int WeakBits { get; set; } = AppSettings.DefaultWeakBits;

    /// <summary>A critical account's password below this many bits is "weak".</summary>
    public int CriticalBits { get; set; } = AppSettings.DefaultCriticalBits;

    /// <summary>A password unchanged for longer than this many months is "old" (0 = never).</summary>
    public int OldAfterMonths { get; set; } = AppSettings.DefaultOldAfterMonths;

    // automatic backups of the encrypted vault file

    /// <summary>How many automatic backups to keep (0 = automatic backups off).</summary>
    public int AutoBackupCount { get; set; } = AppSettings.DefaultAutoBackupCount;

    /// <summary>True = at most one automatic backup per day; false = after every change.</summary>
    public bool AutoBackupDaily { get; set; } = true;

    /// <summary>Folder for automatic backups (empty = "Backups" next to the vault).</summary>
    public string AutoBackupFolder { get; set; } = "";

    // local encrypted log

    /// <summary>"off", "normal" or "detailed".</summary>
    public string LogLevel { get; set; } = "normal";

    /// <summary>Days of log files kept.</summary>
    public int LogKeepDays { get; set; } = AppSettings.DefaultLogKeepDays;

    /// <summary>Clamps values read from disk to the choices the Settings window offers (a damaged or
    /// hand-edited file must not produce e.g. a 0-minute auto-lock or a clipboard that is never cleared).</summary>
    public void Normalize()
    {
        AutoLockMinutes = AppSettings.Nearest(AppSettings.AutoLockChoices, AutoLockMinutes);
        ClipboardClearSeconds = AppSettings.Nearest(AppSettings.ClipboardChoices, ClipboardClearSeconds);
        GeneratorIdleMinutes = AppSettings.Nearest(AppSettings.GeneratorIdleChoices, GeneratorIdleMinutes);
        Theme = ThemeManager.ToSetting(ThemeManager.Parse(Theme));
        StartTab = StartTab == "vault" ? "vault" : "generator";
        WeakBits = AppSettings.Nearest(AppSettings.WeakBitsChoices, WeakBits);
        CriticalBits = AppSettings.Nearest(AppSettings.CriticalBitsChoices, CriticalBits);
        if (CriticalBits < WeakBits) CriticalBits = AppSettings.CriticalBitsChoices.First(c => c >= WeakBits);
        OldAfterMonths = AppSettings.Nearest(AppSettings.OldAfterMonthsChoices, OldAfterMonths);
        AutoBackupCount = AppSettings.Nearest(AppSettings.AutoBackupCountChoices, AutoBackupCount);
        AutoBackupFolder = (AutoBackupFolder ?? "").Trim();
        LogLevel = LogLevel is "off" or "detailed" ? LogLevel : "normal";
        LogKeepDays = AppSettings.Nearest(AppSettings.LogKeepDaysChoices, LogKeepDays);
    }
}

/// <summary>Allowed values and defaults of the Settings window.</summary>
public static class AppSettings
{
    public const int DefaultAutoLockMinutes = 5;
    public const int DefaultClipboardClearSeconds = 20;
    public const int DefaultGeneratorIdleMinutes = 3;

    public static readonly int[] AutoLockChoices = [1, 2, 3, 5, 10, 15, 30];
    public static readonly int[] ClipboardChoices = [10, 15, 20, 30, 45, 60, 90];
    public static readonly int[] GeneratorIdleChoices = [1, 2, 3, 5, 10];

    public const int DefaultWeakBits = 60;
    public const int DefaultCriticalBits = 75;
    public const int DefaultOldAfterMonths = 12;
    public const int DefaultAutoBackupCount = 10;
    public const int DefaultLogKeepDays = 30;

    public static readonly int[] WeakBitsChoices = [40, 50, 60, 70, 80];
    public static readonly int[] CriticalBitsChoices = [60, 70, 75, 80, 90, 100];
    public static readonly int[] OldAfterMonthsChoices = [0, 6, 12, 18, 24, 36];
    public static readonly int[] AutoBackupCountChoices = [0, 3, 5, 10, 20, 50];
    public static readonly int[] LogKeepDaysChoices = [7, 14, 30, 90];

    /// <summary>The allowed value closest to <paramref name="value"/> (ties go to the shorter, safer one).</summary>
    public static int Nearest(int[] choices, int value) =>
        choices.OrderBy(c => Math.Abs(c - value)).ThenBy(c => c).First();
}

/// <summary>
/// Persists presets to %APPDATA%\PassphraseGen\presets.dat.
///
/// The file is encrypted with Windows DPAPI (DataProtectionScope.CurrentUser): the key is bound to the
/// logged-in Windows user, so on disk it is a random-looking binary file that another user cannot read
/// and cannot move to another computer. It holds no passwords, only generator options – encrypted so
/// even the settings are unreadable in a hex editor. A legacy presets.json (from an older version) is
/// migrated and deleted on first load.
/// </summary>
public static class PresetStore
{
    private static string Dir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PassphraseGen");

    /// <summary>Full path of the encrypted preset file.</summary>
    public static string FilePath => Path.Combine(Dir, "presets.dat");
    private static string LegacyJsonPath => Path.Combine(Dir, "presets.json");

    // DPAPI domain separation (not a secret, only distinguishes it from other DPAPI blobs)
    private static readonly byte[] Entropy = "Phrasia | preset store | v2"u8.ToArray();

    /// <summary>Loads and decrypts presets; migrates a legacy plaintext file; returns defaults on any failure.</summary>
    public static PresetFile Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var plain = ProtectedData.Unprotect(File.ReadAllBytes(FilePath), Entropy, DataProtectionScope.CurrentUser);
                try
                {
                    var loaded = JsonSerializer.Deserialize<PresetFile>(plain) ?? new PresetFile();
                    loaded.Normalize();
                    return loaded;
                }
                finally { CryptographicOperations.ZeroMemory(plain); }
            }

            // migrate from the older (unencrypted) version
            if (File.Exists(LegacyJsonPath))
            {
                var file = JsonSerializer.Deserialize<PresetFile>(File.ReadAllText(LegacyJsonPath)) ?? new PresetFile();
                Save(file);
                try { File.Delete(LegacyJsonPath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                return file;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or CryptographicException)
        {
            // a corrupted/foreign file must not block startup – settings simply are not loaded
        }
        return new PresetFile();
    }

    /// <summary>Encrypts (DPAPI) and atomically writes the preset file; returns false on I/O/crypto failure.</summary>
    public static bool Save(PresetFile file)
    {
        try
        {
            Directory.CreateDirectory(Dir);
            var json = JsonSerializer.SerializeToUtf8Bytes(file);
            byte[] prot;
            try { prot = ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser); }
            finally { CryptographicOperations.ZeroMemory(json); }

            var tmp = FilePath + ".tmp";
            File.WriteAllBytes(tmp, prot);
            File.Move(tmp, FilePath, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return false;
        }
    }
}
