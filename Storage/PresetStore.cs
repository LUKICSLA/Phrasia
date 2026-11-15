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

    /// <summary>Target vault unlock time in seconds (Argon2id), 1–10 s, default 1 s.</summary>
    public int UnlockTargetSeconds { get; set; } = 1;
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
                try { return JsonSerializer.Deserialize<PresetFile>(plain) ?? new PresetFile(); }
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
