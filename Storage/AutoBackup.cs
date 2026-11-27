using System.Globalization;
using System.IO;
using System.Security.Cryptography;

namespace Phrasia;

/// <summary>
/// Automatic backups of the encrypted vault file (Settings › Backups). A backup is an exact copy of vault.pgv –
/// still encrypted with the master password and PIM that were valid when it was made – so it can be restored
/// with "Restore from backup" or merged with "Import items from backup". Only the newest N copies are kept.
/// </summary>
public static class AutoBackup
{
    private const string Prefix = "vault-auto-";
    private const string Extension = ".pgv";
    private const string StampFormat = "yyyyMMdd-HHmmss";

    /// <summary>Default folder: "Backups" next to the vault file.</summary>
    public static string DefaultFolder =>
        Path.Combine(Path.GetDirectoryName(Vault.DefaultPath)!, "Backups");

    /// <summary>The folder in use (the custom one, or the default).</summary>
    public static string FolderFor(PresetFile settings) =>
        string.IsNullOrWhiteSpace(settings.AutoBackupFolder) ? DefaultFolder : settings.AutoBackupFolder;

    /// <summary>
    /// Makes a backup if automatic backups are on and one is due: in daily mode when no backup exists from today,
    /// otherwise whenever the vault differs from the newest backup. Then deletes the oldest copies above the limit.
    /// Returns the new backup path, or null when none was needed.
    /// </summary>
    public static string? RunIfDue(string vaultPath, PresetFile settings, DateTime? now = null)
    {
        if (settings.AutoBackupCount <= 0 || !File.Exists(vaultPath)) return null;
        var time = now ?? DateTime.Now;
        string folder = FolderFor(settings);
        Directory.CreateDirectory(folder);

        var existing = List(folder);
        if (existing.Count > 0)
        {
            var newest = existing[0];
            if (settings.AutoBackupDaily && newest.Time.Date == time.Date) return null;
            if (SameContent(newest.Path, vaultPath)) return null; // nothing changed since the last backup
        }

        string path = Path.Combine(folder, Prefix + time.ToString(StampFormat, CultureInfo.InvariantCulture) + Extension);
        if (File.Exists(path)) return null; // two saves within one second
        var tmp = path + ".tmp";
        File.Copy(vaultPath, tmp, overwrite: true);
        File.Move(tmp, path);

        Prune(folder, settings.AutoBackupCount);
        return path;
    }

    /// <summary>Deletes the oldest automatic backups so that at most <paramref name="keep"/> remain.</summary>
    public static int Prune(string folder, int keep)
    {
        if (keep <= 0 || !Directory.Exists(folder)) return 0;
        int deleted = 0;
        foreach (var old in List(folder).Skip(keep))
        {
            try { File.Delete(old.Path); deleted++; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return deleted;
    }

    /// <summary>Automatic backups in the folder, newest first (only files named by Phrasia are touched).</summary>
    public static List<(string Path, DateTime Time)> List(string folder)
    {
        if (!Directory.Exists(folder)) return new();
        var result = new List<(string, DateTime)>();
        foreach (var f in Directory.EnumerateFiles(folder, Prefix + "*" + Extension))
        {
            var stamp = Path.GetFileNameWithoutExtension(f)[Prefix.Length..];
            if (DateTime.TryParseExact(stamp, StampFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var t))
                result.Add((f, t));
        }
        return result.OrderByDescending(x => x.Item2).ToList();
    }

    /// <summary>True if both files have identical bytes (compared by SHA-256).</summary>
    private static bool SameContent(string a, string b)
    {
        var fa = new FileInfo(a);
        var fb = new FileInfo(b);
        if (fa.Length != fb.Length) return false;
        using var sa = fa.OpenRead();
        using var sb = fb.OpenRead();
        return SHA256.HashData(sa).AsSpan().SequenceEqual(SHA256.HashData(sb));
    }
}
