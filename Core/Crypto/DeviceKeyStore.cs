using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Phrasia;

/// <summary>
/// Secret bound to this computer / Windows account. For a device-bound vault (format v7) this 32-byte
/// secret is mixed into key derivation – without it the vault will not open even with the correct password
/// and PIM on another machine.
///
/// How it is formed:
///  - a random 32-byte secret created on first use, stored via Windows DPAPI
///    (DataProtectionScope.CurrentUser) → bound to the logged-in Windows user,
///  - mixed with MachineGuid (registry) and the user SID → also bound to this machine (HWID).
///
/// Deliberate move to another computer: export the "device key" (encrypted with the master password) and
/// import it on the new PC. Without that export the vault is bound to the original machine only – a Windows
/// reinstall, a new profile or a disk change make it unopenable; exporting right after creation is strongly
/// recommended.
/// </summary>
internal static class DeviceKeyStore
{
    private static string Dir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PassphraseGen");
    private static string RawPath => Path.Combine(Dir, "device.bin");       // random secret (DPAPI)
    private static string ImportedPath => Path.Combine(Dir, "device.imp");  // migrated secret (DPAPI)

    private static readonly byte[] DpapiEntropy = "Phrasia | device key | v1"u8.ToArray();
    private static readonly byte[] HkdfInfo = "Phrasia device binding v1"u8.ToArray();
    private static readonly byte[] ExportMagic = "PHRASIA-DEVICE-KEY-1"u8.ToArray();

    /// <summary>Test override: when set, it is used instead of DPAPI/registry.</summary>
    internal static Func<byte[]?>? Override;

    private static byte[]? _cached;

    /// <summary>The 32-byte device secret (cached for the session). Null if it cannot be obtained.</summary>
    public static byte[]? Current()
    {
        if (Override is not null) return Override();
        if (_cached is not null) return _cached;
        try
        {
            // a migrated secret takes precedence (enables deliberate migration)
            if (File.Exists(ImportedPath))
                return _cached = ProtectedData.Unprotect(File.ReadAllBytes(ImportedPath), DpapiEntropy, DataProtectionScope.CurrentUser);

            var raw = GetOrCreateRaw();
            var salt = SHA256.HashData(Encoding.UTF8.GetBytes(MachineId() + "|" + UserSid()));
            var d = new byte[32];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, raw, d, salt, HkdfInfo);
            CryptographicOperations.ZeroMemory(raw);
            return _cached = d;
        }
        catch
        {
            return null; // no binding available; the caller decides what to do
        }
    }

    /// <summary>Whether device binding is available on this computer at all.</summary>
    public static bool IsAvailable => Current() is not null;

    /// <summary>Wipes the cached device secret from RAM (call when locking the vault).</summary>
    public static void ClearCache()
    {
        if (_cached is not null) CryptographicOperations.ZeroMemory(_cached);
        _cached = null;
    }

    /// <summary>Loads the DPAPI-protected raw secret, or creates and stores a new random one on first use.</summary>
    private static byte[] GetOrCreateRaw()
    {
        if (File.Exists(RawPath))
            return ProtectedData.Unprotect(File.ReadAllBytes(RawPath), DpapiEntropy, DataProtectionScope.CurrentUser);

        var raw = EntropyPool.GetBytes(32); // OS CSPRNG + user entropy (mouse)
        Directory.CreateDirectory(Dir);
        File.WriteAllBytes(RawPath, ProtectedData.Protect(raw, DpapiEntropy, DataProtectionScope.CurrentUser));
        return raw;
    }

    /// <summary>Reads the machine's MachineGuid from the registry (empty string if unavailable).</summary>
    private static string MachineId()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return k?.GetValue("MachineGuid")?.ToString() ?? "";
        }
        catch { return ""; }
    }

    /// <summary>Returns the current user's SID string (empty string if unavailable).</summary>
    private static string UserSid()
    {
        try { return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? ""; }
        catch { return ""; }
    }

    // ---------------- portable export / recovery of the device key ----------------

    /// <summary>Exports the current device secret, encrypted with the master password, for migration/backup.</summary>
    public static void ExportRecovery(string path, string masterPassword)
    {
        var d = Current() ?? throw new InvalidOperationException("Device binding is not available on this computer.");
        var salt = EntropyPool.GetBytes(32);
        var key = DeriveExportKey(masterPassword, salt);
        var nonce = EntropyPool.GetBytes(12);
        var ct = new byte[d.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, d, ct, tag, ExportMagic);
        }
        finally { CryptographicOperations.ZeroMemory(key); }

        using var fs = File.Create(path);
        fs.Write(ExportMagic);
        fs.Write(salt);
        fs.Write(nonce);
        fs.Write(ct);
        fs.Write(tag);
    }

    /// <summary>Imports a device key from an export file (another PC) and stores it locally via DPAPI.</summary>
    public static void ImportRecovery(string path, string masterPassword)
    {
        var all = File.ReadAllBytes(path);
        int min = ExportMagic.Length + 32 + 12 + 32 + 16;
        if (all.Length != min || !all.AsSpan(0, ExportMagic.Length).SequenceEqual(ExportMagic))
            throw new InvalidDataException("This is not a Phrasia device-key file.");

        int o = ExportMagic.Length;
        var salt = all.AsSpan(o, 32).ToArray(); o += 32;
        var nonce = all.AsSpan(o, 12).ToArray(); o += 12;
        var ct = all.AsSpan(o, 32).ToArray(); o += 32;
        var tag = all.AsSpan(o, 16).ToArray();

        var key = DeriveExportKey(masterPassword, salt);
        var d = new byte[32];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ct, tag, d, ExportMagic);
        }
        catch (CryptographicException) { throw new WrongPasswordException(); }
        finally { CryptographicOperations.ZeroMemory(key); }

        Directory.CreateDirectory(Dir);
        File.WriteAllBytes(ImportedPath, ProtectedData.Protect(d, DpapiEntropy, DataProtectionScope.CurrentUser));
        CryptographicOperations.ZeroMemory(d);
        _cached = null; // reload on next use
    }

    /// <summary>Derives the export-file encryption key from the master password (PBKDF2-HMAC-SHA512, 600k, vault-independent).</summary>
    private static byte[] DeriveExportKey(string password, byte[] salt)
    {
        var key = new byte[32];
        Rfc2898DeriveBytes.Pbkdf2(password.AsSpan(), salt, key, 600_000, HashAlgorithmName.SHA512);
        return key;
    }
}
