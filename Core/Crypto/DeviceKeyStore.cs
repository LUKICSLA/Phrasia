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
    private static string Dir => DirectoryOverride ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PassphraseGen");

    /// <summary>Test override: where device.bin / device.imp live (so tests never touch the real profile).</summary>
    internal static string? DirectoryOverride;
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
        DurableFile.WriteAllBytes(RawPath, ProtectedData.Protect(raw, DpapiEntropy, DataProtectionScope.CurrentUser));
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

    // Export file v2: [magic 20][params 8][salt 32][nonce 12][ciphertext 32][tag 16], AES-256-GCM, AAD = magic + params.
    // The key is Argon2id with the vault's own parameters × PIM, so a stolen export file is as costly to attack as
    // the vault. (v1 used PBKDF2-HMAC-SHA512 600k – GPU-friendly and much cheaper than the vault; read-only now.)
    private static readonly byte[] ExportMagicV2 = "PHRASIA-DEVICE-KEY-2"u8.ToArray();
    private static readonly byte[] ExportHkdfInfoV2 = "Phrasia device key export v2 | Argon2id (vault parameters) x PIM"u8.ToArray();
    private const int ExportParamsSize = 8, ExportSaltSize = 32, ExportNonceSize = 12, SecretSize = 32, ExportTagSize = 16;
    private static int ExportSizeV1 => ExportMagic.Length + ExportSaltSize + ExportNonceSize + SecretSize + ExportTagSize;
    private static int ExportSizeV2 => ExportMagicV2.Length + ExportParamsSize + ExportSaltSize + ExportNonceSize + SecretSize + ExportTagSize;

    /// <summary>Exports the current device secret for migration/backup, encrypted with the master password through
    /// Argon2id with the vault's parameters × PIM. Call through <see cref="Vault.ExportDeviceKey"/>, which first
    /// verifies the password belongs to the vault.</summary>
    internal static void ExportRecovery(string path, string masterPassword, Argon2Params vaultParams, int pim)
    {
        if (!vaultParams.IsPlausible) throw new ArgumentException("Invalid Argon2id parameters.", nameof(vaultParams));
        if (pim < Vault.MinPim || pim > Vault.MaxPim) throw new ArgumentOutOfRangeException(nameof(pim));
        var d = Current() ?? throw new InvalidOperationException("Device binding is not available on this computer.");

        var header = new byte[ExportMagicV2.Length + ExportParamsSize];
        ExportMagicV2.CopyTo(header, 0);
        WriteParams(header.AsSpan(ExportMagicV2.Length), vaultParams);
        var salt = EntropyPool.GetBytes(ExportSaltSize);
        var nonce = EntropyPool.GetBytes(ExportNonceSize);
        var ct = new byte[SecretSize];
        var tag = new byte[ExportTagSize];
        var key = DeriveExportKeyV2(masterPassword, salt, vaultParams, pim);
        try
        {
            using var aes = new AesGcm(key, ExportTagSize);
            aes.Encrypt(nonce, d, ct, tag, header);
        }
        finally { CryptographicOperations.ZeroMemory(key); }

        DurableFile.WriteAllBytes(path, [.. header, .. salt, .. nonce, .. ct, .. tag]);
    }

    /// <summary>Imports a device key from an export file (another PC) and stores it locally via DPAPI.
    /// <paramref name="pim"/> is the vault's PIM (needed for v2 files; ignored for old v1 files).</summary>
    public static void ImportRecovery(string path, string masterPassword, int pim)
    {
        var all = File.ReadAllBytes(path);
        byte[] key, aad;
        int o;
        if (all.Length == ExportSizeV2 && all.AsSpan(0, ExportMagicV2.Length).SequenceEqual(ExportMagicV2))
        {
            o = ExportMagicV2.Length;
            var p = ReadParams(all.AsSpan(o, ExportParamsSize));
            if (!p.IsPlausible) throw new InvalidDataException("This device-key file is damaged.");
            if (!Argon2Kdf.IsAvailable) throw new InvalidDataException("This device-key file needs Argon2id, which is not available here.");
            if (pim < Vault.MinPim || pim > Vault.MaxPim)
                throw new InvalidDataException($"Enter the vault's PIM ({Vault.MinPim}–{Vault.MaxPim}) – this device-key file is protected by the master password and the PIM.");
            aad = all[..(o + ExportParamsSize)];
            o += ExportParamsSize;
            key = DeriveExportKeyV2(masterPassword, all[o..(o + ExportSaltSize)], p, pim);
        }
        else if (all.Length == ExportSizeV1 && all.AsSpan(0, ExportMagic.Length).SequenceEqual(ExportMagic))
        {
            o = ExportMagic.Length;
            aad = ExportMagic;
            key = DeriveExportKeyV1(masterPassword, all[o..(o + ExportSaltSize)]);
        }
        else throw new InvalidDataException("This is not a Phrasia device-key file.");

        o += ExportSaltSize;
        var nonce = all.AsSpan(o, ExportNonceSize).ToArray(); o += ExportNonceSize;
        var ct = all.AsSpan(o, SecretSize).ToArray(); o += SecretSize;
        var tag = all.AsSpan(o, ExportTagSize).ToArray();

        var d = new byte[SecretSize];
        try
        {
            using var aes = new AesGcm(key, ExportTagSize);
            aes.Decrypt(nonce, ct, tag, d, aad);
        }
        catch (CryptographicException) { throw new WrongPasswordException(); }
        finally { CryptographicOperations.ZeroMemory(key); }

        Directory.CreateDirectory(Dir);
        DurableFile.WriteAllBytes(ImportedPath, ProtectedData.Protect(d, DpapiEntropy, DataProtectionScope.CurrentUser));
        CryptographicOperations.ZeroMemory(d);
        _cached = null; // reload on next use
    }

    /// <summary>v2 export key: Argon2id (vault parameters, passes × PIM) → HKDF-SHA256 → 32 B.</summary>
    private static byte[] DeriveExportKeyV2(string password, byte[] salt, Argon2Params p, int pim)
    {
        var ikm = Argon2Kdf.Derive(password, salt, p.MemoryKiB, p.Passes * pim, p.Lanes, 64);
        try
        {
            var key = new byte[32];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, key, salt, ExportHkdfInfoV2);
            return key;
        }
        finally { CryptographicOperations.ZeroMemory(ikm); }
    }

    /// <summary>v1 export key (read-only legacy): PBKDF2-HMAC-SHA512, 600k iterations.</summary>
    private static byte[] DeriveExportKeyV1(string password, byte[] salt)
    {
        var key = new byte[32];
        Rfc2898DeriveBytes.Pbkdf2(password.AsSpan(), salt, key, 600_000, HashAlgorithmName.SHA512);
        return key;
    }

    /// <summary>Writes Argon2 parameters as [memory KiB int32][passes uint16][lanes byte][0].</summary>
    private static void WriteParams(Span<byte> block, Argon2Params p)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(block, p.MemoryKiB);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(block[4..], (ushort)p.Passes);
        block[6] = (byte)p.Lanes;
        block[7] = 0;
    }

    /// <summary>Reads parameters written by <see cref="WriteParams"/>.</summary>
    private static Argon2Params ReadParams(ReadOnlySpan<byte> block) =>
        new(System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(block),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(block[4..]),
            block[7] == 0 ? block[6] : 0);
}
