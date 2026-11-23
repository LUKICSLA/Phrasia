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
/// Encrypted password vault.
///
/// Current format v7: Argon2id tuned to the computer + mandatory PIM + device binding + a two-cipher cascade.
///  - on create (or via "Tune to this PC") Argon2id is benchmarked and given as much memory as RAM allows
///    (64 MiB – 1 GiB), lanes by core count, and enough passes to hit the chosen unlock time (~1 s default,
///    up to 10 s, or "Maximum"); never below 64 MiB / 3 passes / 4 lanes (= v4, RFC 9106).
///  - PIM (1–100): a secret number chosen by the user that is NOT stored. Effective Argon2id passes =
///    stored (calibrated) × PIM, so without the correct PIM the key is not derived even with a known
///    password and parameters. Higher PIM = slower unlock and costlier guessing.
///  - device binding (v7): a per-machine/account secret (DPAPI + HWID) is mixed into the key, so the vault
///    opens only on this computer; moving it elsewhere requires the exported device key.
///  - file: [salt 32][params 8 – masked][nonce(s)][ciphertext][tag 16]; the params (without the PIM) are
///    masked (XOR with SHA-256 of the salt) and part of the AAD – tampering is detected. Their range is
///    checked (max 1 GiB, 20 passes) so a modified file cannot exhaust the app.
///  - key: Argon2id → 512 bits → HKDF-SHA256 → AES-256-GCM (+ ChaCha20-Poly1305 in v7), key in pinned memory.
///
/// Older formats are upgraded automatically on unlock (without a PIM → v5; with a PIM → v7):
///  v6 = Argon2id + PIM, v5 = Argon2id without PIM, v4 = Argon2id 64 MiB/3/4 (fixed), v3 = PBKDF2-HMAC-SHA512
///  + HKDF, v2 = PBKDF2-HMAC-SHA256, v1 = JSON. If Argon2 fails its self-test, new vaults stay on v3.
/// </summary>
public sealed class Vault : IDisposable
{
    // ----- v6 – Argon2id with calibrated parameters + mandatory PIM -----
    // PIM (Personal Iteration Multiplier): a secret number chosen by the user that is NOT stored in the file.
    // Argon2id passes = stored (calibrated) count × PIM, so without the correct PIM the key is not derived
    // even if the attacker knows the password and all parameters from the file. Higher PIM = slower unlock
    // and costlier guessing for an attacker. The PIM is never written to the log.
    private static readonly byte[] AadV6 = "Phrasia-vault-v6"u8.ToArray();
    private static readonly byte[] HkdfInfoV6 = "Phrasia vault v6 | Argon2id (calibrated) + PIM | AES-256-GCM encryption key"u8.ToArray();
    public const int MinPim = 1;
    public const int MaxPim = 100;

    // ----- v7 (current) – layered: Argon2id + PIM + optional device binding + a cipher cascade -----
    // Layers protecting the master password:
    //  1) Argon2id (memory-hard), passes = calibrated × PIM
    //  2) PIM – a secret multiplier (not stored)
    //  3) optional device secret (DPAPI + HWID) – vault bound to this PC/account
    //  4) HKDF splits the key into two independent subkeys
    //  5) a cascade of two ciphers: AES-256-GCM (inner) + ChaCha20-Poly1305 (outer)
    private static readonly byte[] AadV7 = "Phrasia-vault-v7"u8.ToArray();
    private static readonly byte[] HkdfInfoV7Device = "Phrasia vault v7 | device binding"u8.ToArray();
    private static readonly byte[] HkdfInfoV7Keys = "Phrasia vault v7 | AES-256-GCM + ChaCha20-Poly1305 cascade keys"u8.ToArray();
    private const byte FlagDeviceBound = 0x01;
    private const byte KnownFlags = FlagDeviceBound;

    // ----- v6 – Argon2id + PIM (single cipher) -----
    // ----- v5 – Argon2id with calibrated parameters (no PIM) -----
    private static readonly byte[] AadV5 = "Phrasia-vault-v5"u8.ToArray();
    private static readonly byte[] HkdfInfoV5 = "Phrasia vault v5 | Argon2id (calibrated) | AES-256-GCM encryption key"u8.ToArray();
    private static readonly byte[] ParamsMaskLabel = "Phrasia vault v5 | parameter mask"u8.ToArray();
    private static readonly byte[] AadHeaderBackupV4 = "Phrasia-header-backup-v4"u8.ToArray();
    private const int ParamsBlockSize = 8;

    // ----- v4 – Argon2id with fixed parameters (= Argon2Params.Floor) -----
    public const int Argon2MemoryKiB = 64 * 1024;
    public const int Argon2Passes = 3;
    public const int Argon2Lanes = 4;
    private static readonly byte[] AadV4 = "Phrasia-vault-v4"u8.ToArray();
    private static readonly byte[] HkdfInfoV4 = "Phrasia vault v4 | Argon2id | AES-256-GCM encryption key"u8.ToArray();
    private static readonly byte[] AadHeaderBackupV3 = "Phrasia-header-backup-v3"u8.ToArray();

    // ----- v3 – PBKDF2-HMAC-SHA512 -----
    public const int Pbkdf2Iterations = 1_000_000;
    private static readonly byte[] AadV3 = "Phrasia-vault-v3"u8.ToArray();
    private static readonly byte[] HkdfInfoV3 = "Phrasia vault v3 | AES-256-GCM encryption key"u8.ToArray();
    private static readonly byte[] AadHeaderBackupV2 = "Phrasia-header-backup-v2"u8.ToArray();

    // ----- older formats (read-only) -----
    private const int V2Iterations = 2_000_000;                                          // PBKDF2-HMAC-SHA256
    private static readonly byte[] AadV1 = "PassphraseGen-vault-v1"u8.ToArray();         // JSON format
    private static readonly byte[] AadV2 = "PassphraseGen-vault-v2"u8.ToArray();         // binary v2
    private static readonly byte[] AadHeaderBackupV1 = "PassphraseGen-header-backup-v1"u8.ToArray();

    public const int SaltSize = 32;
    private const int KeySize = 32, NonceSize = 12, TagSize = 16;
    private const int PaddingBlock = 4096;

    private const int HeaderPlainSize = 256;
    /// <summary>A legacy header backup (v1–v4, read-only for v5/v6/v7 vaults) has a fixed size: [backup salt 32][nonce 12][ciphertext 256][tag 16].</summary>
    public const int HeaderBackupSize = SaltSize + NonceSize + HeaderPlainSize + TagSize;

    // ----- header backup v5 (for v5/v6/v7 vaults) -----
    // Encrypted with the vault's own Argon2id parameters × PIM, so guessing the master password from a stolen
    // backup costs as much as from the vault itself. (The older backups used fixed 64 MiB / 3 passes and no PIM –
    // a cheaper target than the vault.) The parameters are stored masked next to the salt, like in the vault.
    /// <summary>Size of a v5 header backup: [backup salt 32][params 8 – masked][nonce 12][ciphertext 256][tag 16].</summary>
    public const int HeaderBackupSizeV5 = SaltSize + ParamsBlockSize + NonceSize + HeaderPlainSize + TagSize;
    private static readonly byte[] AadHeaderBackupV5 = "Phrasia-header-backup-v5"u8.ToArray();
    private static readonly byte[] HkdfInfoHeaderBackupV5 = "Phrasia header backup v5 | Argon2id (vault parameters) x PIM"u8.ToArray();
    private static readonly byte[] BackupParamsMaskLabel = "Phrasia header backup v5 | parameter mask"u8.ToArray();

    /// <summary>On-disk vault format versions (higher = newer/stronger).</summary>
    internal enum Format : byte { V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6, V7 = 7 }

    /// <summary>Format for new vaults: v7 (Argon2id + PIM + device binding + cascade) whenever Argon2 is available – ChaCha20-Poly1305 falls back to a managed implementation where the OS lacks it (Windows 10); otherwise v3.</summary>
    internal static Format CurrentFormat =>
        !Argon2Kdf.IsAvailable ? Format.V3 : Format.V7;

    /// <summary>Target format when upgrading older vaults opened without a PIM (v5 without PIM, otherwise v3).</summary>
    internal static Format UpgradelessFormat => Argon2Kdf.IsAvailable ? Format.V5 : Format.V3;

    /// <summary>Human-readable description of the key derivation used for new vaults.</summary>
    public static string KdfDescription => CurrentFormat switch
    {
        Format.V7 => "Argon2id tuned to this PC + mandatory PIM + device binding + AES-256-GCM / ChaCha20-Poly1305 cascade",
        Format.V6 => "Argon2id tuned to this PC + mandatory PIM + HKDF-SHA256",
        _ => "PBKDF2-HMAC-SHA512 (1,000,000 iterations) + HKDF-SHA256"
    };

    /// <summary>Default vault file path under %APPDATA%\PassphraseGen.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "PassphraseGen", "vault.pgv");

    private ProtectedKey? _key; // key protected in RAM (DPAPI/masking + locked page)
    private byte[] _salt;
    private Format _format;
    private Argon2Params? _params;   // v5/v6/v7
    private int _pim;                // v6/v7 (secret, in memory while unlocked; never stored)
    private bool _deviceBound;       // v7 (bound to this PC/account)
    private readonly object _gate = new(); // guards key/header state against a concurrent lock (Dispose) and re-key
    private bool _disposed;

    public string FilePath { get; }
    /// <summary>The numeric on-disk format version of this vault.</summary>
    public int FormatVersion => (int)_format;
    public bool WasUpgraded { get; private init; }
    public List<VaultEntry> Entries { get; }

    /// <summary>True for formats that use a PIM (v6/v7).</summary>
    private static bool FormatUsesPim(Format f) => f is Format.V6 or Format.V7;
    /// <summary>True for formats that store Argon2 parameters in the header (v5/v6/v7).</summary>
    private static bool FormatHasParams(Format f) => f is Format.V5 or Format.V6 or Format.V7;
    /// <summary>True for the two-cipher cascade format (v7).</summary>
    private static bool FormatIsCascade(Format f) => f == Format.V7;

    /// <summary>Whether this vault uses a PIM (v6/v7).</summary>
    public bool UsesPim => FormatUsesPim(_format);
    /// <summary>Whether this vault is bound to this computer/account (v7).</summary>
    public bool IsDeviceBound => _format == Format.V7 && _deviceBound;
    /// <summary>Whether this vault supports device binding (v7).</summary>
    public bool SupportsDeviceBinding => _format == Format.V7;

    /// <summary>Description of this vaults key derivation (for status/log). The PIM is deliberately omitted.</summary>
    public string KdfInfo => _format switch
    {
        Format.V7 => _params!.ToString() + " × PIM" + (_deviceBound ? " + device-bound" : "") + " + AES-GCM/ChaCha20 cascade",
        Format.V6 => _params!.ToString() + " × PIM",
        Format.V5 => _params!.ToString(),
        Format.V4 => Argon2Params.Floor.ToString(),
        Format.V3 => "PBKDF2-HMAC-SHA512, 1,000,000 iterations",
        _ => "PBKDF2-HMAC-SHA256, 2,000,000 iterations"
    };

    /// <summary>The Argon2 parameters of this vault (null for non-Argon2 formats).</summary>
    public Argon2Params? Argon2Parameters => _format switch
    {
        Format.V7 or Format.V6 or Format.V5 => _params,
        Format.V4 => Argon2Params.Floor,
        _ => null
    };

    /// <summary>Private constructor: wraps the derived key in a <see cref="ProtectedKey"/> and stores the vault state.</summary>
    private Vault(string path, byte[] key, byte[] salt, Format format, Argon2Params? p, int pim, bool deviceBound, List<VaultEntry> entries)
    {
        FilePath = path;
        _key = new ProtectedKey(key); // takes ownership of 'key' and zeroes it
        _salt = salt;
        _format = format;
        _params = p;
        _pim = pim;
        _deviceBound = deviceBound;
        Entries = entries;
    }

    /// <summary>Parameters for a new key in the given format (v5/v6/v7: calibrated for this computer).</summary>
    private static Argon2Params? NewParams(Format f) =>
        FormatHasParams(f) ? Argon2Calibrator.Calibrate().Params : null;

    /// <summary>Throws if a PIM-using format is given a PIM outside 1–100.</summary>
    private static void ValidatePim(Format format, int pim)
    {
        if (FormatUsesPim(format) && (pim < MinPim || pim > MaxPim))
            throw new ArgumentOutOfRangeException(nameof(pim),
                $"PIM must be between {MinPim} and {MaxPim}.");
    }

    /// <summary>The device secret for a bound v7 vault; otherwise null. Throws if binding is unavailable.</summary>
    private static byte[]? DeviceSecretFor(Format format, bool deviceBound)
    {
        if (format != Format.V7 || !deviceBound) return null;
        return DeviceKeyStore.Current()
            ?? throw new InvalidOperationException("This vault is bound to a computer, but device binding is not available here.");
    }

    /// <summary>Creates a new vault. For v7 the <paramref name="pim"/> is mandatory (1–100) and the vault is ALWAYS bound to this computer/account (DeviceKeyStore) – it will not open elsewhere. Moving to another PC requires exporting/importing the device key.</summary>
    public static Vault Create(string path, string masterPassword, int pim)
    {
        if (File.Exists(path)) throw new InvalidOperationException("The vault already exists.");
        var salt = EntropyPool.GetBytes(SaltSize); // OS CSPRNG + user entropy
        var format = CurrentFormat;
        ValidatePim(format, pim);
        if (!FormatUsesPim(format)) pim = 0;
        bool bound = format == Format.V7; // binding is mandatory for v7
        var device = DeviceSecretFor(format, bound);
        var p = NewParams(format);
        var vault = new Vault(path, DeriveKey(format, masterPassword, salt, p, pim, device), salt, format, p, pim, bound,
            new List<VaultEntry>());
        vault.Save();
        return vault;
    }

    /// <summary>Opens a vault. v6/v7 vaults need the correct <paramref name="pim"/>; for older (PIM-less) vaults it is ignored. If a PIM is given for a PIM-less vault, the upgrade sets that PIM.</summary>
    public static Vault Open(string path, string masterPassword, int pim = 0)
    {
        var bytes = File.ReadAllBytes(path);

        // legacy JSON format (v1) → open and re-encrypt into the current format
        if (bytes.Length > 0 && bytes[0] == (byte)'{')
        {
            try { return OpenLegacyJson(path, bytes, masterPassword, pim); }
            catch (JsonException) { /* a random binary file may start with '{' */ }
            catch (FormatException) { }
        }
        return OpenBinaryAny(path, bytes, masterPassword, pim, allowUpgrade: true);
    }

    /// <summary>Tries v7/v6 (when a PIM is given), v5, v4, v3, v2, and upgrades an older format to the current one.</summary>
    private static Vault OpenBinaryAny(string path, byte[] bytes, string masterPassword, int pim, bool allowUpgrade)
    {
        var order = new List<Format>();
        if (Argon2Kdf.IsAvailable && pim >= MinPim) { order.Add(Format.V7); order.Add(Format.V6); }
        if (Argon2Kdf.IsAvailable) { order.Add(Format.V5); order.Add(Format.V4); }
        order.Add(Format.V3);
        order.Add(Format.V2);

        // Argon2 is expensive; several formats can share the same parameters (both v7 and v6 = calibrated × PIM),
        // so the Argon2 output is cached by parameters – on a wrong password it is not recomputed needlessly.
        byte[]? saltForIkm = bytes.Length >= SaltSize ? bytes[..SaltSize] : null;
        var ikmCache = new Dictionary<(int, int, int), byte[]>();
        Func<Argon2Params, byte[]>? ikm = saltForIkm is null ? null : ap =>
        {
            var k = (ap.MemoryKiB, ap.Passes, ap.Lanes);
            if (!ikmCache.TryGetValue(k, out var v))
            {
                v = Argon2Kdf.Derive(masterPassword, saltForIkm, ap.MemoryKiB, ap.Passes, ap.Lanes, 64);
                ikmCache[k] = v;
            }
            return v;
        };

        try
        {
            foreach (var format in order)
            {
                Argon2Params? p = null;
                byte flags = 0;
                if (FormatHasParams(format) && !TryReadParams(bytes, out p, out flags)) continue; // without the expensive computation

                bool bound = format == Format.V7 && (flags & FlagDeviceBound) != 0;
                byte[]? device;
                try { device = DeviceSecretFor(format, bound); }
                catch (InvalidOperationException) { continue; } // bound to another PC – will not open here

                Vault opened;
                try { opened = OpenBinary(path, bytes, masterPassword, format, p, FormatUsesPim(format) ? pim : 0, flags, device, ikm); }
                catch (WrongPasswordException) { continue; }

                if (!allowUpgrade) return opened;
                if (opened._format == Format.V7) return opened; // highest format

                // v6 → upgrade to v7 (cascade + mandatory binding), keep the PIM
                if (opened._format == Format.V6)
                    using (opened) return Upgrade(path, masterPassword, opened.Entries, Format.V7, opened._pim);

                // without a PIM (v5/v4/v3/v2): with a given PIM → v7, otherwise only v5/v3
                if (Argon2Kdf.IsAvailable && pim >= MinPim)
                    using (opened) return Upgrade(path, masterPassword, opened.Entries, Format.V7, pim);

                if (opened._format >= UpgradelessFormat) return opened;
                using (opened) return Upgrade(path, masterPassword, opened.Entries, UpgradelessFormat, 0);
            }
            throw new WrongPasswordException();
        }
        finally
        {
            foreach (var v in ikmCache.Values) CryptographicOperations.ZeroMemory(v);
        }
    }

    /// <summary>Re-encrypts the given entries into a new vault of the target format (binds to this PC for v7) and marks it upgraded.</summary>
    private static Vault Upgrade(string path, string masterPassword, List<VaultEntry> entries, Format format, int pim)
    {
        ValidatePim(format, pim);
        if (!FormatUsesPim(format)) pim = 0;
        bool bound = format == Format.V7; // binding is mandatory for v7
        var device = DeviceSecretFor(format, bound);
        var newSalt = EntropyPool.GetBytes(SaltSize); // OS CSPRNG + user entropy
        var p = NewParams(format);
        var upgraded = new Vault(path, DeriveKey(format, masterPassword, newSalt, p, pim, device), newSalt, format, p, pim, bound, entries)
        {
            WasUpgraded = true
        };
        upgraded.Save();
        return upgraded;
    }

    /// <summary>Length of the header prefix (salt, plus the params block for v5/v6/v7) before the nonce(s).</summary>
    private static int HeaderLength(Format f) => FormatHasParams(f) ? SaltSize + ParamsBlockSize : SaltSize;

    /// <summary>Decrypts a binary vault of a specific format (single cipher or cascade) and returns the opened vault.</summary>
    private static Vault OpenBinary(string path, byte[] bytes, string masterPassword, Format format, Argon2Params? p, int pim, byte flags, byte[]? device,
        Func<Argon2Params, byte[]>? ikm = null)
    {
        int header = HeaderLength(format);
        var salt = bytes[..SaltSize];
        var aad = VaultAad(format, p, flags);
        var key = DeriveKey(format, masterPassword, salt, p, pim, device, ikm);

        byte[] plain;
        if (FormatIsCascade(format))
        {
            plain = DecryptCascade(key, bytes, header, aad);
        }
        else
        {
            if (bytes.Length < header + NonceSize + TagSize + 4)
                throw new InvalidDataException("The vault file is damaged.");
            var nonce = bytes[header..(header + NonceSize)];
            var cipher = bytes[(header + NonceSize)..^TagSize];
            var tag = bytes[^TagSize..];
            plain = Decrypt(key, nonce, cipher, tag, aad);
        }
        try
        {
            int len = BinaryPrimitives.ReadInt32LittleEndian(plain);
            if (len < 0 || len > plain.Length - 4)
                throw new InvalidDataException("The vault file is damaged.");
            var entries = JsonSerializer.Deserialize<List<VaultEntry>>(plain.AsSpan(4, len)) ?? new List<VaultEntry>();
            return new Vault(path, key, salt, format, p, pim, format == Format.V7 && (flags & FlagDeviceBound) != 0, entries);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>Opens a v1 JSON vault (PBKDF2-SHA256) and upgrades it to the current format.</summary>
    private static Vault OpenLegacyJson(string path, byte[] bytes, string masterPassword, int pim)
    {
        var env = JsonSerializer.Deserialize<Envelope>(bytes)
                  ?? throw new InvalidDataException("The vault file is damaged.");
        if (env.Version != 1 || env.Kdf != "PBKDF2-SHA256" || env.Cipher != "AES-256-GCM")
            throw new InvalidDataException("Unsupported vault file version.");
        if (env.Iterations < 100_000)
            throw new InvalidDataException("The vault file has a suspiciously low iteration count.");

        var salt = Convert.FromBase64String(env.Salt);
        var key = DerivePbkdf2Sha256(masterPassword, salt, env.Iterations);
        var plain = Decrypt(key, Convert.FromBase64String(env.Nonce), Convert.FromBase64String(env.Data),
                            Convert.FromBase64String(env.Tag), AadV1);
        CryptographicOperations.ZeroMemory(key);
        try
        {
            var entries = JsonSerializer.Deserialize<List<VaultEntry>>(plain) ?? new List<VaultEntry>();
            var target = (Argon2Kdf.IsAvailable && pim >= MinPim) ? Format.V7 : UpgradelessFormat;
            return Upgrade(path, masterPassword, entries, target, FormatUsesPim(target) ? pim : 0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    // ---------------- v5/v6/v7 header parameters ----------------

    // block[7] = flags (bit0 = device-bound); remaining bits reserved (0).
    /// <summary>Encodes the Argon2 params + flags into the 8-byte header block (block[7] holds the flags).</summary>
    private static byte[] RawParams(Argon2Params p, byte flags)
    {
        var block = new byte[ParamsBlockSize];
        BinaryPrimitives.WriteInt32LittleEndian(block, p.MemoryKiB);
        BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(4), (ushort)p.Passes);
        block[6] = (byte)p.Lanes;
        block[7] = flags;
        return block;
    }

    /// <summary>Mask derived from the salt – the parameters look like random bytes in the file.</summary>
    private static byte[] ParamsMask(ReadOnlySpan<byte> salt, byte[]? label = null)
    {
        label ??= ParamsMaskLabel;
        var input = new byte[label.Length + salt.Length];
        label.CopyTo(input, 0);
        salt.CopyTo(input.AsSpan(label.Length));
        return SHA256.HashData(input)[..ParamsBlockSize];
    }

    /// <summary>Returns the params block XOR-masked with a salt-derived mask (so it looks random in the file).</summary>
    private static byte[] MaskedParams(ReadOnlySpan<byte> salt, Argon2Params p, byte flags, byte[]? label = null)
    {
        var block = RawParams(p, flags);
        var mask = ParamsMask(salt, label);
        for (int i = 0; i < ParamsBlockSize; i++) block[i] ^= mask[i];
        return block;
    }

    /// <summary>Reads v5/v6/v7 parameters + flags and validates their range (otherwise it is not such a file).</summary>
    private static bool TryReadParams(byte[] bytes, out Argon2Params? p, out byte flags)
    {
        p = null; flags = 0;
        if (bytes.Length < SaltSize + ParamsBlockSize + NonceSize + TagSize + 4) return false;
        var mask = ParamsMask(bytes.AsSpan(0, SaltSize));
        var block = new byte[ParamsBlockSize];
        for (int i = 0; i < ParamsBlockSize; i++) block[i] = (byte)(bytes[SaltSize + i] ^ mask[i]);
        if ((block[7] & ~KnownFlags) != 0) return false; // unknown flags → not our file
        var candidate = new Argon2Params(
            BinaryPrimitives.ReadInt32LittleEndian(block),
            BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(4)),
            block[6]);
        if (!candidate.IsPlausible) return false;
        p = candidate;
        flags = block[7];
        return true;
    }

    /// <summary>AAD: format version + parameters + flags (tampering is detected). The PIM and device secret are not in the AAD.</summary>
    private static byte[] VaultAad(Format f, Argon2Params? p, byte flags) => f switch
    {
        Format.V7 => AadV7.Concat(RawParams(p!, flags)).ToArray(),
        Format.V6 => AadV6.Concat(RawParams(p!, 0)).ToArray(),
        Format.V5 => AadV5.Concat(RawParams(p!, 0)).ToArray(),
        Format.V4 => AadV4,
        Format.V3 => AadV3,
        _ => AadV2
    };

    // ---------------- cipher cascade (v7): AES-256-GCM (inner) + ChaCha20-Poly1305 (outer) ----------------

    /// <summary>v7 encryption: AES-256-GCM (inner) then ChaCha20-Poly1305 (outer); returns [nonceAes][nonceChaCha][ct][tag].</summary>
    private static byte[] EncryptCascade(byte[] key64, byte[] plain, byte[] aad)
    {
        var kAes = key64[..KeySize];
        var kChacha = key64[KeySize..];
        var nAes = RandomNumberGenerator.GetBytes(NonceSize);
        var nCh = RandomNumberGenerator.GetBytes(NonceSize);
        var innerCt = new byte[plain.Length];
        var innerTag = new byte[TagSize];
        byte[]? inner = null;
        try
        {
            using (var aes = new AesGcm(kAes, TagSize))
                aes.Encrypt(nAes, plain, innerCt, innerTag, aad);
            inner = new byte[innerCt.Length + TagSize];
            innerCt.CopyTo(inner, 0);
            innerTag.CopyTo(inner, innerCt.Length);

            var outerCt = new byte[inner.Length];
            var outerTag = new byte[TagSize];
            ChaCha20Poly1305Aead.Encrypt(kChacha, nCh, inner, outerCt, outerTag, aad);

            var body = new byte[NonceSize + NonceSize + outerCt.Length + TagSize];
            nAes.CopyTo(body, 0);
            nCh.CopyTo(body, NonceSize);
            outerCt.CopyTo(body, NonceSize + NonceSize);
            outerTag.CopyTo(body, NonceSize + NonceSize + outerCt.Length);
            return body;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kAes);
            CryptographicOperations.ZeroMemory(kChacha);
            CryptographicOperations.ZeroMemory(innerCt);
            if (inner is not null) CryptographicOperations.ZeroMemory(inner);
        }
    }

    /// <summary>v7 decryption: reverses the ChaCha20-Poly1305 then AES-256-GCM cascade; throws WrongPassword on failure.</summary>
    private static byte[] DecryptCascade(byte[] key64, byte[] bytes, int header, byte[] aad)
    {
        if (bytes.Length < header + NonceSize + NonceSize + TagSize + 4)
            throw new InvalidDataException("The vault file is damaged.");
        var kAes = key64[..KeySize];
        var kChacha = key64[KeySize..];
        var nAes = bytes[header..(header + NonceSize)];
        var nCh = bytes[(header + NonceSize)..(header + 2 * NonceSize)];
        var outerCt = bytes[(header + 2 * NonceSize)..^TagSize];
        var outerTag = bytes[^TagSize..];
        var inner = new byte[outerCt.Length];
        try
        {
            ChaCha20Poly1305Aead.Decrypt(kChacha, nCh, outerCt, outerTag, inner, aad);
            if (inner.Length < TagSize) throw new InvalidDataException("The vault file is damaged.");
            int innerCtLen = inner.Length - TagSize;
            var innerTag = inner[innerCtLen..];
            var plain = new byte[innerCtLen];
            using (var aes = new AesGcm(kAes, TagSize))
                aes.Decrypt(nAes, inner.AsSpan(0, innerCtLen), innerTag, plain, aad);
            return plain;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(key64);
            throw new WrongPasswordException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kAes);
            CryptographicOperations.ZeroMemory(kChacha);
            CryptographicOperations.ZeroMemory(inner);
        }
    }

    /// <summary>Single-cipher AES-256-GCM decryption; throws WrongPassword (and zeroes the key) on failure.</summary>
    private static byte[] Decrypt(byte[] key, byte[] nonce, byte[] cipher, byte[] tag, byte[] aad)
    {
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain, aad);
            return plain;
        }
        catch (CryptographicException)
        {
            // wrong password or altered file – GCM cannot tell them apart
            CryptographicOperations.ZeroMemory(key);
            throw new WrongPasswordException();
        }
    }

    /// <summary>Serializes, pads and encrypts the entries (single cipher or v7 cascade) and atomically writes the vault file. Safe against a concurrent lock (Dispose) or re-key.</summary>
    public void Save()
    {
        lock (_gate) SaveCore();
    }

    /// <summary>Save implementation; the caller must hold <see cref="_gate"/>.</summary>
    private void SaveCore()
    {
        ThrowIfLocked();
        byte flags = (byte)(IsDeviceBound ? FlagDeviceBound : 0);
        var aad = VaultAad(_format, _params, flags);

        // [length 4 B][JSON][random padding to a multiple of 4 KiB]
        var json = JsonSerializer.SerializeToUtf8Bytes(Entries);
        int payload = 4 + json.Length;
        int padded = (payload / PaddingBlock + 1) * PaddingBlock;
        var plain = new byte[padded];
        BinaryPrimitives.WriteInt32LittleEndian(plain, json.Length);
        json.CopyTo(plain, 4);
        RandomNumberGenerator.Fill(plain.AsSpan(payload));
        CryptographicOperations.ZeroMemory(json);

        int header = HeaderLength(_format);
        byte[]? body = null;
        try
        {
            if (FormatIsCascade(_format))
            {
                _key!.Use(k => body = EncryptCascade(k, plain, aad));
            }
            else
            {
                var nonce = RandomNumberGenerator.GetBytes(NonceSize);
                var ct = new byte[plain.Length];
                var tag = new byte[TagSize];
                _key!.Use(k =>
                {
                    using var aes = new AesGcm(k, TagSize);
                    aes.Encrypt(nonce, plain, ct, tag, aad);
                });
                body = new byte[NonceSize + ct.Length + TagSize];
                nonce.CopyTo(body, 0);
                ct.CopyTo(body, NonceSize);
                tag.CopyTo(body, NonceSize + ct.Length);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }

        var output = new byte[header + body!.Length];
        _salt.CopyTo(output, 0);
        if (FormatHasParams(_format)) MaskedParams(_salt, _params!, flags).CopyTo(output, SaltSize);
        body.CopyTo(output, header);

        // atomic, durable write: a flushed temp file first, then a write-through replace – neither a crash
        // nor a power cut leaves an empty or half-written vault
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        DurableFile.ReplaceAtomically(FilePath, output);
        WriteChecksum(FilePath, output);
    }

    /// <summary>Verifies the password belongs to this (unlocked) vault – constant-time comparison. Throws <see cref="ObjectDisposedException"/> if the vault is (or gets) locked meanwhile.</summary>
    public bool VerifyPassword(string masterPassword)
    {
        // snapshot the state under the lock; the slow key derivation then runs without holding it
        ProtectedKey key;
        Format format;
        byte[] salt;
        Argon2Params? p;
        int pim;
        bool bound;
        lock (_gate)
        {
            ThrowIfLocked();
            (key, format, salt, p, pim, bound) = (_key!, _format, _salt, _params, _pim, _deviceBound);
        }
        var device = DeviceSecretFor(format, bound);
        var k = DeriveKey(format, masterPassword, salt, p, pim, device);
        try { return key.Equals(k); } // ProtectedKey throws ObjectDisposedException if it was wiped meanwhile
        finally { CryptographicOperations.ZeroMemory(k); }
    }

    /// <summary>Changes the master password: verifies the current one, generates a new salt and key, and re-encrypts. Format, PIM and binding are kept. On a save error the previous state is restored.</summary>
    public void ChangeMasterPassword(string currentPassword, string newPassword) =>
        ReKey(currentPassword, newPassword, _format, _params, _pim, _deviceBound);

    /// <summary>Re-encrypts the vault with Argon2 parameters re-tuned to this computer (password, PIM and binding are kept). <paramref name="targetMs"/> = unlock time (1–10 s), or <paramref name="maximum"/> = hardest settings this computer can bear (ignores the target time). Returns the calibration result.</summary>
    public CalibrationResult TuneToThisComputer(string masterPassword, double targetMs = Argon2Calibrator.DefaultTargetMs, bool maximum = false)
    {
        if (!FormatHasParams(_format)) throw new InvalidOperationException("Argon2id is not available for this vault.");
        if (!VerifyPassword(masterPassword)) throw new WrongPasswordException();
        var result = maximum ? Argon2Calibrator.CalibrateMaximum() : CalibrateForTarget(targetMs);
        ReKey(masterPassword, masterPassword, _format, result.Params, _pim, _deviceBound);
        return result;
    }

    /// <summary>Enables/disables binding the vault to this computer/account (v7 only). Requires the master password.</summary>
    public void SetDeviceBinding(string masterPassword, bool bind)
    {
        if (_format != Format.V7) throw new InvalidOperationException("Device binding needs a v7 vault.");
        if (bind && DeviceKeyStore.Current() is null)
            throw new InvalidOperationException("Device binding is not available on this computer.");
        ReKey(masterPassword, masterPassword, Format.V7, _params, _pim, bind);
    }

    /// <summary>Exports the device key of this device-bound vault for migration/recovery. First verifies that
    /// <paramref name="masterPassword"/> is this vault's password (a typo would otherwise produce an export nobody
    /// can open), then protects the export with the vault's Argon2id parameters × PIM.</summary>
    public void ExportDeviceKey(string path, string masterPassword)
    {
        if (!VerifyPassword(masterPassword)) throw new WrongPasswordException();
        Argon2Params p;
        int pim;
        lock (_gate)
        {
            ThrowIfLocked();
            if (_format != Format.V7 || !_deviceBound || _params is null)
                throw new InvalidOperationException("This vault is not bound to this computer.");
            (p, pim) = (_params, _pim);
        }
        DeviceKeyStore.ExportRecovery(path, masterPassword, p, pim);
    }

    /// <summary>Sets the calibration target and runs a fresh calibration.</summary>
    private static CalibrationResult CalibrateForTarget(double targetMs)
    {
        Argon2Calibrator.TargetMs = targetMs;
        return Argon2Calibrator.Calibrate(force: true);
    }

    /// <summary>Verifies the current password and re-encrypts with a new salt/key/format/PIM/binding, reverting on a save error.</summary>
    private void ReKey(string currentPassword, string newPassword, Format newFormat, Argon2Params? newParams, int newPim, bool newDeviceBound)
    {
        if (!VerifyPassword(currentPassword)) throw new WrongPasswordException();
        ValidatePim(newFormat, newPim);
        if (!FormatUsesPim(newFormat)) newPim = 0;
        bool bound = newFormat == Format.V7 && newDeviceBound;
        var device = DeviceSecretFor(newFormat, bound);

        // the slow key derivation runs outside the lock …
        var newSalt = EntropyPool.GetBytes(SaltSize); // OS CSPRNG + user entropy
        var newKey = new ProtectedKey(DeriveKey(newFormat, newPassword, newSalt, newParams, newPim, device)); // takes ownership of the bytes and zeroes them

        // … while the state swap and the save are atomic with respect to locking (Dispose)
        lock (_gate)
        {
            if (_disposed)
            {
                newKey.Dispose();
                throw LockedError(); // the vault was locked meanwhile – nothing was changed
            }
            var oldKey = _key;
            var (oldSalt, oldFormat, oldParams, oldPim, oldBound) = (_salt, _format, _params, _pim, _deviceBound);
            _key = newKey;
            (_salt, _format, _params, _pim, _deviceBound) = (newSalt, newFormat, newParams, newPim, bound);
            try
            {
                SaveCore();
            }
            catch
            {
                _key = oldKey;
                (_salt, _format, _params, _pim, _deviceBound) = (oldSalt, oldFormat, oldParams, oldPim, oldBound);
                newKey.Dispose();
                throw;
            }
            oldKey?.Dispose();
        }
    }

    /// <summary>Changes the vault PIM (requires the password; the current PIM is implied by the unlocked state). Re-encrypts with the new PIM. Works on v6/v7 vaults.</summary>
    public void ChangePim(string masterPassword, int newPim)
    {
        if (!FormatUsesPim(_format)) throw new InvalidOperationException("This vault does not use a PIM.");
        ValidatePim(_format, newPim);
        ReKey(masterPassword, masterPassword, _format, _params, newPim, _deviceBound);
    }

    // ---------------- header backup ----------------

    /// <summary>Writes an encrypted header backup (format, parameters, salt). Protected by the master password with its own salt; externally it looks like random bytes. For v5/v6/v7 vaults (backup v5, 324 B) the key is derived with the vault's own Argon2id parameters × PIM – as costly to attack as the vault itself; v3/v4 vaults keep the legacy 316 B backup.</summary>
    public void ExportHeaderBackup(string backupPath, string masterPassword)
    {
        if (!VerifyPassword(masterPassword)) throw new WrongPasswordException();

        Format format;
        Argon2Params? p;
        byte[] salt;
        bool bound;
        int pim;
        lock (_gate)
        {
            ThrowIfLocked();
            (format, p, salt, bound, pim) = (_format, _params, (byte[])_salt.Clone(), IsDeviceBound, _pim);
        }

        var plain = new byte[HeaderPlainSize];
        plain[0] = (byte)format;
        BinaryPrimitives.WriteInt32LittleEndian(plain.AsSpan(1), FormatParameter(format, p));
        salt.CopyTo(plain, 5);
        RandomNumberGenerator.Fill(plain.AsSpan(5 + SaltSize));
        if (FormatHasParams(format))
        {
            plain[5 + SaltSize] = (byte)p!.Passes;
            plain[6 + SaltSize] = (byte)p.Lanes;
            plain[7 + SaltSize] = (byte)(bound ? FlagDeviceBound : 0); // flags (v7)
        }

        var backupSalt = EntropyPool.GetBytes(SaltSize); // OS CSPRNG + user entropy
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] output;
        byte[] backupKey;
        byte[] aad;
        int prefix; // bytes before the nonce
        if (FormatHasParams(format))
        {
            // v5 backup: the vault's own Argon2id parameters × PIM (no device binding – the backup must still
            // open after moving to another PC); the parameters are stored masked and authenticated in the AAD
            output = new byte[HeaderBackupSizeV5];
            prefix = SaltSize + ParamsBlockSize;
            MaskedParams(backupSalt, p!, 0, BackupParamsMaskLabel).CopyTo(output, SaltSize);
            backupKey = DeriveHeaderBackupKeyV5(masterPassword, backupSalt, p!, pim);
            aad = HeaderBackupAadV5(p!);
        }
        else
        {
            output = new byte[HeaderBackupSize];
            prefix = SaltSize;
            backupKey = DeriveKey(format, masterPassword, backupSalt, null, 0, null);
            aad = HeaderBackupAad(format);
        }
        try
        {
            using var aes = new AesGcm(backupKey, TagSize);
            aes.Encrypt(nonce, plain,
                output.AsSpan(prefix + NonceSize, HeaderPlainSize),
                output.AsSpan(output.Length - TagSize),
                aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            SecureMemory.Wipe(backupKey);
        }
        backupSalt.CopyTo(output, 0);
        nonce.CopyTo(output, prefix);
        DurableFile.WriteAllBytes(backupPath, output);
    }

    /// <summary>Key of a v5 header backup: Argon2id with the vault's parameters, passes × PIM (a vault without a PIM counts as PIM 1).</summary>
    private static byte[] DeriveHeaderBackupKeyV5(string password, byte[] backupSalt, Argon2Params p, int pim) =>
        DeriveKeyArgon2(password, backupSalt, EffectivePimParams(p, Math.Max(pim, MinPim)), HkdfInfoHeaderBackupV5, KeySize);

    /// <summary>AAD of a v5 header backup: label + the (unmasked) parameters.</summary>
    private static byte[] HeaderBackupAadV5(Argon2Params p) => AadHeaderBackupV5.Concat(RawParams(p, 0)).ToArray();

    /// <summary>The primary KDF parameter stored in a header backup (memory for Argon2, iterations for PBKDF2).</summary>
    private static int FormatParameter(Format f, Argon2Params? p) => f switch
    {
        Format.V7 or Format.V6 or Format.V5 => p!.MemoryKiB,
        Format.V4 => Argon2MemoryKiB,
        Format.V3 => Pbkdf2Iterations,
        _ => V2Iterations
    };

    /// <summary>AAD selector for a header backup of the given format.</summary>
    private static byte[] HeaderBackupAad(Format f) => f switch
    {
        Format.V7 or Format.V6 or Format.V5 => AadHeaderBackupV4,
        Format.V4 => AadHeaderBackupV3,
        Format.V3 => AadHeaderBackupV2,
        _ => AadHeaderBackupV1
    };

    /// <summary>Decrypted contents of a header backup: format, key-derivation parameters, flags and salt.</summary>
    private sealed record HeaderBackupInfo(Format HeaderFormat, Argon2Params? Params, byte Flags, byte[] Salt)
    {
        /// <summary>True for a v7 backup of a device-bound vault.</summary>
        public bool DeviceBound => HeaderFormat == Format.V7 && (Flags & FlagDeviceBound) != 0;
    }

    /// <summary>Decrypts a header backup with the master password (and, for a v5 backup, the PIM), trying every supported backup format. Throws <see cref="WrongPasswordException"/> (wrong password/PIM or not a header backup) or <see cref="InvalidDataException"/>.</summary>
    private static HeaderBackupInfo ReadHeaderBackup(string backupPath, string masterPassword, int pim)
    {
        var backup = File.ReadAllBytes(backupPath);
        var plain = backup.Length switch
        {
            HeaderBackupSizeV5 => DecryptHeaderBackupV5(backup, masterPassword, pim),
            HeaderBackupSize => DecryptLegacyHeaderBackup(backup, masterPassword),
            _ => throw new InvalidDataException("The selected file is not a header backup.")
        };

        try
        {
            var format = (Format)plain[0];
            if (format is not (Format.V2 or Format.V3 or Format.V4 or Format.V5 or Format.V6 or Format.V7))
                throw new InvalidDataException("Unsupported header backup version.");

            Argon2Params? p = null;
            byte flags = 0;
            if (FormatHasParams(format))
            {
                p = new Argon2Params(BinaryPrimitives.ReadInt32LittleEndian(plain.AsSpan(1)),
                                     plain[5 + SaltSize], plain[6 + SaltSize]);
                if (!p.IsPlausible) throw new InvalidDataException("The header backup has invalid parameters.");
                flags = (byte)(plain[7 + SaltSize] & KnownFlags);
            }
            else if (BinaryPrimitives.ReadInt32LittleEndian(plain.AsSpan(1)) != FormatParameter(format, null))
                throw new InvalidDataException("The header backup has incompatible parameters.");

            return new HeaderBackupInfo(format, p, flags, plain.AsSpan(5, SaltSize).ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>Decrypts a v5 header backup (vault parameters × PIM). Throws WrongPassword on a wrong password/PIM.</summary>
    private static byte[] DecryptHeaderBackupV5(byte[] backup, string masterPassword, int pim)
    {
        if (!Argon2Kdf.IsAvailable) throw new InvalidDataException("This header backup needs Argon2id, which is not available here.");
        if (pim > MaxPim) throw new WrongPasswordException();

        var backupSalt = backup[..SaltSize];
        var mask = ParamsMask(backupSalt, BackupParamsMaskLabel);
        var block = new byte[ParamsBlockSize];
        for (int i = 0; i < ParamsBlockSize; i++) block[i] = (byte)(backup[SaltSize + i] ^ mask[i]);
        var p = new Argon2Params(BinaryPrimitives.ReadInt32LittleEndian(block),
                                 BinaryPrimitives.ReadUInt16LittleEndian(block.AsSpan(4)), block[6]);
        if (block[7] != 0 || !p.IsPlausible) throw new InvalidDataException("The selected file is not a header backup.");

        int prefix = SaltSize + ParamsBlockSize;
        var nonce = backup[prefix..(prefix + NonceSize)];
        var cipher = backup[(prefix + NonceSize)..^TagSize];
        var tag = backup[^TagSize..];
        var key = DeriveHeaderBackupKeyV5(masterPassword, backupSalt, p, pim);
        try { return Decrypt(key, nonce, cipher, tag, HeaderBackupAadV5(p)); }
        finally { SecureMemory.Wipe(key); }
    }

    /// <summary>Decrypts a legacy (316 B) header backup, trying each old backup KDF/AAD.</summary>
    private static byte[] DecryptLegacyHeaderBackup(byte[] backup, string masterPassword)
    {
        var backupSalt = backup[..SaltSize];
        var nonce = backup[SaltSize..(SaltSize + NonceSize)];
        var cipher = backup[(SaltSize + NonceSize)..^TagSize];
        var tag = backup[^TagSize..];

        // (backup KDF, AAD) – the old v5/v6/v7 and v4 backups use the same key (Argon2id 64 MiB/3/4)
        var attempts = new List<(Format Kdf, byte[] Aad)>();
        if (Argon2Kdf.IsAvailable)
        {
            attempts.Add((Format.V4, AadHeaderBackupV4));
            attempts.Add((Format.V4, AadHeaderBackupV3));
        }
        attempts.Add((Format.V3, AadHeaderBackupV2));
        attempts.Add((Format.V2, AadHeaderBackupV1));

        byte[]? cachedKey = null;
        Format cachedKdf = 0;
        try
        {
            foreach (var (kdf, aad) in attempts)
            {
                if (cachedKey is null || cachedKdf != kdf)
                {
                    SecureMemory.Wipe(cachedKey);
                    cachedKey = DeriveKey(kdf, masterPassword, backupSalt, null, 0, null);
                    cachedKdf = kdf;
                }
                var attemptKey = (byte[])cachedKey.Clone();
                try { return Decrypt(attemptKey, nonce, cipher, tag, aad); }
                catch (WrongPasswordException) { }
                finally { CryptographicOperations.ZeroMemory(attemptKey); }
            }
            throw new WrongPasswordException();
        }
        finally
        {
            SecureMemory.Wipe(cachedKey);
        }
    }

    /// <summary>A copy of the vault file with its header (salt + parameters) replaced by the one from the backup.</summary>
    private static byte[] WithBackupHeader(byte[] vault, HeaderBackupInfo b)
    {
        int header = HeaderLength(b.HeaderFormat);
        if (vault.Length < header + NonceSize + TagSize + 4)
            throw new InvalidDataException("The vault file is too badly damaged.");
        var repaired = (byte[])vault.Clone();
        b.Salt.CopyTo(repaired, 0);
        if (FormatHasParams(b.HeaderFormat)) MaskedParams(b.Salt, b.Params!, b.Flags).CopyTo(repaired, SaltSize);
        return repaired;
    }

    /// <summary>Whether the vault bytes open with the backup's format/parameters and this password + PIM. Nothing is written.</summary>
    private static bool OpensWith(string vaultPath, byte[] bytes, HeaderBackupInfo b, string masterPassword, int pim)
    {
        var device = DeviceSecretFor(b.HeaderFormat, b.DeviceBound);
        try
        {
            using (OpenBinary(vaultPath, bytes, masterPassword, b.HeaderFormat, b.Params,
                       FormatUsesPim(b.HeaderFormat) ? pim : 0, b.Flags, device)) { }
            return true;
        }
        catch (WrongPasswordException)
        {
            return false;
        }
    }

    /// <summary>Restores the vault header from a backup. Before writing, it verifies the vault actually opens with the restored header. Keeps the original as *.before-restore. Supports backups from formats v7 down to v2.</summary>
    public static void RestoreHeader(string vaultPath, string backupPath, string masterPassword, int pim = 0)
    {
        var b = ReadHeaderBackup(backupPath, masterPassword, pim);
        var repaired = WithBackupHeader(File.ReadAllBytes(vaultPath), b);
        if (!OpensWith(vaultPath, repaired, b, masterPassword, pim))
            throw new InvalidDataException(
                "The backup does not belong to this vault, or the vault content is damaged too (not just the header).");

        DurableFile.WriteAllBytes(vaultPath + ".before-restore", File.ReadAllBytes(vaultPath));
        DurableFile.ReplaceAtomically(vaultPath, repaired);
        WriteChecksum(vaultPath, repaired);
    }

    /// <summary>Result of a read-only header check (see <see cref="CheckHeader"/>).</summary>
    public sealed record HeaderCheckReport(
        int BackupFormat,
        string BackupKdf,
        bool BackupDeviceBound,
        bool NeedsDeviceKey,
        bool VaultTooDamaged,
        bool HeaderMatchesBackup,
        bool VaultOpens,
        int? VaultFormat,
        bool BackupRepairsVault,
        ChecksumStatus Checksum);

    /// <summary>VeraCrypt-style header check that changes nothing: verifies the backup opens with the password, whether the vault opens with its current header, whether that header is identical to the backup, and whether restoring from the backup would make the vault open. Throws <see cref="WrongPasswordException"/> when the backup does not open with the password.</summary>
    public static HeaderCheckReport CheckHeader(string vaultPath, string backupPath, string masterPassword, int pim = 0)
    {
        var b = ReadHeaderBackup(backupPath, masterPassword, pim);
        var vault = File.ReadAllBytes(vaultPath);
        var checksum = VerifyChecksum(vaultPath, vault);
        bool needsDeviceKey = b.DeviceBound && DeviceKeyStore.Current() is null;

        byte[]? repaired = null;
        try { repaired = WithBackupHeader(vault, b); }
        catch (InvalidDataException) { }
        int header = HeaderLength(b.HeaderFormat);
        bool matches = repaired is not null && vault.AsSpan(0, header).SequenceEqual(repaired.AsSpan(0, header));

        bool opens = false;
        int? openedFormat = null;
        try
        {
            using var current = OpenBinaryAny(vaultPath, vault, masterPassword, pim, allowUpgrade: false);
            opens = true;
            openedFormat = current.FormatVersion;
        }
        catch (Exception ex) when (ex is WrongPasswordException or InvalidDataException) { }

        bool repairs = matches ? opens : false;
        if (!matches && repaired is not null && !needsDeviceKey)
        {
            try { repairs = OpensWith(vaultPath, repaired, b, masterPassword, pim); }
            catch (InvalidDataException) { }
        }

        return new HeaderCheckReport((int)b.HeaderFormat, DescribeKdf(b.HeaderFormat, b.Params), b.DeviceBound,
            needsDeviceKey, repaired is null, matches, opens, openedFormat, repairs, checksum);
    }

    /// <summary>Human-readable key derivation of a format (as stored in a header backup); the PIM is not shown.</summary>
    private static string DescribeKdf(Format f, Argon2Params? p) => f switch
    {
        Format.V7 or Format.V6 => p!.ToString() + " × PIM",
        Format.V5 => p!.ToString(),
        Format.V4 => Argon2Params.Floor.ToString(),
        Format.V3 => "PBKDF2-HMAC-SHA512, 1,000,000 iterations",
        _ => "PBKDF2-HMAC-SHA256, 2,000,000 iterations"
    };

    // ---------------- file checksum: detects changes made outside Phrasia ----------------
    // After every write Phrasia stores HMAC-SHA256(device key, whole vault file) in *.sum. The vault itself is
    // authenticated by AES-GCM/ChaCha20-Poly1305 (any change makes it fail to open), but that needs the password;
    // the checksum also tells that the file was edited, damaged or replaced (e.g. by an older copy) since Phrasia
    // last saved it. Keyed with the device secret, so it cannot simply be recomputed by someone else.

    /// <summary>Result of comparing the vault file with the checksum stored when Phrasia last saved it.</summary>
    public enum ChecksumStatus
    {
        /// <summary>The file is exactly what Phrasia last saved.</summary>
        Unchanged,
        /// <summary>The file was changed, damaged or replaced outside Phrasia.</summary>
        Changed,
        /// <summary>No checksum yet (older version, first run) or it cannot be verified on this computer.</summary>
        Missing
    }

    private static readonly byte[] ChecksumMagic = "PHRSUM1\0"u8.ToArray();
    private static readonly byte[] ChecksumInfo = "Phrasia vault file checksum v1"u8.ToArray();
    private const byte ChecksumPlain = 0, ChecksumKeyed = 1;

    /// <summary>Path of the checksum file next to the vault.</summary>
    public static string ChecksumPath(string vaultPath) => vaultPath + ".sum";

    /// <summary>Stores the checksum of the vault file (read from disk when <paramref name="content"/> is null). Never throws –
    /// a missing checksum only means the next check reports "no checksum yet".</summary>
    public static void WriteChecksum(string vaultPath, byte[]? content = null)
    {
        try
        {
            content ??= File.ReadAllBytes(vaultPath);
            var mac = ComputeChecksum(content, out byte mode);
            var data = new byte[ChecksumMagic.Length + 1 + mac.Length];
            ChecksumMagic.CopyTo(data, 0);
            data[ChecksumMagic.Length] = mode;
            mac.CopyTo(data, ChecksumMagic.Length + 1);
            File.WriteAllBytes(ChecksumPath(vaultPath), data);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException) { }
    }

    /// <summary>Compares the vault file (read from disk when <paramref name="content"/> is null) with its stored checksum.</summary>
    public static ChecksumStatus VerifyChecksum(string vaultPath, byte[]? content = null)
    {
        try
        {
            var sumPath = ChecksumPath(vaultPath);
            if (!File.Exists(sumPath) || !File.Exists(vaultPath)) return ChecksumStatus.Missing;
            var data = File.ReadAllBytes(sumPath);
            int macOffset = ChecksumMagic.Length + 1;
            if (data.Length != macOffset + 32 || !data.AsSpan(0, ChecksumMagic.Length).SequenceEqual(ChecksumMagic))
                return ChecksumStatus.Changed; // the checksum file itself was damaged or replaced
            content ??= File.ReadAllBytes(vaultPath);
            var mac = ComputeChecksum(content, out byte mode);
            if (mode != data[ChecksumMagic.Length])
                return ChecksumStatus.Missing; // made with/without the device key – cannot be compared here
            return CryptographicOperations.FixedTimeEquals(mac, data.AsSpan(macOffset))
                ? ChecksumStatus.Unchanged
                : ChecksumStatus.Changed;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return ChecksumStatus.Missing;
        }
    }

    /// <summary>HMAC-SHA256 keyed by the device secret (via HKDF), or plain SHA-256 where no device secret exists.</summary>
    private static byte[] ComputeChecksum(ReadOnlySpan<byte> content, out byte mode)
    {
        var device = DeviceKeyStore.Current();
        if (device is null)
        {
            mode = ChecksumPlain;
            return SHA256.HashData(content);
        }
        mode = ChecksumKeyed;
        var key = new byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, device, key, Array.Empty<byte>(), ChecksumInfo);
        try { return HMACSHA256.HashData(key, content); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    // ---------------- secure delete ----------------

    /// <summary>Securely erases the vault and its working files (*.tmp, *.before-restore): content is overwritten twice with random data (flushed to disk), truncated to 0 B, renamed to a random name, then deleted. Returns the number of deleted files.</summary>
    public static int SecureDelete(string vaultPath)
    {
        int count = 0;
        foreach (var file in new[] { vaultPath, vaultPath + ".tmp", vaultPath + ".before-restore", ChecksumPath(vaultPath) })
        {
            if (!File.Exists(file)) continue;
            SecureDeleteFile(file);
            count++;
        }
        return count;
    }

    /// <summary>Overwrites a file with random data (flushed to disk), truncates, renames, then deletes it.</summary>
    public static void SecureDeleteFile(string path, int passes = 2)
    {
        var info = new FileInfo(path);
        if (info.IsReadOnly) info.IsReadOnly = false;
        long length = info.Length;

        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None,
                                       bufferSize: 1, FileOptions.WriteThrough))
        {
            var buffer = new byte[64 * 1024];
            for (int pass = 0; pass < passes; pass++)
            {
                fs.Position = 0;
                long remaining = length;
                while (remaining > 0)
                {
                    int n = (int)Math.Min(buffer.Length, remaining);
                    RandomNumberGenerator.Fill(buffer.AsSpan(0, n));
                    fs.Write(buffer, 0, n);
                    remaining -= n;
                }
                fs.Flush(flushToDisk: true);
            }
            fs.SetLength(0);
            fs.Flush(flushToDisk: true);
            CryptographicOperations.ZeroMemory(buffer);
        }

        // random name – the original name does not remain in the file-system record
        var dir = Path.GetDirectoryName(Path.GetFullPath(path))!;
        var renamed = Path.Combine(dir, Convert.ToHexString(RandomNumberGenerator.GetBytes(8)));
        File.Move(path, renamed);
        File.Delete(renamed);
    }

    // ---------------- backup import ----------------

    /// <summary>Reads entries from a vault backup (*.pgv) without modifying it (a temporary copy is opened – an old format would otherwise be rewritten on open).</summary>
    public static List<VaultEntry> ReadEntriesFromBackup(string backupPath, string masterPassword, int pim = 0)
    {
        var tmp = Path.Combine(Path.GetTempPath(), "pgv-import-" + Guid.NewGuid().ToString("N") + ".pgv");
        File.Copy(backupPath, tmp);
        try
        {
            using var v = Open(tmp, masterPassword, pim);
            return v.Entries.ToList();
        }
        finally
        {
            TryDelete(tmp);
            TryDelete(tmp + ".tmp");
        }
    }

    /// <summary>Replaces the vault with a backup. First verifies the backup password; keeps the current vault (if any) as *.before-restore.</summary>
    public static void RestoreFromBackup(string vaultPath, string backupPath, string masterPassword, int pim = 0)
    {
        if (Path.GetFullPath(vaultPath).Equals(Path.GetFullPath(backupPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The selected file is the vault itself, not a backup.");

        ReadEntriesFromBackup(backupPath, masterPassword, pim); // verifies the backup password and integrity

        Directory.CreateDirectory(Path.GetDirectoryName(vaultPath)!);
        if (File.Exists(vaultPath))
            DurableFile.WriteAllBytes(vaultPath + ".before-restore", File.ReadAllBytes(vaultPath));
        var restored = File.ReadAllBytes(backupPath);
        DurableFile.ReplaceAtomically(vaultPath, restored);
        WriteChecksum(vaultPath, restored);
    }

    /// <summary>Merges entries (e.g. from a backup) into the vault. An entry with the same Id is overwritten only if the backup's is newer. Does not save – the caller calls Save().</summary>
    public (int Added, int Updated, int Skipped) Merge(IEnumerable<VaultEntry> items)
    {
        int added = 0, updated = 0, skipped = 0;
        foreach (var item in items)
        {
            var existing = Entries.FirstOrDefault(e => e.Id == item.Id);
            if (existing is null)
            {
                Entries.Add(item);
                added++;
            }
            else if (item.Modified > existing.Modified)
            {
                existing.Title = item.Title;
                existing.Username = item.Username;
                existing.Password = item.Password;
                existing.Url = item.Url;
                existing.Note = item.Note;
                existing.Critical = item.Critical;
                existing.PasswordChanged = item.PasswordChanged;
                existing.Modified = item.Modified;
                updated++;
            }
            else skipped++;
        }
        return (added, updated, skipped);
    }

    /// <summary>Deletes a file, ignoring I/O and access errors.</summary>
    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>Locks the vault: wipes the protected key from memory. Waits for an in-progress save/re-key to finish (milliseconds), so the vault file is never left half re-keyed.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _key?.Dispose();
            _key = null;
        }
    }

    /// <summary>Error for operations on a locked (disposed) vault.</summary>
    private static ObjectDisposedException LockedError() => new(nameof(Vault), "The vault is locked.");

    /// <summary>Throws if the vault has been locked. The caller must hold <see cref="_gate"/>.</summary>
    private void ThrowIfLocked()
    {
        if (_disposed || _key is null) throw LockedError();
    }

    // ---------------- key derivation ----------------

    /// <summary>Array in pinned, locked (VirtualLock) memory – the GC does not move it and it is not paged to disk.</summary>
    private static byte[] Pinned(int size) => SecureMemory.AllocLocked(size);

    // ikm (optional): a provider of a cached Argon2 output – when opening, it avoids recomputing Argon2
    // across formats with the same parameters (v7/v6). When null, Argon2 is computed directly.
    /// <summary>Derives the encryption key for a format (optionally via a cached Argon2 ikm provider).</summary>
    private static byte[] DeriveKey(Format format, string password, byte[] salt, Argon2Params? p, int pim, byte[]? deviceSecret,
        Func<Argon2Params, byte[]>? ikm = null) => format switch
    {
        Format.V7 => DeriveKeyV7(password, salt, EffectivePimParams(p, pim), deviceSecret, ikm),
        Format.V6 => DeriveKeyArgon2(password, salt, EffectivePimParams(p, pim), HkdfInfoV6, KeySize, ikm),
        Format.V5 => DeriveKeyArgon2(password, salt, p ?? throw new ArgumentNullException(nameof(p)), HkdfInfoV5, KeySize, ikm),
        Format.V4 => DeriveKeyArgon2(password, salt, Argon2Params.Floor, HkdfInfoV4, KeySize, ikm),
        Format.V3 => DeriveKeyV3(password, salt),
        _ => DeriveKeyV2(password, salt)
    };

    /// <summary>v6/v7: effective passes = stored (calibrated) × PIM. The PIM is secret and not stored in the file.</summary>
    private static Argon2Params EffectivePimParams(Argon2Params? p, int pim)
    {
        if (p is null) throw new ArgumentNullException(nameof(p));
        if (pim < MinPim || pim > MaxPim) throw new ArgumentOutOfRangeException(nameof(pim), "PIM out of range.");
        return p with { Passes = p.Passes * pim };
    }

    /// <summary>v7: Argon2id → (optionally mixed with the device secret) → HKDF → 64 B = two 32 B subkeys (AES-256-GCM + ChaCha20-Poly1305). The device secret binds the vault to this PC/account.</summary>
    private static byte[] DeriveKeyV7(string password, byte[] salt, Argon2Params eff, byte[]? deviceSecret,
        Func<Argon2Params, byte[]>? ikmProvider)
    {
        bool ownIkm = ikmProvider is null;
        var ikm = ikmProvider is not null ? ikmProvider(eff)
            : Argon2Kdf.Derive(password, salt, eff.MemoryKiB, eff.Passes, eff.Lanes, 64);
        byte[]? root = null;
        var key = Pinned(2 * KeySize); // 64 B
        try
        {
            if (deviceSecret is not null)
            {
                root = Pinned(64);
                HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, root, deviceSecret, HkdfInfoV7Device);
                HKDF.DeriveKey(HashAlgorithmName.SHA256, root, key, salt, HkdfInfoV7Keys);
            }
            else
            {
                HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, key, salt, HkdfInfoV7Keys);
            }
            return key;
        }
        finally
        {
            if (ownIkm) CryptographicOperations.ZeroMemory(ikm);
            SecureMemory.Wipe(root);
        }
    }

    /// <summary>v4/v5/v6: Argon2id (64 B) → HKDF-SHA256 with "info" → key in pinned memory.</summary>
    private static byte[] DeriveKeyArgon2(string password, byte[] salt, Argon2Params p, byte[] info, int keyLen,
        Func<Argon2Params, byte[]>? ikmProvider = null)
    {
        bool ownIkm = ikmProvider is null;
        var ikm = ikmProvider is not null ? ikmProvider(p)
            : Argon2Kdf.Derive(password, salt, p.MemoryKiB, p.Passes, p.Lanes, 64);
        var key = Pinned(keyLen);
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, key, salt, info);
            return key;
        }
        finally
        {
            if (ownIkm) CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>v3: PBKDF2-HMAC-SHA512 (1M iterations, 64 B) → HKDF-SHA256 with "info" → 32 B key for AES-256-GCM.</summary>
    private static byte[] DeriveKeyV3(string password, byte[] salt)
    {
        var ikm = Pinned(64);
        var key = Pinned(KeySize);
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(password.AsSpan(), salt, ikm, Pbkdf2Iterations, HashAlgorithmName.SHA512);
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, key, salt, HkdfInfoV3);
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>v2 (read-only legacy): PBKDF2-HMAC-SHA256, 2M iterations.</summary>
    private static byte[] DeriveKeyV2(string password, byte[] salt) => DerivePbkdf2Sha256(password, salt, V2Iterations);

    /// <summary>Legacy v2 key derivation: PBKDF2-HMAC-SHA256 with the given iteration count.</summary>
    private static byte[] DerivePbkdf2Sha256(string password, byte[] salt, int iterations)
    {
        var key = Pinned(KeySize);
        Rfc2898DeriveBytes.Pbkdf2(password.AsSpan(), salt, key, iterations, HashAlgorithmName.SHA256);
        return key;
    }

    /// <summary>JSON envelope of the legacy v1 vault format.</summary>
    private sealed class Envelope
    {
        public int Version { get; set; } = 1;
        public string Kdf { get; set; } = "PBKDF2-SHA256";
        public int Iterations { get; set; }
        public string Cipher { get; set; } = "AES-256-GCM";
        public string Salt { get; set; } = "";
        public string Nonce { get; set; } = "";
        public string Tag { get; set; } = "";
        public string Data { get; set; } = "";
    }
}
