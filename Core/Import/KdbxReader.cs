using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Konscious.Security.Cryptography;

namespace Phrasia;

/// <summary>The password / key file does not open the KeePass database (or the file is damaged at the very start).</summary>
public sealed class KeePassWrongKeyException : Exception
{
    public KeePassWrongKeyException()
        : base("The password or key file is wrong for this KeePass database.") { }
}

/// <summary>
/// Read-only decoder of KeePass 2 databases (.kdbx), written from the public KDBX specification:
///  - KDBX 3.1 and KDBX 4.0 / 4.1,
///  - key derivation AES-KDF, Argon2d, Argon2id,
///  - outer cipher AES-256-CBC or ChaCha20 (Twofish is a KeePass plugin and is not supported),
///  - inner-stream protection Salsa20 (3.x) or ChaCha20 (4.x),
///  - composite key: password and/or key file (XML 1.0 / 2.0, 32-byte binary, 64-hex, or any file hashed).
/// The result is the decrypted XML document with every protected value already decrypted in place.
/// Nothing is ever written back – Phrasia only imports from KeePass.
/// </summary>
internal static class KdbxReader
{
    private const uint Signature1 = 0x9AA2D903, Signature2 = 0xB54BFB67, SignatureKdb1 = 0xB54BFB65;

    /// <summary>Largest database accepted (encrypted file and decompressed XML) – protects against decompression bombs.</summary>
    internal const long MaxFileBytes = 512L * 1024 * 1024;
    internal const long MaxXmlBytes = 1024L * 1024 * 1024;

    /// <summary>Largest Argon2 memory cost accepted from a file (KeePass allows absurd values; this keeps the app alive).</summary>
    internal const ulong MaxArgon2MemoryBytes = 2UL * 1024 * 1024 * 1024;

    // KeePass UUIDs as stored in the file (RFC byte order – not .NET Guid byte order, so they are compared as bytes)
    private static readonly byte[] CipherAes256 = Convert.FromHexString("31c1f2e6bf714350be5805216afc5aff");
    private static readonly byte[] CipherChaCha20 = Convert.FromHexString("d6038a2b8b6f4cb5a524339a31dbb59a");
    private static readonly byte[] CipherTwofish = Convert.FromHexString("ad68f29f576f4bb9a36ad47af965346c");
    private static readonly byte[] KdfAes = Convert.FromHexString("c9d9f39a628a4460bf740d08c18a4fea");
    private static readonly byte[] KdfAesKdbx4 = Convert.FromHexString("7c02bb8279a74ac0927d114a00648238");
    private static readonly byte[] KdfArgon2d = Convert.FromHexString("ef636ddf8c29444b91f7a9a403e30a0c");
    private static readonly byte[] KdfArgon2id = Convert.FromHexString("9e298b1956db4773b23dfc3ec6f0a1e6");

    private static readonly byte[] Salsa20InnerNonce = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

    /// <summary>Summary of what the file contains besides the XML (for the import report).</summary>
    internal sealed record KdbxInfo(int MajorVersion, int MinorVersion, string Kdf, string Cipher);

    /// <summary>True if the bytes start with the KeePass 2 signature (used to sniff a file chosen with "All files").</summary>
    public static bool LooksLikeKdbx(ReadOnlySpan<byte> start) =>
        start.Length >= 8 && BinaryPrimitives.ReadUInt32LittleEndian(start) == Signature1;

    /// <summary>Builds the KeePass composite key: SHA-256 over SHA-256(password) ‖ key-file key (each only if present).</summary>
    public static byte[] CompositeKey(string? password, byte[]? keyFile)
    {
        if (password is null && keyFile is null)
            throw new ArgumentException("A password or a key file is required.");
        using var all = new MemoryStream();
        if (password is not null)
        {
            var pw = Encoding.UTF8.GetBytes(password);
            try { all.Write(SHA256.HashData(pw)); }
            finally { CryptographicOperations.ZeroMemory(pw); }
        }
        if (keyFile is not null)
        {
            var k = KeyFileKey(keyFile);
            try { all.Write(k); }
            finally { CryptographicOperations.ZeroMemory(k); }
        }
        var buffer = all.GetBuffer();
        try { return SHA256.HashData(buffer.AsSpan(0, (int)all.Length)); }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    /// <summary>Turns a KeePass key file into its 32-byte key (XML 2.0 / 1.0, raw 32 bytes, 64 hex digits, otherwise SHA-256 of the file).</summary>
    internal static byte[] KeyFileKey(byte[] file)
    {
        if (file.Length == 0) throw new InvalidDataException("The key file is empty.");

        // XML key file (KeePass 2.x)
        if (TryParseXmlKeyFile(file, out var xmlKey)) return xmlKey;

        if (file.Length == 32) return (byte[])file.Clone();

        if (file.Length == 64)
        {
            var text = Encoding.ASCII.GetString(file);
            if (text.All(Uri.IsHexDigit)) return Convert.FromHexString(text);
        }
        return SHA256.HashData(file);
    }

    /// <summary>Parses a KeePass XML key file (v1.0: base64 data; v2.0: hex data with a 4-byte SHA-256 check).</summary>
    private static bool TryParseXmlKeyFile(byte[] file, out byte[] key)
    {
        key = [];
        // quick check before involving the XML parser
        int probe = Math.Min(file.Length, 512);
        var head = Encoding.UTF8.GetString(file, 0, probe);
        if (!head.Contains("<KeyFile", StringComparison.Ordinal)) return false;
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(file), SafeXmlSettings);
            var doc = XDocument.Load(reader);
            var root = doc.Root;
            if (root is null || root.Name.LocalName != "KeyFile") return false;
            string version = root.Element("Meta")?.Element("Version")?.Value.Trim() ?? "1.0";
            var data = root.Element("Key")?.Element("Data");
            if (data is null) return false;

            if (version.StartsWith("2", StringComparison.Ordinal))
            {
                var hex = new string(data.Value.Where(c => !char.IsWhiteSpace(c)).ToArray());
                key = Convert.FromHexString(hex);
                var expected = (string?)data.Attribute("Hash");
                if (!string.IsNullOrEmpty(expected))
                {
                    var actual = Convert.ToHexString(SHA256.HashData(key).AsSpan(0, 4));
                    if (!string.Equals(actual, expected.Trim(), StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("The key file is damaged (its checksum does not match).");
                }
            }
            else
            {
                key = Convert.FromBase64String(data.Value.Trim());
            }
            return key.Length > 0;
        }
        catch (Exception ex) when (ex is XmlException or FormatException)
        {
            return false; // not a valid XML key file – KeePass then hashes the whole file
        }
    }

    /// <summary>XML reader settings without DTDs or external resolution (the file comes from outside).</summary>
    internal static XmlReaderSettings SafeXmlSettings => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreComments = true,
        CloseInput = true,
        MaxCharactersInDocument = MaxXmlBytes,
    };

    /// <summary>Decrypts a .kdbx file with the composite key and returns its XML (protected values decrypted).</summary>
    /// <exception cref="KeePassWrongKeyException">Wrong password / key file.</exception>
    /// <exception cref="InvalidDataException">Not a KeePass 2 file, unsupported variant, or damaged.</exception>
    public static (XDocument Document, KdbxInfo Info) Read(byte[] file, byte[] compositeKey)
    {
        if (file.Length < 12) throw new InvalidDataException("The file is too short to be a KeePass database.");
        var span = file.AsSpan();
        uint sig1 = BinaryPrimitives.ReadUInt32LittleEndian(span);
        uint sig2 = BinaryPrimitives.ReadUInt32LittleEndian(span[4..]);
        if (sig1 != Signature1)
            throw new InvalidDataException("This is not a KeePass database (.kdbx).");
        if (sig2 == SignatureKdb1)
            throw new InvalidDataException("KeePass 1.x databases (.kdb) are not supported. Open the file in KeePass 2 and save it as .kdbx, then import again.");
        if (sig2 != Signature2)
            throw new InvalidDataException("This is not a KeePass 2 database (.kdbx).");

        uint version = BinaryPrimitives.ReadUInt32LittleEndian(span[8..]);
        int major = (int)(version >> 16), minor = (int)(version & 0xFFFF);
        if (major is < 2 or > 4)
            throw new InvalidDataException($"KDBX version {major}.{minor} is not supported (supported: 3.1, 4.0, 4.1).");
        bool v4 = major >= 4;

        // ---- outer header ----
        int pos = 12;
        var fields = new Dictionary<byte, byte[]>();
        while (true)
        {
            if (pos + (v4 ? 5 : 3) > file.Length) throw Damaged();
            byte id = file[pos++];
            int size;
            if (v4) { size = BinaryPrimitives.ReadInt32LittleEndian(span[pos..]); pos += 4; }
            else { size = BinaryPrimitives.ReadUInt16LittleEndian(span[pos..]); pos += 2; }
            if (size < 0 || pos + size > file.Length) throw Damaged();
            var data = span.Slice(pos, size).ToArray();
            pos += size;
            if (id == 0) break;
            fields[id] = data;
        }
        int headerEnd = pos;

        var cipherId = Field(fields, 2, "cipher");
        string cipherName;
        if (cipherId.AsSpan().SequenceEqual(CipherAes256)) cipherName = "AES-256";
        else if (cipherId.AsSpan().SequenceEqual(CipherChaCha20)) cipherName = "ChaCha20";
        else if (cipherId.AsSpan().SequenceEqual(CipherTwofish))
            throw new InvalidDataException("This database is encrypted with Twofish (a KeePass plugin). In KeePass, switch the encryption to AES-256 or ChaCha20 (File › Database Settings › Security), save, and import again.");
        else throw new InvalidDataException("This database uses an unknown cipher.");

        uint compression = fields.TryGetValue(3, out var c) && c.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(c) : 0;
        if (compression > 1) throw new InvalidDataException("Unknown compression in the KeePass database.");
        var masterSeed = Field(fields, 4, "master seed");
        var iv = Field(fields, 7, "encryption IV");

        // ---- key derivation ----
        byte[] transformed;
        string kdfName;
        if (v4)
        {
            var kdf = ReadVariantDictionary(Field(fields, 11, "KDF parameters"));
            (transformed, kdfName) = DeriveKdbx4(kdf, compositeKey);
        }
        else
        {
            var seed = Field(fields, 5, "transform seed");
            var roundsBytes = Field(fields, 6, "transform rounds");
            if (roundsBytes.Length != 8) throw Damaged();
            ulong rounds = BinaryPrimitives.ReadUInt64LittleEndian(roundsBytes);
            transformed = AesKdf(compositeKey, seed, rounds);
            kdfName = $"AES-KDF ({rounds:N0} rounds)";
        }

        byte[] cipherKey = SHA256.HashData([.. masterSeed, .. transformed]);
        byte[] payload;
        IKdbxKeyStream? inner = null;
        int binaries = 0;
        try
        {
            if (v4)
            {
                byte[] hmacKey = SHA512.HashData([.. masterSeed, .. transformed, 1]);
                try
                {
                    if (headerEnd + 64 > file.Length) throw Damaged();
                    var header = span[..headerEnd];
                    if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(header), span.Slice(headerEnd, 32)))
                        throw new InvalidDataException("The KeePass database header is damaged (checksum mismatch).");
                    using (var h = new HMACSHA256(BlockKey(hmacKey, ulong.MaxValue)))
                    {
                        if (!CryptographicOperations.FixedTimeEquals(h.ComputeHash(header.ToArray()), span.Slice(headerEnd + 32, 32)))
                            throw new KeePassWrongKeyException();
                    }
                    var encrypted = ReadHmacBlocks(file, headerEnd + 64, hmacKey);
                    payload = Decrypt(cipherId, cipherKey, iv, encrypted, wrongKeyOnPadding: false);
                }
                finally { CryptographicOperations.ZeroMemory(hmacKey); }

                if (compression == 1) payload = Gunzip(payload);

                // ---- inner header (KDBX 4) ----
                int p = 0;
                uint streamId = 0;
                byte[]? streamKey = null;
                while (true)
                {
                    if (p + 5 > payload.Length) throw Damaged();
                    byte type = payload[p];
                    int size = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(p + 1));
                    p += 5;
                    if (size < 0 || p + size > payload.Length) throw Damaged();
                    var data = payload.AsSpan(p, size);
                    p += size;
                    if (type == 0) break;
                    if (type == 1 && size >= 4) streamId = BinaryPrimitives.ReadUInt32LittleEndian(data);
                    else if (type == 2) streamKey = data.ToArray();
                    else if (type == 3) binaries++;
                }
                inner = CreateInnerStream(streamId, streamKey);
                if (streamKey is not null) CryptographicOperations.ZeroMemory(streamKey);
                var xml = payload.AsSpan(p).ToArray();
                CryptographicOperations.ZeroMemory(payload);
                payload = xml;
            }
            else
            {
                var expectedStart = Field(fields, 9, "stream start bytes");
                var decrypted = Decrypt(cipherId, cipherKey, iv, span[headerEnd..].ToArray(), wrongKeyOnPadding: true);
                if (decrypted.Length < expectedStart.Length
                    || !CryptographicOperations.FixedTimeEquals(decrypted.AsSpan(0, expectedStart.Length), expectedStart))
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    throw new KeePassWrongKeyException();
                }
                payload = ReadHashedBlocks(decrypted, expectedStart.Length);
                CryptographicOperations.ZeroMemory(decrypted);
                if (compression == 1) payload = Gunzip(payload);

                uint streamId = fields.TryGetValue(10, out var sid) && sid.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(sid) : 0;
                byte[]? protectedKey = fields.TryGetValue(8, out var pk) ? pk : null;
                inner = CreateInnerStream(streamId, protectedKey);
            }

            var doc = ParseXml(payload);
            CryptographicOperations.ZeroMemory(payload);
            DecryptProtectedValues(doc, inner);
            if (binaries > 0) doc.Root?.SetAttributeValue("PhrasiaInnerBinaries", binaries);
            return (doc, new KdbxInfo(major, minor, kdfName, cipherName));
        }
        finally
        {
            inner?.Dispose();
            CryptographicOperations.ZeroMemory(cipherKey);
            CryptographicOperations.ZeroMemory(transformed);
        }
    }

    /// <summary>Parses XML bytes into a document with the safe reader settings.</summary>
    internal static XDocument ParseXml(byte[] xml)
    {
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(xml, writable: false), SafeXmlSettings);
            return XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException ex)
        {
            throw new InvalidDataException("The database contents are not valid KeePass XML: " + ex.Message, ex);
        }
    }

    /// <summary>Decrypts every element marked Protected="True" (Value and Binary) in document order with the inner stream.</summary>
    internal static void DecryptProtectedValues(XDocument doc, IKdbxKeyStream? inner)
    {
        foreach (var el in doc.Descendants())
        {
            var attr = el.Attribute("Protected");
            if (attr is null || !string.Equals(attr.Value, "True", StringComparison.OrdinalIgnoreCase)) continue;
            if (inner is null)
                throw new InvalidDataException("The file contains protected values but no inner-stream key.");
            byte[] data;
            try { data = Convert.FromBase64String(el.Value); }
            catch (FormatException) { throw Damaged(); }
            inner.Xor(data);
            el.Value = el.Name.LocalName == "Value" ? Encoding.UTF8.GetString(data) : Convert.ToBase64String(data);
            CryptographicOperations.ZeroMemory(data);
            attr.Remove();
        }
    }

    /// <summary>Inner random stream: 0 = none, 2 = Salsa20, 3 = ChaCha20 (1 = ArcFour variant, obsolete).</summary>
    private static IKdbxKeyStream? CreateInnerStream(uint id, byte[]? key)
    {
        switch (id)
        {
            case 0: return null;
            case 2:
                if (key is null) throw Damaged();
                var k = SHA256.HashData(key);
                try { return new KdbxSalsa20(k, Salsa20InnerNonce); }
                finally { CryptographicOperations.ZeroMemory(k); }
            case 3:
                if (key is null) throw Damaged();
                var h = SHA512.HashData(key);
                try { return new KdbxChaCha20(h.AsSpan(0, 32), h.AsSpan(32, 12)); }
                finally { CryptographicOperations.ZeroMemory(h); }
            default:
                throw new InvalidDataException("This database uses an obsolete inner protection (ArcFour). Save it once in a current KeePass and import again.");
        }
    }

    // ---------------- key derivation ----------------

    /// <summary>KDBX 4 key derivation from the variant dictionary (AES-KDF, Argon2d, Argon2id).</summary>
    private static (byte[] Key, string Name) DeriveKdbx4(Dictionary<string, byte[]> p, byte[] compositeKey)
    {
        if (!p.TryGetValue("$UUID", out var uuid) || uuid.Length != 16) throw Damaged();

        if (uuid.AsSpan().SequenceEqual(KdfAes) || uuid.AsSpan().SequenceEqual(KdfAesKdbx4))
        {
            var seed = Need(p, "S");
            ulong rounds = BinaryPrimitives.ReadUInt64LittleEndian(Need(p, "R"));
            return (AesKdf(compositeKey, seed, rounds), $"AES-KDF ({rounds:N0} rounds)");
        }
        bool isId = uuid.AsSpan().SequenceEqual(KdfArgon2id);
        if (!isId && !uuid.AsSpan().SequenceEqual(KdfArgon2d))
            throw new InvalidDataException("This database uses an unknown key-derivation function.");

        var salt = Need(p, "S");
        uint lanes = BinaryPrimitives.ReadUInt32LittleEndian(Need(p, "P"));
        ulong memoryBytes = BinaryPrimitives.ReadUInt64LittleEndian(Need(p, "M"));
        ulong iterations = BinaryPrimitives.ReadUInt64LittleEndian(Need(p, "I"));
        uint version = p.TryGetValue("V", out var v) && v.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(v) : 0x13;
        if (version != 0x13)
            throw new InvalidDataException($"Argon2 version 0x{version:X} is not supported (only 1.3 / 0x13). Re-save the database in a current KeePass.");
        if (memoryBytes > MaxArgon2MemoryBytes)
            throw new InvalidDataException($"The database asks for {memoryBytes / (1024 * 1024):N0} MiB of Argon2 memory – more than Phrasia allows for an import ({MaxArgon2MemoryBytes / (1024 * 1024):N0} MiB).");
        if (lanes is < 1 or > 255 || iterations is < 1 or > int.MaxValue || memoryBytes < 8 * 1024)
            throw Damaged();

        Argon2 argon = isId ? new Argon2id(compositeKey) : new Argon2d(compositeKey);
        try
        {
            argon.Salt = salt;
            argon.DegreeOfParallelism = (int)lanes;
            argon.MemorySize = (int)(memoryBytes / 1024);
            argon.Iterations = (int)iterations;
            if (p.TryGetValue("K", out var secret) && secret.Length > 0) argon.KnownSecret = secret;
            if (p.TryGetValue("A", out var ad) && ad.Length > 0) argon.AssociatedData = ad;
            var key = argon.GetBytes(32);
            return (key, $"{(isId ? "Argon2id" : "Argon2d")} ({memoryBytes / (1024 * 1024):N0} MiB, {iterations} it., {lanes} lanes)");
        }
        finally { argon.Dispose(); }
    }

    /// <summary>AES-KDF: encrypts the composite key with AES-256-ECB (key = seed) <paramref name="rounds"/> times, then SHA-256.</summary>
    internal static byte[] AesKdf(byte[] compositeKey, byte[] seed, ulong rounds)
    {
        if (seed.Length != 32) throw Damaged();
        using var aes = Aes.Create();
        aes.Key = seed;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        var buf = (byte[])compositeKey.Clone();
        var tmp = new byte[32];
        try
        {
            using var enc = aes.CreateEncryptor();
            for (ulong i = 0; i < rounds; i++)
            {
                enc.TransformBlock(buf, 0, 32, tmp, 0);
                (buf, tmp) = (tmp, buf);
            }
            return SHA256.HashData(buf);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buf);
            CryptographicOperations.ZeroMemory(tmp);
        }
    }

    // ---------------- body ----------------

    /// <summary>Decrypts the body: AES-256-CBC (PKCS#7) or ChaCha20.</summary>
    private static byte[] Decrypt(byte[] cipher, byte[] key, byte[] iv, byte[] data, bool wrongKeyOnPadding)
    {
        if (cipher.AsSpan().SequenceEqual(CipherChaCha20))
        {
            if (iv.Length != 12) throw Damaged();
            using var cc = new KdbxChaCha20(key, iv);
            cc.Xor(data);
            return data;
        }
        if (iv.Length != 16 || data.Length % 16 != 0) throw Damaged();
        using var aes = Aes.Create();
        aes.Key = key;
        try
        {
            return aes.DecryptCbc(data, iv, PaddingMode.PKCS7);
        }
        catch (CryptographicException)
        {
            // KDBX 3: a wrong key shows up as bad padding; KDBX 4 has already verified the key via the header HMAC
            if (wrongKeyOnPadding) throw new KeePassWrongKeyException();
            throw Damaged();
        }
    }

    /// <summary>KDBX 4 HMAC block stream: [HMAC 32][size 4][data]…, ends with a size-0 block.</summary>
    private static byte[] ReadHmacBlocks(byte[] file, int pos, byte[] hmacKey)
    {
        using var output = new MemoryStream();
        Span<byte> prefix = stackalloc byte[12];
        for (ulong index = 0; ; index++)
        {
            if (pos + 36 > file.Length) throw Damaged();
            var mac = file.AsSpan(pos, 32);
            int size = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(pos + 32));
            pos += 36;
            if (size < 0 || pos + size > file.Length) throw Damaged();

            BinaryPrimitives.WriteUInt64LittleEndian(prefix, index);
            BinaryPrimitives.WriteInt32LittleEndian(prefix[8..], size);
            var blockKey = BlockKey(hmacKey, index);
            using (var h = new HMACSHA256(blockKey))
            {
                h.TransformBlock(prefix.ToArray(), 0, 12, null, 0);
                h.TransformFinalBlock(file, pos, size);
                if (!CryptographicOperations.FixedTimeEquals(h.Hash, mac))
                    throw new InvalidDataException("The KeePass database is damaged (block " + index + " failed its integrity check).");
            }
            CryptographicOperations.ZeroMemory(blockKey);
            if (size == 0) break;
            output.Write(file, pos, size);
            pos += size;
            if (output.Length > MaxFileBytes) throw TooLarge();
        }
        return output.ToArray();
    }

    /// <summary>HMAC key of one block: SHA-512(index ‖ HMAC base key).</summary>
    private static byte[] BlockKey(byte[] hmacKey, ulong index)
    {
        var buf = new byte[8 + hmacKey.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, index);
        hmacKey.CopyTo(buf, 8);
        try { return SHA512.HashData(buf); }
        finally { CryptographicOperations.ZeroMemory(buf); }
    }

    /// <summary>KDBX 3 hashed block stream: [index 4][SHA-256 32][size 4][data]…, ends with a size-0 block.</summary>
    private static byte[] ReadHashedBlocks(byte[] data, int pos)
    {
        using var output = new MemoryStream();
        while (true)
        {
            if (pos + 40 > data.Length) throw Damaged();
            var hash = data.AsSpan(pos + 4, 32);
            int size = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(pos + 36));
            pos += 40;
            if (size < 0 || pos + size > data.Length) throw Damaged();
            if (size == 0) break;
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(data.AsSpan(pos, size)), hash))
                throw new InvalidDataException("The KeePass database is damaged (a block failed its integrity check).");
            output.Write(data, pos, size);
            pos += size;
        }
        return output.ToArray();
    }

    /// <summary>GZip decompression with a size limit.</summary>
    private static byte[] Gunzip(byte[] data)
    {
        using var output = new MemoryStream();
        try
        {
            using var gz = new GZipStream(new MemoryStream(data, writable: false), CompressionMode.Decompress);
            var buffer = new byte[81920];
            int n;
            while ((n = gz.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, n);
                if (output.Length > MaxXmlBytes) break;
            }
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidDataException("The KeePass database is damaged (decompression failed).", ex);
        }
        if (output.Length > MaxXmlBytes) throw TooLarge();
        CryptographicOperations.ZeroMemory(data);
        return output.ToArray();
    }

    // ---------------- helpers ----------------

    /// <summary>KDBX 4 VariantDictionary → name/raw value bytes.</summary>
    internal static Dictionary<string, byte[]> ReadVariantDictionary(byte[] data)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (data.Length < 2) throw Damaged();
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(data);
        if ((version & 0xFF00) > 0x0100) throw new InvalidDataException("Unsupported KDF parameter format.");
        int pos = 2;
        while (pos < data.Length)
        {
            byte type = data[pos++];
            if (type == 0) return result;
            if (pos + 4 > data.Length) throw Damaged();
            int nameLen = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(pos)); pos += 4;
            if (nameLen < 0 || pos + nameLen + 4 > data.Length) throw Damaged();
            string name = Encoding.UTF8.GetString(data, pos, nameLen); pos += nameLen;
            int valueLen = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(pos)); pos += 4;
            if (valueLen < 0 || pos + valueLen > data.Length) throw Damaged();
            result[name] = data.AsSpan(pos, valueLen).ToArray();
            pos += valueLen;
        }
        throw Damaged();
    }

    private static byte[] Field(Dictionary<byte, byte[]> fields, byte id, string what) =>
        fields.TryGetValue(id, out var v) && v.Length > 0
            ? v
            : throw new InvalidDataException($"The KeePass database header is incomplete (missing {what}).");

    private static byte[] Need(Dictionary<string, byte[]> p, string name) =>
        p.TryGetValue(name, out var v) ? v : throw Damaged();

    private static InvalidDataException Damaged() => new("The KeePass database is damaged or incomplete.");
    private static InvalidDataException TooLarge() => new("The KeePass database is too large to import.");
}
