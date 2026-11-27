using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Phrasia;

/// <summary>What to carry over from the source into each item's note.</summary>
public sealed record ImportOptions(bool IncludeGroup = true, bool IncludeCustomFields = true);

/// <summary>Result of reading an export or database – nothing is in the vault yet.</summary>
public sealed class ImportResult
{
    public List<VaultEntry> Entries { get; } = new();
    /// <summary>Human-readable source ("KeePass 4.1 database (Argon2d …, ChaCha20)", "CSV (Bitwarden)" …).</summary>
    public string Source { get; set; } = "";
    /// <summary>Items in the KeePass recycle bin – not imported.</summary>
    public int RecycleBinSkipped { get; set; }
    /// <summary>File attachments – Phrasia has no attachments, they are only listed in the note.</summary>
    public int AttachmentsSkipped { get; set; }
    /// <summary>Completely empty items / rows that were ignored.</summary>
    public int EmptySkipped { get; set; }
}

/// <summary>
/// Reads KeePass 2 databases (.kdbx), KeePass / KeePassXC XML exports, and CSV exports of KeePass, KeePassXC,
/// Bitwarden, Proton Pass, 1Password, Chrome / Edge and Firefox into new <see cref="VaultEntry"/> items.
/// KeePass fields without a Phrasia counterpart (group, tags, custom fields, expiry, attachment names)
/// are kept in a short block at the end of the item's note.
/// </summary>
public static class KeePassImporter
{
    private const string NoteHeader = "— Imported from {0} —";
    private static readonly string[] StandardKeys = ["Title", "UserName", "Password", "URL", "Notes"];

    // ---------------- KeePass .kdbx ----------------

    /// <summary>Decrypts a KeePass 2 database. <paramref name="password"/> may be null when only a key file is used.</summary>
    /// <exception cref="KeePassWrongKeyException">The password / key file does not open the database.</exception>
    public static ImportResult ReadKdbx(string path, string? password, string? keyFilePath, ImportOptions options)
    {
        var file = ReadLimited(path, KdbxReader.MaxFileBytes);
        byte[]? keyFile = keyFilePath is null ? null : ReadLimited(keyFilePath, 16 * 1024 * 1024);
        try
        {
            // Key file + empty password: KeePassXC leaves the password out of the key, KeePass 2 can include an
            // empty one – try both (the second attempt only runs when the first is rejected).
            if (keyFile is not null && string.IsNullOrEmpty(password))
            {
                try { return ReadKdbxWith(file, null, keyFile, options); }
                catch (KeePassWrongKeyException) { return ReadKdbxWith(file, "", keyFile, options); }
            }
            return ReadKdbxWith(file, password ?? "", keyFile, options);
        }
        finally
        {
            if (keyFile is not null) CryptographicOperations.ZeroMemory(keyFile);
        }
    }

    /// <summary>One decryption attempt with one composite key.</summary>
    private static ImportResult ReadKdbxWith(byte[] file, string? password, byte[]? keyFile, ImportOptions options)
    {
        var composite = KdbxReader.CompositeKey(password, keyFile);
        try
        {
            var (doc, info) = KdbxReader.Read(file, composite);
            var result = FromKeePassXml(doc, options, "KeePass");
            result.Source = $"KeePass database (KDBX {info.MajorVersion}.{info.MinorVersion} · {info.Kdf} · {info.Cipher})";
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(composite);
        }
    }

    /// <summary>True if the file starts with the KeePass 2 signature.</summary>
    public static bool IsKdbxFile(string path)
    {
        Span<byte> head = stackalloc byte[8];
        using var fs = File.OpenRead(path);
        return fs.Read(head) == 8 && KdbxReader.LooksLikeKdbx(head);
    }

    // ---------------- KeePass XML export ----------------

    /// <summary>Reads an unencrypted KeePass 2 / KeePassXC XML export.</summary>
    public static ImportResult ReadKeePassXml(string path, ImportOptions options)
    {
        var doc = KdbxReader.ParseXml(ReadLimited(path, KdbxReader.MaxXmlBytes));
        if (doc.Root?.Name.LocalName != "KeePassFile")
            throw new InvalidDataException("This XML file is not a KeePass export (expected <KeePassFile>).");
        // a plain export has no inner stream – an element still marked Protected cannot be read
        if (doc.Descendants().Any(e => string.Equals((string?)e.Attribute("Protected"), "True", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("This XML still contains encrypted (protected) values. Export it from KeePass via File › Export › KeePass XML (2.x).");
        var result = FromKeePassXml(doc, options, "KeePass");
        result.Source = "KeePass XML export";
        return result;
    }

    /// <summary>Converts the KeePass XML tree (already decrypted) into vault items.</summary>
    internal static ImportResult FromKeePassXml(XDocument doc, ImportOptions options, string sourceName)
    {
        var result = new ImportResult();
        var root = doc.Root ?? throw new InvalidDataException("Empty KeePass document.");
        var meta = root.Element("Meta");
        string? recycleUuid = meta?.Element("RecycleBinUUID")?.Value.Trim();
        bool recycleEnabled = !string.Equals(meta?.Element("RecycleBinEnabled")?.Value.Trim(), "False", StringComparison.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(recycleUuid) || recycleUuid == "AAAAAAAAAAAAAAAAAAAAAA==") recycleUuid = null;

        var top = root.Element("Root")?.Element("Group")
                  ?? throw new InvalidDataException("The KeePass document has no groups.");
        // the top group is the database itself ("Root", "Passwords" …) – it is not repeated in every path
        WalkGroup(top, [], isTop: true);
        return result;

        void WalkGroup(XElement group, List<string> path, bool isTop)
        {
            string uuid = group.Element("UUID")?.Value.Trim() ?? "";
            if (!isTop && recycleEnabled && recycleUuid is not null && uuid == recycleUuid)
            {
                result.RecycleBinSkipped += group.Descendants("Entry").Count(e => e.Parent?.Name.LocalName != "History");
                return;
            }
            var here = isTop ? path : [.. path, group.Element("Name")?.Value.Trim() ?? ""];

            foreach (var entry in group.Elements("Entry"))
            {
                var item = ConvertEntry(entry, here, options, sourceName, result);
                if (item is null) result.EmptySkipped++;
                else result.Entries.Add(item);
            }
            foreach (var sub in group.Elements("Group"))
                WalkGroup(sub, here, isTop: false);
        }
    }

    /// <summary>One KeePass entry → a vault item (null if it has no content at all).</summary>
    private static VaultEntry? ConvertEntry(XElement entry, List<string> groupPath, ImportOptions options,
        string sourceName, ImportResult result)
    {
        var strings = ReadStrings(entry);
        string Get(string key) => strings.TryGetValue(key, out var v) ? v : "";

        string title = Get("Title").Trim(), user = Get("UserName").Trim(), password = Get("Password"),
               url = Get("URL").Trim(), notes = Get("Notes").TrimEnd();

        var extra = new List<string>();
        var groups = groupPath.Where(g => g.Length > 0).ToList();
        if (options.IncludeGroup && groups.Count > 0) extra.Add("Group: " + string.Join(" / ", groups));

        var tags = entry.Element("Tags")?.Value;
        if (!string.IsNullOrWhiteSpace(tags))
            extra.Add("Tags: " + string.Join(", ", tags.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)));

        if (options.IncludeCustomFields)
            foreach (var (key, value) in strings)
                if (!StandardKeys.Contains(key) && !string.IsNullOrEmpty(value))
                    extra.Add(FormatField(key, value));

        var times = entry.Element("Times");
        if (string.Equals(times?.Element("Expires")?.Value.Trim(), "True", StringComparison.OrdinalIgnoreCase)
            && ParseKeePassTime(times?.Element("ExpiryTime")?.Value) is { } expiry)
            extra.Add($"Expires: {expiry:yyyy-MM-dd}");

        var attachments = entry.Elements("Binary")
            .Select(b => b.Element("Key")?.Value.Trim())
            .Where(n => !string.IsNullOrEmpty(n))
            .ToList();
        if (attachments.Count > 0)
        {
            result.AttachmentsSkipped += attachments.Count;
            extra.Add("Attachments not imported: " + string.Join(", ", attachments));
        }

        if (title.Length == 0 && user.Length == 0 && password.Length == 0 && url.Length == 0
            && notes.Length == 0 && extra.Count(l => !l.StartsWith("Group:", StringComparison.Ordinal)) == 0)
            return null;

        var created = ParseKeePassTime(times?.Element("CreationTime")?.Value) ?? DateTime.Now;
        var modified = ParseKeePassTime(times?.Element("LastModificationTime")?.Value) ?? created;
        if (modified < created) modified = created;

        return new VaultEntry
        {
            Title = title.Length > 0 ? title : FallbackTitle(url, user),
            Username = user,
            Password = password,
            Url = url,
            Note = ComposeNote(notes, extra, sourceName),
            Created = created,
            Modified = modified,
            PasswordChanged = PasswordChangedFromHistory(entry, password, created, modified),
        };
    }

    /// <summary>All String key/value pairs of an entry (later duplicates win, as in KeePass).</summary>
    private static Dictionary<string, string> ReadStrings(XElement entry)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var s in entry.Elements("String"))
        {
            var key = s.Element("Key")?.Value;
            if (string.IsNullOrEmpty(key)) continue;
            d[key] = s.Element("Value")?.Value ?? "";
        }
        return d;
    }

    /// <summary>
    /// When the current password was set: the modification time of the oldest consecutive history version that
    /// already had it (KeePass saves a history copy on every change). Falls back to the creation time.
    /// </summary>
    private static DateTime? PasswordChangedFromHistory(XElement entry, string current, DateTime created, DateTime modified)
    {
        var history = entry.Element("History")?.Elements("Entry").ToList();
        if (history is null || history.Count == 0) return created;

        var versions = history
            .Select(h => (Password: ReadStrings(h).GetValueOrDefault("Password", ""),
                          Time: ParseKeePassTime(h.Element("Times")?.Element("LastModificationTime")?.Value)))
            .OrderBy(v => v.Time ?? DateTime.MinValue)
            .ToList();

        DateTime? since = modified;
        for (int i = versions.Count - 1; i >= 0; i--)
        {
            if (versions[i].Password != current) break;
            since = versions[i].Time ?? since;
        }
        // every version had this password → it was set when the entry was created
        return versions.All(v => v.Password == current) ? created : since;
    }

    /// <summary>KDBX 4 stores times as base64 seconds since 0001-01-01 UTC, KDBX 3 / XML as ISO 8601.</summary>
    internal static DateTime? ParseKeePassTime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim();
        if (DateTime.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var iso))
            return iso.ToLocalTime();
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length != 8) return null;
            long seconds = BitConverter.ToInt64(bytes);
            if (seconds <= 0 || seconds > 315_537_897_599) return null; // up to 9999-12-31
            return new DateTime(1, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(seconds).ToLocalTime();
        }
        catch (FormatException) { return null; }
    }

    // ---------------- CSV export ----------------

    /// <summary>Column name synonyms of popular managers (compared case-insensitively, ignoring spaces, '_' and '-').</summary>
    private static readonly Dictionary<string, string[]> CsvColumns = new()
    {
        ["title"] = ["title", "name", "account", "accountname", "entry", "itemname"],
        ["username"] = ["username", "user", "login", "loginname", "loginusername", "userid"],
        ["email"] = ["email", "emailaddress", "mail"],
        ["password"] = ["password", "loginpassword", "pass", "pwd"],
        ["url"] = ["url", "website", "web", "site", "loginuri", "uri", "loginurl", "urls", "address"],
        ["notes"] = ["notes", "note", "comments", "comment", "extra", "notesplain"],
        ["group"] = ["group", "folder", "path", "grouping", "category", "collection"],
        ["vault"] = ["vault"],
        ["totp"] = ["totp", "otp", "logintotp", "otpauth", "onetimepassword", "otpurl"],
        ["fields"] = ["fields", "customfields"],
        ["tags"] = ["tags", "tag", "labels"],
        ["created"] = ["created", "createtime", "timecreated", "creationtime", "createdat"],
        ["modified"] = ["lastmodified", "modifytime", "modified", "modificationtime", "updatedat", "lastmodificationtime"],
        ["pwchanged"] = ["timepasswordchanged", "passwordchanged", "passwordmodified"],
        ["type"] = ["type", "itemtype"],
    };

    /// <summary>Reads a CSV export. Columns are recognized by their header names (KeePass, KeePassXC, Bitwarden,
    /// Proton Pass, 1Password, Chrome/Edge, Firefox, generic "title,username,password,url,notes").</summary>
    public static ImportResult ReadCsv(string path, ImportOptions options)
    {
        var raw = ReadLimited(path, 256L * 1024 * 1024);
        string text = DecodeText(raw);
        CryptographicOperations.ZeroMemory(raw);

        var rows = ParseCsv(text);
        if (rows.Count == 0) throw new InvalidDataException("The CSV file is empty.");

        var header = rows[0].Select(NormalizeHeader).ToList();
        var map = new Dictionary<string, int>();
        foreach (var (field, names) in CsvColumns)
        {
            int index = header.FindIndex(h => names.Contains(h));
            if (index >= 0) map[field] = index;
        }
        if (!map.ContainsKey("password"))
            throw new InvalidDataException(
                "Could not recognize the CSV columns – the first row must be a header with at least a \"password\" column " +
                "(for example: title,username,password,url,notes).");

        var result = new ImportResult { Source = "CSV export" + GuessCsvSource(header) };
        string sourceName = "CSV" + GuessCsvSource(header);
        for (int r = 1; r < rows.Count; r++)
        {
            var row = rows[r];
            string Get(string field) => map.TryGetValue(field, out var i) && i < row.Count ? row[i] : "";

            string title = Get("title").Trim(), user = Get("username").Trim(), email = Get("email").Trim(),
                   password = Get("password"), url = Get("url").Trim(), notes = Get("notes").TrimEnd();
            if (user.Length == 0) user = email;
            if (url.Contains('\n')) url = url.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "";

            var extra = new List<string>();
            string group = Get("group").Trim();
            if (group.Length == 0) group = Get("vault").Trim();
            if (options.IncludeGroup && group.Length > 0) extra.Add("Group: " + group.Replace("/", " / ").Replace("  ", " "));
            string tags = Get("tags").Trim();
            if (tags.Length > 0) extra.Add("Tags: " + tags);
            if (options.IncludeCustomFields)
            {
                if (email.Length > 0 && !string.Equals(email, user, StringComparison.OrdinalIgnoreCase)) extra.Add("E-mail: " + email);
                string totp = Get("totp").Trim();
                if (totp.Length > 0) extra.Add("TOTP: " + totp);
                string fields = Get("fields").Trim();
                if (fields.Length > 0) extra.Add(fields);
            }

            if (title.Length == 0 && user.Length == 0 && password.Length == 0 && url.Length == 0 && notes.Length == 0)
            {
                result.EmptySkipped++;
                continue;
            }

            var created = ParseCsvTime(Get("created")) ?? DateTime.Now;
            var modified = ParseCsvTime(Get("modified")) ?? created;
            if (modified < created) modified = created;
            result.Entries.Add(new VaultEntry
            {
                Title = title.Length > 0 ? title : FallbackTitle(url, user),
                Username = user,
                Password = password,
                Url = url,
                Note = ComposeNote(notes, extra, sourceName),
                Created = created,
                Modified = modified,
                PasswordChanged = ParseCsvTime(Get("pwchanged")) ?? modified,
            });
        }
        return result;
    }

    /// <summary>Lower-case header without spaces, '_', '-' and quotes ("Login Name" → "loginname").</summary>
    private static string NormalizeHeader(string h) =>
        new(h.Trim().Trim('﻿').ToLowerInvariant().Where(ch => ch is not (' ' or '_' or '-' or '"' or '.')).ToArray());

    /// <summary>A hint of which manager produced the CSV (only for the report).</summary>
    private static string GuessCsvSource(List<string> header)
    {
        bool Has(string h) => header.Contains(h);
        if (Has("loginpassword") && Has("loginuri")) return " (Bitwarden)";
        if (Has("account") && Has("loginname") && Has("website")) return " (KeePass)";
        if (Has("vault") && Has("createtime")) return " (Proton Pass)";
        if (Has("timepasswordchanged") || Has("httprealm")) return " (Firefox)";
        if (Has("group") && Has("title") && Has("totp")) return " (KeePassXC)";
        if (Has("name") && Has("url") && Has("username") && Has("password") && header.Count <= 5) return " (Chrome / Edge)";
        return "";
    }

    /// <summary>Times in CSV exports: ISO 8601 / local text, Unix seconds (Proton) or Unix milliseconds (Firefox).</summary>
    private static DateTime? ParseCsvTime(string value)
    {
        value = value.Trim();
        if (value.Length == 0) return null;
        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n) && n > 0)
        {
            try
            {
                return (n > 100_000_000_000 ? DateTimeOffset.FromUnixTimeMilliseconds(n) : DateTimeOffset.FromUnixTimeSeconds(n))
                    .LocalDateTime;
            }
            catch (ArgumentOutOfRangeException) { return null; }
        }
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
            return dto.LocalDateTime;
        return null;
    }

    /// <summary>RFC 4180 CSV parser: quoted fields, doubled quotes, newlines inside quotes; delimiter , ; or tab (detected from the header).</summary>
    internal static List<List<string>> ParseCsv(string text)
    {
        int firstLineEnd = text.IndexOfAny(['\r', '\n']);
        string first = firstLineEnd < 0 ? text : text[..firstLineEnd];
        char delimiter = new[] { ',', ';', '\t' }.OrderByDescending(d => first.Count(ch => ch == d)).First();

        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        bool inQuotes = false, fieldStarted = false;

        for (int i = 0; i < text.Length; i++)
        {
            char ch = text[i];
            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                    else inQuotes = false;
                }
                else field.Append(ch);
                continue;
            }
            if (ch == '"' && field.Length == 0) { inQuotes = true; fieldStarted = true; }
            else if (ch == delimiter) { row.Add(field.ToString()); field.Clear(); fieldStarted = false; }
            else if (ch is '\r' or '\n')
            {
                if (ch == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                row.Add(field.ToString()); field.Clear(); fieldStarted = false;
                if (row.Count > 1 || row[0].Length > 0) rows.Add(row);
                row = new List<string>();
            }
            else { field.Append(ch); fieldStarted = true; }
        }
        if (field.Length > 0 || fieldStarted || row.Count > 0)
        {
            row.Add(field.ToString());
            if (row.Count > 1 || row[0].Length > 0) rows.Add(row);
        }
        field.Clear();
        return rows;
    }

    // ---------------- shared helpers ----------------

    /// <summary>Removes items that already exist in the vault (same title, username, password and URL) – importing the same file twice adds nothing.</summary>
    public static int RemoveExisting(IEnumerable<VaultEntry> existing, List<VaultEntry> incoming)
    {
        var known = new HashSet<(string, string, string, string)>(
            existing.Select(e => (e.Title.Trim(), e.Username.Trim(), e.Password, e.Url.Trim())));
        return incoming.RemoveAll(e => known.Contains((e.Title.Trim(), e.Username.Trim(), e.Password, e.Url.Trim())));
    }

    /// <summary>Original notes, then a short block with the fields Phrasia has no place for.</summary>
    private static string ComposeNote(string notes, List<string> extra, string sourceName)
    {
        if (extra.Count == 0) return notes;
        var sb = new StringBuilder(notes);
        if (sb.Length > 0) sb.Append("\n\n");
        sb.Append(string.Format(CultureInfo.InvariantCulture, NoteHeader, sourceName));
        foreach (var line in extra) sb.Append('\n').Append(line);
        return sb.ToString();
    }

    /// <summary>"Key: value"; a multi-line value continues on indented lines.</summary>
    private static string FormatField(string key, string value)
    {
        var lines = value.Replace("\r\n", "\n").Split('\n');
        return lines.Length == 1 ? $"{key}: {value}" : $"{key}:\n  " + string.Join("\n  ", lines);
    }

    /// <summary>Title for items that have none: the website host, else the username, else "(untitled)".</summary>
    private static string FallbackTitle(string url, string user)
    {
        if (url.Length > 0)
        {
            var candidate = url.Contains("://", StringComparison.Ordinal) ? url : "https://" + url;
            if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
                return uri.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? uri.Host[4..] : uri.Host;
        }
        return user.Length > 0 ? user : "(untitled)";
    }

    /// <summary>UTF-8 (with or without BOM) or UTF-16 with BOM; invalid UTF-8 falls back to Latin-1.</summary>
    private static string DecodeText(byte[] raw)
    {
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) return Encoding.Unicode.GetString(raw, 2, raw.Length - 2);
        if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(raw, 2, raw.Length - 2);
        int offset = raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF ? 3 : 0;
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(raw, offset, raw.Length - offset);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(raw);
        }
    }

    /// <summary>Reads a whole file, refusing anything above <paramref name="max"/> bytes.</summary>
    private static byte[] ReadLimited(string path, long max)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("The file does not exist.", path);
        if (info.Length > max) throw new InvalidDataException($"The file is too large to import ({info.Length / (1024 * 1024):N0} MiB).");
        return File.ReadAllBytes(path);
    }
}
