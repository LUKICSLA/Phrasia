using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NLog;
using NLog.Config;
using NLog.Targets;

namespace Phrasia;

/// <summary>
/// Logging setup (NLog) with on-disk encryption.
///
/// SECURITY RULE: the log NEVER records passwords, the master password, generated passwords, entry
/// titles, usernames, URLs, notes or clipboard content – only events, counts and technical data
/// (version, errors).
///
/// ENCRYPTION: each log line is encrypted with Windows DPAPI (DataProtectionScope.CurrentUser) before
/// writing and stored as Base64. On disk the log is therefore unreadable – in a hex editor or Notepad it
/// looks like random text, and only the same Windows user on the same computer can decrypt it. The
/// readable content is shown only by the built-in viewer (the "Logs" button). Logs are purely local –
/// nothing is sent anywhere. Path: %LOCALAPPDATA%\PassphraseGen\logs\phrasia-YYYY-MM-DD.log (files older
/// than the retention chosen in Settings are deleted; logging can also be turned off there).
/// </summary>
internal static class Logging
{
    /// <summary>How many days of log files are kept before deletion (Settings › Logging).</summary>
    public static int KeepDays { get; private set; } = AppSettings.DefaultLogKeepDays;

    /// <summary>"off", "normal" (Info and above) or "detailed" (Debug and above) – Settings › Logging.</summary>
    public static string Level { get; private set; } = "normal";

    /// <summary>DPAPI domain separation for log lines (not a secret).</summary>
    internal static readonly byte[] Entropy = "Phrasia | encrypted log | v1"u8.ToArray();

    /// <summary>Directory that holds the daily log files.</summary>
    public static string LogDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PassphraseGen", "logs");

    /// <summary>NLog layout for one (pre-encryption) log line.</summary>
    public const string LineLayout =
        "${longdate} | ${level:uppercase=true:padding=-5} | ${logger:shortName=true} | ${message}" +
        "${onexception:inner= | ${exception:format=ToString}}";

    /// <summary>Configures NLog with the encrypting file target plus a debugger target, then prunes old logs.
    /// Called at startup and again whenever the logging settings change.</summary>
    public static void Configure(string level = "normal", int keepDays = AppSettings.DefaultLogKeepDays)
    {
        Level = level;
        KeepDays = keepDays;
        try
        {
            var config = new LoggingConfiguration();
            var file = new EncryptedFileTarget("file")
            {
                Directory = LogDirectory,
                Layout = LineLayout
            };
            if (level != "off")
                config.AddRule(level == "detailed" ? LogLevel.Debug : LogLevel.Info, LogLevel.Fatal, file);

            var debugger = new DebuggerTarget("debugger")
            {
                Layout = "${time} ${level:uppercase=true} ${logger:shortName=true}: ${message}"
            };
            config.AddRule(LogLevel.Debug, LogLevel.Fatal, debugger);

            LogManager.Configuration = config;
        }
        catch (Exception)
        {
            // logging must never prevent the app from starting
        }

        DeleteOldLogs();
    }

    /// <summary>Reads and decrypts the most recent log lines (newest files) for the built-in viewer.</summary>
    public static IReadOnlyList<string> ReadDecrypted(int maxLines = 2000)
    {
        var lines = new List<string>();
        try
        {
            if (!Directory.Exists(LogDirectory)) return lines;
            var files = new DirectoryInfo(LogDirectory).GetFiles("phrasia-*.log")
                .OrderBy(f => f.LastWriteTimeUtc).ToArray();
            foreach (var f in files)
            {
                foreach (var b64 in File.ReadLines(f.FullName))
                {
                    if (string.IsNullOrWhiteSpace(b64)) continue;
                    try
                    {
                        var prot = Convert.FromBase64String(b64);
                        var plain = ProtectedData.Unprotect(prot, Entropy, DataProtectionScope.CurrentUser);
                        try { lines.Add(Encoding.UTF8.GetString(plain)); }
                        finally { CryptographicOperations.ZeroMemory(plain); }
                    }
                    catch (Exception ex) when (ex is FormatException or CryptographicException)
                    {
                        lines.Add("[unreadable log line – different Windows user or corrupted]");
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }

        if (lines.Count > maxLines) lines.RemoveRange(0, lines.Count - maxLines);
        return lines;
    }

    /// <summary>Deletes every log file (Settings › Logging › Delete logs now). Returns the number deleted.</summary>
    public static int DeleteAll()
    {
        int n = 0;
        try
        {
            if (!Directory.Exists(LogDirectory)) return 0;
            foreach (var f in Directory.EnumerateFiles(LogDirectory, "phrasia-*.log"))
            {
                try { File.Delete(f); n++; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return n;
    }

    /// <summary>Deletes log files older than <see cref="KeepDays"/> days.</summary>
    private static void DeleteOldLogs()
    {
        try
        {
            if (!Directory.Exists(LogDirectory)) return;
            foreach (var f in Directory.EnumerateFiles(LogDirectory, "phrasia-*.log"))
                if (File.GetLastWriteTimeUtc(f) < DateTime.UtcNow.AddDays(-KeepDays))
                    File.Delete(f);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}

/// <summary>
/// NLog target that encrypts each line with DPAPI (CurrentUser) and stores it as Base64.
/// On disk the log is unreadable; only the built-in viewer decrypts it.
/// </summary>
[Target("EncryptedFile")]
internal sealed class EncryptedFileTarget : TargetWithLayout
{
    private readonly object _lock = new();

    /// <summary>Creates the target with the given NLog name.</summary>
    public EncryptedFileTarget(string name) => Name = name;

    /// <summary>Log directory; the file is phrasia-YYYY-MM-DD.log.</summary>
    public string Directory { get; set; } = "";

    /// <summary>Path of today's log file.</summary>
    private string CurrentFile => Path.Combine(Directory, $"phrasia-{DateTime.Now:yyyy-MM-dd}.log");

    /// <summary>Renders the event, DPAPI-encrypts it, and appends it as a Base64 line (failures are swallowed).</summary>
    protected override void Write(LogEventInfo logEvent)
    {
        string text = Layout.Render(logEvent);
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        try
        {
            byte[] prot;
            try { prot = ProtectedData.Protect(bytes, Logging.Entropy, DataProtectionScope.CurrentUser); }
            finally { CryptographicOperations.ZeroMemory(bytes); }

            string line = Convert.ToBase64String(prot) + Environment.NewLine;
            lock (_lock)
            {
                System.IO.Directory.CreateDirectory(Directory);
                File.AppendAllText(CurrentFile, line, Encoding.ASCII);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            // logging must not crash the app
        }
    }
}
