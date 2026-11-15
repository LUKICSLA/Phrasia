using System.Text.RegularExpressions;

namespace Phrasia;

/// <summary>Result of analyzing the passwords stored in the vault.</summary>
public sealed class VaultAnalysis
{
    public int Total { get; init; }
    public int Critical { get; init; }
    public List<VaultEntry> Empty { get; } = new();
    public List<VaultEntry> Weak { get; } = new();
    public List<List<VaultEntry>> ReusedGroups { get; } = new();
    public List<VaultEntry> Old { get; } = new();
    public List<VaultEntry> Personal { get; } = new();       // password contains the entry title / username
    public List<VaultEntry> CommonPattern { get; } = new();  // 123456, qwerty, password, aaaa…
    public List<VaultEntry> SuggestedCritical { get; } = new();

    /// <summary>Entries that have at least one issue.</summary>
    public HashSet<Guid> NeedsAttention { get; } = new();

    /// <summary>0–100; critical accounts are weighted triple in the score.</summary>
    public int Score { get; set; }

    /// <summary>Total number of entries that share a password with at least one other entry.</summary>
    public int ReusedCount => ReusedGroups.Sum(g => g.Count);

    /// <summary>A short textual grade derived from <see cref="Score"/>.</summary>
    public string Grade => Total == 0 ? "Empty vault" : Score switch
    {
        >= 90 => "Excellent",
        >= 75 => "Good",
        >= 50 => "Needs work",
        _ => "At risk"
    };
}

/// <summary>Analyzes all stored passwords – runs locally, nothing is sent anywhere.</summary>
public static class VaultAnalyzer
{
    /// <summary>Below this entropy (bits) a non-critical password is flagged weak.</summary>
    public const double WeakBits = 60;
    /// <summary>Below this entropy (bits) a critical password is flagged weak.</summary>
    public const double CriticalBits = 75;
    /// <summary>A password unchanged longer than this many days is flagged old.</summary>
    public const int OldAfterDays = 365;

    private static readonly string[] CommonFragments =
    {
        "password", "passwort", "heslo", "qwerty", "qwertz", "asdf", "yxcv", "zxcv", "123456", "654321",
        "111111", "abc123", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "master", "login"
    };

    private static readonly Regex RepeatedChars = new(@"(.)\1{3,}", RegexOptions.Compiled);
    private static readonly Regex DigitRun = new(@"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)",
        RegexOptions.Compiled);

    /// <summary>Account keywords that suggest an entry should be marked critical.</summary>
    private static readonly string[] CriticalKeywords =
    {
        "mail", "gmail", "outlook", "hotmail", "icloud", "proton", "seznam", "zoznam", "azet", "centrum", "yahoo",
        "bank", "banka", "tatra", "slsp", "sporitel", "vub", "csob", "unicredit", "revolut", "paypal",
        "365bank", "mbank", "raiffeisen", "airbank", "moneta",
        "apple", "google", "microsoft", "office", "praca", "práca",
        "bitwarden", "1password", "lastpass", "keepass", "github", "gitlab", "aws", "azure"
    };

    /// <summary>Scans entries for empty/weak/reused/old/personal/common-pattern passwords and computes a score.</summary>
    public static VaultAnalysis Analyze(IReadOnlyList<VaultEntry> entries, DateTime? now = null)
    {
        var today = now ?? DateTime.Now;
        var a = new VaultAnalysis { Total = entries.Count, Critical = entries.Count(e => e.Critical) };

        foreach (var e in entries)
        {
            string pw = e.Password ?? "";
            if (pw.Length == 0)
            {
                Flag(a, a.Empty, e);
                continue;
            }

            double bits = MasterPasswordPolicy.EstimateBits(pw);
            if (bits < (e.Critical ? CriticalBits : WeakBits)) Flag(a, a.Weak, e);

            var changed = e.PasswordChanged ?? e.Modified;
            if ((today - changed).TotalDays > OldAfterDays) Flag(a, a.Old, e);

            if (ContainsPersonal(pw, e)) Flag(a, a.Personal, e);
            if (HasCommonPattern(pw)) Flag(a, a.CommonPattern, e);

            if (!e.Critical && LooksCritical(e)) a.SuggestedCritical.Add(e);
        }

        foreach (var g in entries.Where(e => !string.IsNullOrEmpty(e.Password))
                                 .GroupBy(e => e.Password).Where(g => g.Count() > 1))
        {
            var group = g.OrderByDescending(e => e.Critical).ThenBy(e => e.Title).ToList();
            a.ReusedGroups.Add(group);
            foreach (var e in group) a.NeedsAttention.Add(e.Id);
        }
        a.ReusedGroups.Sort((x, y) => y.Count.CompareTo(x.Count));

        // score: share of "healthy" entries, critical accounts weigh 3×
        double total = entries.Sum(Weight);
        double ok = entries.Where(e => !a.NeedsAttention.Contains(e.Id)).Sum(Weight);
        a.Score = total == 0 ? 100 : (int)Math.Round(100 * ok / total);
        return a;

        static double Weight(VaultEntry e) => e.Critical ? 3 : 1;
    }

    /// <summary>Adds an entry to an issue list and marks it as needing attention.</summary>
    private static void Flag(VaultAnalysis a, List<VaultEntry> list, VaultEntry e)
    {
        list.Add(e);
        a.NeedsAttention.Add(e.Id);
    }

    /// <summary>True if the password contains a common fragment, a long character run, or a digit sequence.</summary>
    public static bool HasCommonPattern(string pw)
    {
        string lower = pw.ToLowerInvariant();
        return CommonFragments.Any(lower.Contains) || RepeatedChars.IsMatch(pw) || DigitRun.IsMatch(pw);
    }

    /// <summary>True if the password contains the entry title or username (a token of at least 4 characters).</summary>
    public static bool ContainsPersonal(string pw, VaultEntry e)
    {
        string lower = pw.ToLowerInvariant();
        var parts = new List<string>();
        parts.AddRange(Words(e.Title));
        var user = e.Username ?? "";
        int at = user.IndexOf('@');
        parts.AddRange(Words(at > 0 ? user[..at] : user));
        return parts.Any(p => p.Length >= 4 && lower.Contains(p));

        static IEnumerable<string> Words(string s) =>
            Regex.Split(s.ToLowerInvariant(), @"[^\p{L}\p{N}]+").Where(w => w.Length > 0);
    }

    /// <summary>True if the entry title or URL matches a keyword for a security-critical account.</summary>
    public static bool LooksCritical(VaultEntry e)
    {
        string hay = (e.Title + " " + e.Url).ToLowerInvariant();
        return CriticalKeywords.Any(hay.Contains);
    }
}
