using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace Phrasia;

/// <summary>A newer release found on GitHub.</summary>
internal sealed record UpdateInfo(Version Version, string Tag, string Title, string Url);

/// <summary>
/// Asks GitHub whether a newer Phrasia release exists. The only data sent is an ordinary HTTPS request
/// (the app name and version in the User-Agent, as GitHub requires) – nothing about the user or the vault.
/// Nothing is downloaded or installed automatically: the user only gets a link to the release page.
/// </summary>
internal static class UpdateChecker
{
    public const string Owner = "LUKICSLA";
    public const string Repository = "Phrasia";

    /// <summary>Release list on GitHub (also the fallback link).</summary>
    public static string ReleasesPage => $"https://github.com/{Owner}/{Repository}/releases";

    private static string LatestReleaseApi => $"https://api.github.com/repos/{Owner}/{Repository}/releases/latest";

    /// <summary>Returns the newer release, or null if this version is current, there is no release yet, or the
    /// check fails. Never throws except on cancellation.</summary>
    public static async Task<UpdateInfo?> CheckAsync(Version current, CancellationToken cancel = default)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = 1 << 20 };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"Phrasia/{Normalize(current).ToString(3)}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

        using var response = await http.GetAsync(LatestReleaseApi, cancel).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound) return null; // no published release yet
        response.EnsureSuccessStatusCode();
        string json = await response.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);
        return ParseLatestRelease(json, current);
    }

    /// <summary>Reads the GitHub "latest release" JSON; returns it only if it is a published release newer than <paramref name="current"/>.</summary>
    internal static UpdateInfo? ParseLatestRelease(string json, Version current)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (IsTrue(root, "draft") || IsTrue(root, "prerelease")) return null;

            string tag = root.TryGetProperty("tag_name", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString()! : "";
            if (!TryParseVersion(tag, out var version) || version <= Normalize(current)) return null;

            string url = root.TryGetProperty("html_url", out var u) && u.ValueKind == JsonValueKind.String ? u.GetString()! : "";
            if (!IsTrustedReleaseUrl(url)) url = ReleasesPage; // only ever open a link into this repository

            string title = root.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString()! : "";
            if (string.IsNullOrWhiteSpace(title) || title.Length > 100) title = "Phrasia " + version.ToString(3);
            return new UpdateInfo(version, tag, title.Trim(), url);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Parses a tag such as "v1.21.0", "1.21" or "v1.22.0-beta" (suffix ignored) into a 3-part version.</summary>
    internal static bool TryParseVersion(string? tag, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(tag)) return false;
        string s = tag.Trim();
        if (s.StartsWith('v') || s.StartsWith('V')) s = s[1..];
        int cut = s.IndexOfAny(['-', '+', ' ']);
        if (cut >= 0) s = s[..cut];
        if (!s.Contains('.') || !Version.TryParse(s, out var parsed)) return false;
        version = Normalize(parsed);
        return true;
    }

    /// <summary>Major.Minor.Build with a missing build treated as 0 (so 1.21 == 1.21.0 == 1.21.0.0).</summary>
    internal static Version Normalize(Version v) => new(v.Major, v.Minor, Math.Max(0, v.Build));

    /// <summary>True only for https://github.com/LUKICSLA/Phrasia/… links.</summary>
    internal static bool IsTrustedReleaseUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
        && uri.AbsolutePath.StartsWith($"/{Owner}/{Repository}/", StringComparison.OrdinalIgnoreCase);

    private static bool IsTrue(JsonElement root, string name) =>
        root.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;
}
