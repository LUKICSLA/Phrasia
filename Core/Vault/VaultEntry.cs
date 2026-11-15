using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Phrasia;
/// <summary>One stored credential: title, username, password, URL, note, timestamps and a critical flag.</summary>
public sealed class VaultEntry
{
    /// <summary>Stable unique identifier of the entry.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Url { get; set; } = "";
    public string Note { get; set; } = "";
    public DateTime Created { get; set; } = DateTime.Now;
    public DateTime Modified { get; set; } = DateTime.Now;

    /// <summary>Critical account (e-mail, bank, work…) – highlighted and held to a stricter strength requirement.</summary>
    public bool Critical { get; set; }

    /// <summary>When the password was last changed (older entries: null → Modified is used).</summary>
    public DateTime? PasswordChanged { get; set; }

    // Transient flags for list display – not persisted to the vault.
    [JsonIgnore] public bool IsReused { get; set; }
    [JsonIgnore] public bool IsWeak { get; set; }
    [JsonIgnore] public bool HasUsername => !string.IsNullOrEmpty(Username);
    [JsonIgnore] public bool HasPassword => !string.IsNullOrEmpty(Password);
    [JsonIgnore] public string UsernameSuffix => HasUsername ? "  " + Username : "";

    // strength indicator in the list (0 = weakest … 5 = Cosmic) – computed on display, not stored
    [JsonIgnore] public double StrengthBits { get; set; }
    [JsonIgnore] public int StrengthLevel { get; set; }
    [JsonIgnore] public string StrengthText { get; set; } = "";

    /// <summary>Returns the entry title (or "(untitled)").</summary>
    public override string ToString() =>
        string.IsNullOrEmpty(Username) ? Title : $"{Title}  ·  {Username}";
}
