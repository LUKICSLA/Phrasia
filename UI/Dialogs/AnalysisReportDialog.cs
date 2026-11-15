using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>The follow-up step the user chose in the analysis report.</summary>
public enum AnalysisAction { None, ShowAttention, MarkCritical, Backup }

/// <summary>Vault analysis report dialog: score, detected issues, and recommended actions.</summary>
internal sealed class AnalysisReportDialog : Window
{
    /// <summary>The action the user chose (None if the dialog was just closed).</summary>
    public AnalysisAction Action { get; private set; } = AnalysisAction.None;

    /// <summary>Resolves a brush resource by key.</summary>
    private static Brush R(string key) => (Brush)Application.Current.Resources[key];
    /// <summary>Resolves a style resource by key.</summary>
    private static Style S(string key) => (Style)Application.Current.Resources[key];

    private static readonly Brush Red = Freeze(Color.FromRgb(0xC6, 0x28, 0x28));
    private static readonly Brush Orange = Freeze(Color.FromRgb(0xE6, 0x51, 0x00));
    private static readonly Brush Green = Freeze(Color.FromRgb(0x2E, 0x7D, 0x32));

    /// <summary>Builds the report UI from a completed analysis and wires the recommended-action buttons.</summary>
    public AnalysisReportDialog(Window owner, VaultAnalysis a)
    {
        Owner = owner;
        Title = "Password analysis";
        Width = 560;
        SizeToContent = SizeToContent.Height;
        MaxHeight = Math.Max(400, owner.ActualHeight - 40);
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = R("WindowBrush");

        var root = new StackPanel { Margin = new Thickness(24, 22, 24, 22) };

        // ----- score -----
        var scoreBrush = a.Score >= 90 ? Green : a.Score >= 75 ? Freeze(Color.FromRgb(0x38, 0x8E, 0x3C))
                       : a.Score >= 50 ? Orange : Red;
        var header = new DockPanel();
        var scoreBox = new Border
        {
            Width = 86, Height = 86, CornerRadius = new CornerRadius(43),
            BorderBrush = scoreBrush, BorderThickness = new Thickness(5), Margin = new Thickness(0, 0, 18, 0),
            Child = new TextBlock
            {
                Text = a.Total == 0 ? "–" : a.Score.ToString(), FontSize = 28, FontWeight = FontWeights.Bold,
                Foreground = scoreBrush, HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            }
        };
        DockPanel.SetDock(scoreBox, Dock.Left);
        header.Children.Add(scoreBox);
        var headText = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        headText.Children.Add(new TextBlock { Text = a.Grade, FontSize = 22, FontWeight = FontWeights.Bold, Foreground = scoreBrush });
        headText.Children.Add(new TextBlock
        {
            Text = a.Total == 0
                ? "There is nothing to analyze yet."
                : $"{a.Total} items · {a.Critical} critical · {a.NeedsAttention.Count} need attention",
            Foreground = R("MutedBrush"), Margin = new Thickness(0, 4, 0, 0)
        });
        headText.Children.Add(new TextBlock
        {
            Text = "Analyzed locally on this computer – nothing was sent anywhere.",
            Foreground = R("SubtleBrush"), FontSize = 11, Margin = new Thickness(0, 4, 0, 0)
        });
        header.Children.Add(headText);
        root.Children.Add(header);

        // ----- findings -----
        root.Children.Add(Section("FINDINGS"));
        if (a.NeedsAttention.Count == 0 && a.Total > 0)
            root.Children.Add(Line("No problems found. Every password is unique and strong.", Green));

        AddFinding(root, a.ReusedGroups.Count > 0, Red,
            $"{a.ReusedCount} items share passwords ({a.ReusedGroups.Count} group{Plural(a.ReusedGroups.Count)})",
            string.Join("\n", a.ReusedGroups.Take(4).Select(g => "• " + string.Join(", ", g.Select(Name)))) +
            (a.ReusedGroups.Count > 4 ? $"\n• …and {a.ReusedGroups.Count - 4} more group(s)" : ""),
            "If one site leaks, every account with the same password is exposed.");
        AddFinding(root, a.Weak.Count > 0, Red, $"{a.Weak.Count} weak password{Plural(a.Weak.Count)}",
            Names(a.Weak), "Under 60 bits (75 bits for critical accounts).");
        AddFinding(root, a.CommonPattern.Count > 0, Orange, $"{a.CommonPattern.Count} with common patterns",
            Names(a.CommonPattern), "Contains things like 123456, qwerty, password or aaaa – these are tried first.");
        AddFinding(root, a.Personal.Count > 0, Orange, $"{a.Personal.Count} contain the site name or username",
            Names(a.Personal), "Easy to guess for anyone who knows the account.");
        AddFinding(root, a.Old.Count > 0, Orange, $"{a.Old.Count} not changed for over a year",
            Names(a.Old), "Old passwords are more likely to appear in past breaches.");
        AddFinding(root, a.Empty.Count > 0, R("MutedBrush"), $"{a.Empty.Count} item{Plural(a.Empty.Count)} without a password",
            Names(a.Empty), "Fill in the password or delete the item if it is no longer needed.");

        // ----- recommended steps -----
        root.Children.Add(Section("RECOMMENDED STEPS"));
        if (a.NeedsAttention.Count > 0)
            root.Children.Add(Step($"Show only the {a.NeedsAttention.Count} item{Plural(a.NeedsAttention.Count)} that need attention",
                "Open each one, click ↻ to generate a new password, then change it on the website too – critical accounts first.",
                "Show items", AnalysisAction.ShowAttention, primary: true));
        if (a.SuggestedCritical.Count > 0)
            root.Children.Add(Step($"Mark {a.SuggestedCritical.Count} account{Plural(a.SuggestedCritical.Count)} as critical",
                Names(a.SuggestedCritical) + "\nE-mail and banking accounts are the keys to everything else.",
                "Mark critical", AnalysisAction.MarkCritical, primary: a.NeedsAttention.Count == 0));
        root.Children.Add(Step("Back up the vault",
            "Keep an encrypted copy on a USB drive or in the cloud in case this computer fails.",
            "Back up…", AnalysisAction.Backup, primary: false));

        var close = new Button
        {
            Content = "Close", IsCancel = true, IsDefault = true, HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 18, 0, 0), Style = S("GhostButton")
        };
        root.Children.Add(close);

        Content = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = root };
    }

    // ----- helpers -----

    /// <summary>Returns the plural suffix ("" for 1, "s" otherwise).</summary>
    private static string Plural(int n) => n == 1 ? "" : "s";
    /// <summary>Returns a display name for an entry (or "(untitled)").</summary>
    private static string Name(VaultEntry e) => string.IsNullOrWhiteSpace(e.Title) ? "(untitled)" : e.Title;

    /// <summary>Joins up to six entry names, summarizing the rest as "…and N more".</summary>
    private static string Names(List<VaultEntry> list) =>
        string.Join(", ", list.Take(6).Select(Name)) + (list.Count > 6 ? $", …and {list.Count - 6} more" : "");

    /// <summary>Creates a small-caps section header text block.</summary>
    private static TextBlock Section(string text) => new()
    {
        Text = text, FontSize = 11, FontWeight = FontWeights.Bold, Foreground = R("SubtleBrush"),
        Margin = new Thickness(0, 22, 0, 6)
    };

    /// <summary>Creates a single colored, bold, wrapping line.</summary>
    private static TextBlock Line(string text, Brush color) => new()
    {
        Text = text, Foreground = color, TextWrapping = TextWrapping.Wrap, FontWeight = FontWeights.SemiBold
    };

    /// <summary>Appends a finding card (title, affected items, and why it matters) when <paramref name="show"/> is true.</summary>
    private static void AddFinding(Panel root, bool show, Brush color, string title, string items, string why)
    {
        if (!show) return;
        var box = new Border
        {
            Background = Brushes.White, BorderBrush = R("LineBrush"), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10), Padding = new Thickness(14, 10, 14, 10), Margin = new Thickness(0, 6, 0, 0)
        };
        var sp = new StackPanel();
        sp.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, Foreground = color, TextWrapping = TextWrapping.Wrap });
        sp.Children.Add(new TextBlock { Text = items, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) });
        sp.Children.Add(new TextBlock { Text = why, TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = R("MutedBrush"), Margin = new Thickness(0, 4, 0, 0) });
        box.Child = sp;
        root.Children.Add(box);
    }

    /// <summary>Creates a recommended-step card whose button sets <see cref="Action"/> and closes the dialog.</summary>
    private Border Step(string title, string detail, string buttonText, AnalysisAction action, bool primary)
    {
        var button = new Button
        {
            Content = buttonText, Margin = new Thickness(14, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center,
            Style = S(primary ? "PrimaryButton" : "SecondaryButton")
        };
        button.Click += (_, _) => { Action = action; DialogResult = true; };
        DockPanel.SetDock(button, Dock.Right);

        var text = new StackPanel();
        text.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
        text.Children.Add(new TextBlock { Text = detail, FontSize = 12, Foreground = R("MutedBrush"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0) });

        var dock = new DockPanel();
        dock.Children.Add(button);
        dock.Children.Add(text);
        return new Border
        {
            Background = R("AccentSoftBrush"), CornerRadius = new CornerRadius(10),
            Padding = new Thickness(14, 10, 12, 10), Margin = new Thickness(0, 6, 0, 0), Child = dock
        };
    }

    /// <summary>Creates and freezes a solid-color brush.</summary>
    private static Brush Freeze(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }
}
