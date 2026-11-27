using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace Phrasia;

/// <summary>The values edited in the Settings window (copied in, read back after Save).</summary>
internal sealed class SettingsValues
{
    // security
    public int AutoLockMinutes { get; set; } = AppSettings.DefaultAutoLockMinutes;
    public bool LockOnMinimize { get; set; } = true;
    public int ClipboardClearSeconds { get; set; } = AppSettings.DefaultClipboardClearSeconds;
    public bool ClearClipboardOnLock { get; set; } = true;
    // privacy
    public bool CaptureProtection { get; set; } = true;
    public int GeneratorIdleMinutes { get; set; } = AppSettings.DefaultGeneratorIdleMinutes;
    public bool HoverReveal { get; set; }
    // password health
    public int WeakBits { get; set; } = AppSettings.DefaultWeakBits;
    public int CriticalBits { get; set; } = AppSettings.DefaultCriticalBits;
    public int OldAfterMonths { get; set; } = AppSettings.DefaultOldAfterMonths;
    // backups
    public int AutoBackupCount { get; set; } = AppSettings.DefaultAutoBackupCount;
    public bool AutoBackupDaily { get; set; } = true;
    public string AutoBackupFolder { get; set; } = "";
    // general
    public string StartTab { get; set; } = "generator";
    public bool SearchNotes { get; set; }
    public string Theme { get; set; } = "system";
    // updates & logs
    public bool CheckForUpdates { get; set; } = true;
    public string? SkippedVersion { get; set; }
    public string LogLevel { get; set; } = "normal";
    public int LogKeepDays { get; set; } = AppSettings.DefaultLogKeepDays;

    public static SettingsValues From(PresetFile f) => new()
    {
        AutoLockMinutes = f.AutoLockMinutes,
        LockOnMinimize = f.LockOnMinimize,
        ClipboardClearSeconds = f.ClipboardClearSeconds,
        ClearClipboardOnLock = f.ClearClipboardOnLock,
        CaptureProtection = f.CaptureProtection,
        GeneratorIdleMinutes = f.GeneratorIdleMinutes,
        HoverReveal = f.HoverReveal,
        WeakBits = f.WeakBits,
        CriticalBits = f.CriticalBits,
        OldAfterMonths = f.OldAfterMonths,
        AutoBackupCount = f.AutoBackupCount,
        AutoBackupDaily = f.AutoBackupDaily,
        AutoBackupFolder = f.AutoBackupFolder,
        StartTab = f.StartTab,
        SearchNotes = f.SearchNotes,
        Theme = f.Theme,
        CheckForUpdates = f.CheckForUpdates,
        SkippedVersion = f.SkippedVersion,
        LogLevel = f.LogLevel,
        LogKeepDays = f.LogKeepDays,
    };

    public void CopyTo(PresetFile f)
    {
        f.AutoLockMinutes = AutoLockMinutes;
        f.LockOnMinimize = LockOnMinimize;
        f.ClipboardClearSeconds = ClipboardClearSeconds;
        f.ClearClipboardOnLock = ClearClipboardOnLock;
        f.CaptureProtection = CaptureProtection;
        f.GeneratorIdleMinutes = GeneratorIdleMinutes;
        f.HoverReveal = HoverReveal;
        f.WeakBits = WeakBits;
        f.CriticalBits = CriticalBits;
        f.OldAfterMonths = OldAfterMonths;
        f.AutoBackupCount = AutoBackupCount;
        f.AutoBackupDaily = AutoBackupDaily;
        f.AutoBackupFolder = AutoBackupFolder;
        f.StartTab = StartTab;
        f.SearchNotes = SearchNotes;
        f.Theme = Theme;
        f.CheckForUpdates = CheckForUpdates;
        f.SkippedVersion = SkippedVersion;
        f.LogLevel = LogLevel;
        f.LogKeepDays = LogKeepDays;
        f.Normalize();
    }
}

/// <summary>
/// The Settings window – the only place where app settings are changed. Categories on the left:
/// Security, Privacy, Password health, Backups, General, Updates &amp; logs.
/// Unlock strength (Argon2id time, PIM, device binding, master password) stays on the vault buttons, because
/// changing it re-encrypts the vault and needs the master password.
/// </summary>
internal sealed class SettingsDialog : Window
{
    // security
    private readonly ComboBox _autoLock = Combo();
    private readonly CheckBox _lockOnMinimize = Toggle("Lock the vault when the window is minimized");
    private readonly ComboBox _clipboard = Combo();
    private readonly CheckBox _clearClipboardOnLock = Toggle("Clear a copied password when the vault locks");
    // privacy
    private readonly CheckBox _capture = Toggle("Hide Phrasia from screenshots, screen recording and screen sharing");
    private readonly ComboBox _generatorIdle = Combo();
    private readonly CheckBox _hoverReveal = Toggle("Reveal masked generated passwords while the mouse is over them");
    // password health
    private readonly ComboBox _weakBits = Combo();
    private readonly ComboBox _criticalBits = Combo();
    private readonly ComboBox _oldAfter = Combo();
    // backups
    private readonly ComboBox _backupCount = Combo();
    private readonly ComboBox _backupWhen = Combo();
    private readonly TextBox _backupFolder = new() { IsReadOnly = true, Margin = new Thickness(0, 6, 0, 0) };
    private readonly TextBlock _backupInfo = HintBlock("");
    // general
    private readonly ComboBox _startTab = Combo();
    private readonly CheckBox _searchNotes = Toggle("Search also looks inside notes");
    private readonly ComboBox _theme = Combo();
    // updates & logs
    private readonly CheckBox _updates = Toggle("Check GitHub for a newer version at startup");
    private readonly Button _checkNow = SmallButton("Check now");
    private readonly TextBlock _skippedText = HintBlock("");
    private readonly Button _unskip = SmallButton("Offer it again");
    private readonly ComboBox _logLevel = Combo();
    private readonly ComboBox _logKeep = Combo();
    private readonly Button _deleteLogs = SmallButton("Delete all logs now");

    private readonly TextBlock _warning = new() { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
    private readonly ContentControl _page = new();
    private readonly ListBox _nav = new() { Width = 170, BorderThickness = new Thickness(0), Background = Brushes.Transparent };
    private string? _skippedVersion;

    /// <summary>The edited values (valid after the dialog returns true).</summary>
    public SettingsValues Values { get; private set; }

    public SettingsDialog(MainWindow owner, SettingsValues current, string? initialSection = null)
    {
        Owner = owner;
        Title = "Settings";
        Width = 800;
        Height = Math.Min(640, SystemParameters.WorkArea.Height - 60);
        MinWidth = 700;
        MinHeight = 480;
        ResizeMode = ResizeMode.CanResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = R("WindowBrush");
        Foreground = R("TextBrush");
        _warning.Foreground = R("WarningBrush");
        _error.Foreground = R("DangerBrush");
        Values = current;

        FillChoices();
        WireEvents(owner);

        var sections = new (string Name, string Icon, FrameworkElement Page)[]
        {
            ("Security", "", SecurityPage()),
            ("Privacy", "", PrivacyPage()),
            ("Password health", "", HealthPage()),
            ("Backups", "", BackupPage()),
            ("General", "", GeneralPage()),
            ("Updates & logs", "", UpdatesPage()),
        };
        foreach (var (name, icon, page) in sections)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4, 3, 4, 3) };
            row.Children.Add(new TextBlock { Text = icon, Style = (Style)Application.Current.Resources["Icon"] });
            row.Children.Add(new TextBlock { Text = name, VerticalAlignment = VerticalAlignment.Center });
            _nav.Items.Add(new ListBoxItem { Content = row, Tag = page });
        }
        _nav.SelectionChanged += (_, _) =>
        {
            if (_nav.SelectedItem is ListBoxItem { Tag: FrameworkElement page }) _page.Content = page;
        };
        _nav.SelectedIndex = Math.Max(0, Array.FindIndex(sections, s => s.Name == initialSection));

        // ---- layout: navigation | page ; bottom: warning + buttons ----
        var reset = new Button { Content = "Reset all to defaults", Style = (Style)Application.Current.Resources["GhostButton"] };
        reset.Click += (_, _) =>
        {
            var d = new SettingsValues { SkippedVersion = _skippedVersion };
            Load(d);
        };
        var save = new Button { Content = "Save", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 0, 8, 0), Style = (Style)Application.Current.Resources["PrimaryButton"] };
        save.Click += (_, _) => Save();
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90, Style = (Style)Application.Current.Resources["GhostButton"] };

        var buttons = new DockPanel { LastChildFill = false, Margin = new Thickness(0, 12, 0, 0) };
        DockPanel.SetDock(reset, Dock.Left);
        DockPanel.SetDock(cancel, Dock.Right);
        DockPanel.SetDock(save, Dock.Right);
        buttons.Children.Add(reset);
        buttons.Children.Add(cancel);
        buttons.Children.Add(save);

        var bottom = new StackPanel { Margin = new Thickness(20, 0, 20, 16) };
        bottom.Children.Add(_warning);
        bottom.Children.Add(_error);
        bottom.Children.Add(buttons);

        var navBorder = new Border
        {
            Background = R("SurfaceBrush"),
            BorderBrush = R("LineBrush"),
            BorderThickness = new Thickness(0, 0, 1, 0),
            Padding = new Thickness(10, 14, 10, 14),
            Child = _nav,
        };
        var scroller = new ScrollViewer
        {
            Content = _page,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(24, 18, 24, 18),
        };

        var main = new DockPanel();
        DockPanel.SetDock(bottom, Dock.Bottom);
        DockPanel.SetDock(navBorder, Dock.Left);
        main.Children.Add(bottom);
        main.Children.Add(navBorder);
        main.Children.Add(scroller);
        Content = main;

        Load(current);

        // the window shows no secrets, but follows the main window so a shared screen looks consistent
        SourceInitialized += (_, _) => { if (owner.IsCaptureProtectionOn) MainWindow.ApplyCaptureProtection(this, true); };
    }

    // ---------------- pages ----------------

    private FrameworkElement SecurityPage() => Page("Security",
        Section("VAULT", first: true),
        Row("Lock automatically after", _autoLock, "Counted from your last key press or click while the vault is open."),
        _lockOnMinimize,
        ToggleHint("Locking Windows, signing out or putting the computer to sleep always locks the vault."),
        Section("CLIPBOARD"),
        Row("Clear copied passwords after", _clipboard,
            "Phrasia clears the clipboard only if it still holds the password it copied. Copied passwords never go to the Windows clipboard history (Win+V) or the cloud clipboard."),
        _clearClipboardOnLock,
        Section("UNLOCKING"),
        HintBlock("The unlock time (Argon2id strength), PIM, device binding and master password re-encrypt the vault, so they are " +
                  "changed with the buttons in the unlocked vault (Tune to this PC…, Change master password…)."));

    private FrameworkElement PrivacyPage() => Page("Privacy",
        Section("SCREEN", first: true),
        _capture,
        ToggleHint("Windows 10 2004 and newer leave the window out completely; older versions show a black area instead."),
        Section("GENERATOR"),
        Row("Hide generated passwords after", _generatorIdle,
            "They are also hidden when the window is minimized, Windows locks or the computer sleeps."),
        _hoverReveal);

    private FrameworkElement HealthPage() => Page("Password health",
        HintBlock("Used by the badges in the item list, the strength hint in the editor and the Analyze report."),
        Section("STRENGTH"),
        Row("Weak below (normal accounts)", _weakBits, null),
        Row("Weak below (critical accounts)", _criticalBits,
            "Critical accounts – e-mail, bank, work – deserve a stricter limit. A 5-word Phrasia passphrase has about 65–75 bits."),
        Section("AGE"),
        Row("Flag passwords as old after", _oldAfter,
            "Old passwords are more likely to appear in past data breaches."));

    private FrameworkElement BackupPage()
    {
        var change = SmallButton("Change…");
        change.Click += (_, _) => PickBackupFolder();
        var reset = SmallButton("Default");
        reset.Click += (_, _) => { _backupFolder.Text = ""; UpdateBackupInfo(); };
        var open = SmallButton("Open folder");
        open.Click += (_, _) => OpenFolder(CurrentBackupFolder());
        var folderButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
        folderButtons.Children.Add(change);
        folderButtons.Children.Add(reset);
        folderButtons.Children.Add(open);

        return Page("Backups",
            HintBlock("Phrasia can keep copies of the encrypted vault file automatically. A copy opens with the master password and PIM " +
                      "that were valid when it was made – restore it with “Restore from backup” on the locked screen, or merge it " +
                      "with “Import items from backup”."),
            Section("AUTOMATIC BACKUPS"),
            Row("Keep", _backupCount, null),
            Row("Make a backup", _backupWhen, null),
            Section("FOLDER"),
            _backupFolder,
            folderButtons,
            HintBlock("Tip: choose a folder on another drive or in a synced cloud folder – the copies stay encrypted."),
            _backupInfo);
    }

    private FrameworkElement GeneralPage() => Page("General",
        Section("STARTUP", first: true),
        Row("Open Phrasia on", _startTab, null),
        Section("VAULT LIST"),
        _searchNotes,
        Section("APPEARANCE"),
        Row("Theme", _theme, "“Follow Windows” switches with the Windows light/dark app mode."));

    private FrameworkElement UpdatesPage()
    {
        var updateRow = new DockPanel { Margin = new Thickness(0, 10, 0, 0) };
        DockPanel.SetDock(_checkNow, Dock.Right);
        updateRow.Children.Add(_checkNow);
        _updates.Margin = new Thickness(0);
        _updates.VerticalAlignment = VerticalAlignment.Center;
        updateRow.Children.Add(_updates);

        var skippedRow = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
        DockPanel.SetDock(_unskip, Dock.Right);
        skippedRow.Children.Add(_unskip);
        _skippedText.VerticalAlignment = VerticalAlignment.Center;
        _skippedText.Margin = new Thickness(0);
        skippedRow.Children.Add(_skippedText);

        return Page("Updates & logs",
            Section("UPDATES", first: true),
            updateRow,
            ToggleHint("Only the app version is sent to GitHub. Nothing is downloaded or installed automatically."),
            skippedRow,
            Section("LOG"),
            Row("Logging", _logLevel,
                "The log never contains passwords, titles, usernames or notes – only events and errors. It is encrypted for your Windows account."),
            Row("Keep log files for", _logKeep, null),
            _deleteLogs);
    }

    // ---------------- values ----------------

    private void FillChoices()
    {
        Fill(_autoLock, AppSettings.AutoLockChoices, Minutes, AppSettings.DefaultAutoLockMinutes);
        Fill(_clipboard, AppSettings.ClipboardChoices, s => $"{s} seconds", AppSettings.DefaultClipboardClearSeconds);
        Fill(_generatorIdle, AppSettings.GeneratorIdleChoices, Minutes, AppSettings.DefaultGeneratorIdleMinutes);
        Fill(_weakBits, AppSettings.WeakBitsChoices, b => $"{b} bits", AppSettings.DefaultWeakBits);
        Fill(_criticalBits, AppSettings.CriticalBitsChoices, b => $"{b} bits", AppSettings.DefaultCriticalBits);
        Fill(_oldAfter, AppSettings.OldAfterMonthsChoices,
             m => m == 0 ? "Never" : m % 12 == 0 ? (m == 12 ? "1 year" : $"{m / 12} years") : $"{m} months",
             AppSettings.DefaultOldAfterMonths);
        Fill(_backupCount, AppSettings.AutoBackupCountChoices, n => n == 0 ? "Off" : $"{n} newest copies",
             AppSettings.DefaultAutoBackupCount);
        Fill(_logKeep, AppSettings.LogKeepDaysChoices, d => $"{d} days", AppSettings.DefaultLogKeepDays);

        Add(_backupWhen, "Once a day", true);
        Add(_backupWhen, "After every change", false);
        Add(_startTab, "Generator", "generator");
        Add(_startTab, "Vault", "vault");
        Add(_theme, "Follow Windows", "system");
        Add(_theme, "Light", "light");
        Add(_theme, "Dark", "dark");
        Add(_logLevel, "Off", "off");
        Add(_logLevel, "Normal (default)", "normal");
        Add(_logLevel, "Detailed – for troubleshooting", "detailed");

        static string Minutes(int m) => m == 1 ? "1 minute" : $"{m} minutes";
    }

    private void WireEvents(MainWindow owner)
    {
        foreach (var cb in new[] { _autoLock, _clipboard, _generatorIdle, _weakBits, _criticalBits, _logLevel })
            cb.SelectionChanged += (_, _) => UpdateWarning();
        foreach (var t in new[] { _lockOnMinimize, _clearClipboardOnLock, _capture })
        {
            t.Checked += (_, _) => UpdateWarning();
            t.Unchecked += (_, _) => UpdateWarning();
        }
        _backupCount.SelectionChanged += (_, _) => UpdateBackupInfo();
        _backupWhen.SelectionChanged += (_, _) => UpdateBackupInfo();

        _checkNow.Click += async (_, _) =>
        {
            _checkNow.IsEnabled = false;
            try { await owner.CheckForUpdatesNowAsync(this); }
            finally { _checkNow.IsEnabled = true; }
        };
        _unskip.Click += (_, _) => { _skippedVersion = null; UpdateSkipped(); };
        _deleteLogs.Click += (_, _) =>
        {
            var answer = AppMessageBox.Show(this, "Delete all Phrasia log files now?", "Delete logs",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes) return;
            int n = Logging.DeleteAll();
            AppMessageBox.Show(this, n == 0 ? "There were no log files." : $"{n} log file{(n == 1 ? "" : "s")} deleted.",
                "Delete logs", MessageBoxButton.OK, MessageBoxImage.Information);
        };
    }

    /// <summary>Puts the values into the controls.</summary>
    private void Load(SettingsValues v)
    {
        Select(_autoLock, v.AutoLockMinutes);
        _lockOnMinimize.IsChecked = v.LockOnMinimize;
        Select(_clipboard, v.ClipboardClearSeconds);
        _clearClipboardOnLock.IsChecked = v.ClearClipboardOnLock;
        _capture.IsChecked = v.CaptureProtection;
        Select(_generatorIdle, v.GeneratorIdleMinutes);
        _hoverReveal.IsChecked = v.HoverReveal;
        Select(_weakBits, v.WeakBits);
        Select(_criticalBits, v.CriticalBits);
        Select(_oldAfter, v.OldAfterMonths);
        Select(_backupCount, v.AutoBackupCount);
        Select(_backupWhen, v.AutoBackupDaily);
        _backupFolder.Text = v.AutoBackupFolder;
        Select(_startTab, v.StartTab);
        _searchNotes.IsChecked = v.SearchNotes;
        Select(_theme, v.Theme);
        _updates.IsChecked = v.CheckForUpdates;
        _skippedVersion = v.SkippedVersion;
        Select(_logLevel, v.LogLevel);
        Select(_logKeep, v.LogKeepDays);
        UpdateSkipped();
        UpdateBackupInfo();
        UpdateWarning();
        _error.Text = "";
    }

    /// <summary>Reads the controls back into a new value object.</summary>
    private SettingsValues Read() => new()
    {
        AutoLockMinutes = Selected<int>(_autoLock),
        LockOnMinimize = _lockOnMinimize.IsChecked == true,
        ClipboardClearSeconds = Selected<int>(_clipboard),
        ClearClipboardOnLock = _clearClipboardOnLock.IsChecked == true,
        CaptureProtection = _capture.IsChecked == true,
        GeneratorIdleMinutes = Selected<int>(_generatorIdle),
        HoverReveal = _hoverReveal.IsChecked == true,
        WeakBits = Selected<int>(_weakBits),
        CriticalBits = Selected<int>(_criticalBits),
        OldAfterMonths = Selected<int>(_oldAfter),
        AutoBackupCount = Selected<int>(_backupCount),
        AutoBackupDaily = Selected<bool>(_backupWhen),
        AutoBackupFolder = _backupFolder.Text.Trim(),
        StartTab = Selected<string>(_startTab) ?? "generator",
        SearchNotes = _searchNotes.IsChecked == true,
        Theme = Selected<string>(_theme) ?? "system",
        CheckForUpdates = _updates.IsChecked == true,
        SkippedVersion = _skippedVersion,
        LogLevel = Selected<string>(_logLevel) ?? "normal",
        LogKeepDays = Selected<int>(_logKeep),
    };

    /// <summary>Validates and closes with OK.</summary>
    private void Save()
    {
        var v = Read();
        if (v.CriticalBits < v.WeakBits)
        {
            _error.Text = "The limit for critical accounts must not be lower than the one for normal accounts (Password health).";
            _nav.SelectedIndex = 2;
            return;
        }
        if (v.AutoBackupCount > 0 && v.AutoBackupFolder.Length > 0)
        {
            try { Directory.CreateDirectory(v.AutoBackupFolder); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                _error.Text = "The backup folder cannot be used: " + ex.Message;
                _nav.SelectedIndex = 3;
                return;
            }
        }
        Values = v;
        DialogResult = true;
    }

    /// <summary>Plain-language note when a choice weakens protection (allowed – the user decides).</summary>
    private void UpdateWarning()
    {
        var notes = new List<string>();
        if (Selected<int>(_autoLock) >= 15) notes.Add("the vault stays open for a long time when you walk away");
        if (_lockOnMinimize.IsChecked != true) notes.Add("a minimized window keeps the vault open");
        if (Selected<int>(_clipboard) >= 60) notes.Add("copied passwords stay on the clipboard where any app can read them");
        if (_clearClipboardOnLock.IsChecked != true) notes.Add("locking does not remove a copied password");
        if (_capture.IsChecked != true) notes.Add("screenshots and screen sharing will show your passwords");
        if (Selected<int>(_weakBits) < AppSettings.DefaultWeakBits || Selected<int>(_criticalBits) < AppSettings.DefaultCriticalBits)
            notes.Add("weaker passwords will no longer be flagged");
        if (Selected<string>(_logLevel) == "detailed") notes.Add("detailed logging writes more about what you do (still never passwords)");

        _warning.Text = notes.Count == 0 ? "" : "Less protection: " + string.Join("; ", notes) + ".";
        _warning.Margin = new Thickness(0, notes.Count == 0 ? 0 : 10, 0, 0);
    }

    private string CurrentBackupFolder() =>
        string.IsNullOrWhiteSpace(_backupFolder.Text) ? AutoBackup.DefaultFolder : _backupFolder.Text.Trim();

    /// <summary>Shows the folder in use and how many automatic backups exist there.</summary>
    private void UpdateBackupInfo()
    {
        bool on = Selected<int>(_backupCount) > 0;
        _backupWhen.IsEnabled = _backupFolder.IsEnabled = on;
        string folder = CurrentBackupFolder();
        string where = string.IsNullOrWhiteSpace(_backupFolder.Text) ? $"Default folder: {folder}" : $"Folder: {folder}";
        try
        {
            var list = AutoBackup.List(folder);
            _backupInfo.Text = where + "\n" + (list.Count == 0
                ? "No automatic backups yet."
                : $"{list.Count} automatic backup{(list.Count == 1 ? "" : "s")}, newest {list[0].Time:g}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            _backupInfo.Text = where;
        }
        if (!on) _backupInfo.Text += "\nAutomatic backups are off – existing copies are kept.";
    }

    private void UpdateSkipped()
    {
        bool any = !string.IsNullOrEmpty(_skippedVersion);
        _skippedText.Text = any ? $"Skipped version: {_skippedVersion} (its update notice is not shown)." : "No version is skipped.";
        _unskip.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
    }

    private void PickBackupFolder()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Folder for automatic vault backups",
            InitialDirectory = Directory.Exists(CurrentBackupFolder()) ? CurrentBackupFolder() : "",
        };
        if (dlg.ShowDialog(this) != true) return;
        _backupFolder.Text = dlg.FolderName;
        UpdateBackupInfo();
    }

    private void OpenFolder(string folder)
    {
        try
        {
            Directory.CreateDirectory(folder);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{folder}\"") { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or ArgumentException)
        {
            AppMessageBox.Show(this, "Could not open the folder: " + ex.Message, "Backups", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // ---------------- building blocks ----------------

    private static Brush R(string key) => (Brush)Application.Current.Resources[key];

    private static StackPanel Page(string title, params FrameworkElement[] children)
    {
        var p = new StackPanel();
        p.Children.Add(new TextBlock { Text = title, Style = (Style)Application.Current.Resources["CardTitle"], Margin = new Thickness(0, 0, 0, 8) });
        foreach (var c in children) p.Children.Add(c);
        return p;
    }

    private static ComboBox Combo() => new() { Width = 210, Margin = new Thickness(0) };

    private static Button SmallButton(string text) => new()
    {
        Content = text,
        Style = (Style)Application.Current.Resources["GhostButton"],
        Padding = new Thickness(10, 5, 10, 5),
        Margin = new Thickness(0, 0, 6, 0),
        HorizontalAlignment = HorizontalAlignment.Left,
    };

    private static CheckBox Toggle(string text) => new()
    {
        Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap },
        Margin = new Thickness(0, 12, 0, 0),
    };

    private static TextBlock Section(string text, bool first = false) => new()
    {
        Text = text,
        Style = (Style)Application.Current.Resources["SectionLabel"],
        Margin = new Thickness(0, first ? 6 : 22, 0, 2),
    };

    private static TextBlock HintBlock(string text) => new()
    {
        Text = text,
        Style = (Style)Application.Current.Resources["HintText"],
        FontSize = 12,
        Margin = new Thickness(0, 8, 0, 0),
    };

    /// <summary>A hint aligned with the text of the toggle above it.</summary>
    private static TextBlock ToggleHint(string text)
    {
        var t = HintBlock(text);
        t.Margin = new Thickness(46, 4, 0, 0);
        return t;
    }

    /// <summary>"Label ............ [combo]" with an optional hint underneath.</summary>
    private static FrameworkElement Row(string label, ComboBox combo, string? hint)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 12, 0, 0) };
        var line = new DockPanel();
        DockPanel.SetDock(combo, Dock.Right);
        line.Children.Add(combo);
        line.Children.Add(new TextBlock { Text = label, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(line);
        if (hint is not null)
        {
            var h = HintBlock(hint);
            h.Margin = new Thickness(0, 4, 0, 0);
            panel.Children.Add(h);
        }
        return panel;
    }

    private static void Fill(ComboBox combo, int[] values, Func<int, string> label, int recommended)
    {
        foreach (var v in values)
            Add(combo, label(v) + (v == recommended ? " (default)" : ""), v);
    }

    private static void Add(ComboBox combo, string label, object tag) =>
        combo.Items.Add(new ComboBoxItem { Content = label, Tag = tag });

    private static void Select(ComboBox combo, object value) =>
        combo.SelectedItem = combo.Items.Cast<ComboBoxItem>().FirstOrDefault(i => Equals(i.Tag, value)) ?? combo.Items[0];

    private static T? Selected<T>(ComboBox combo) => (combo.SelectedItem as ComboBoxItem)?.Tag is T v ? v : default;
}
