using System.IO;
using System.Windows;

namespace Phrasia;

/// <summary>
/// The Settings window and applying its values. Settings live ONLY in the Settings window – the main window has
/// no duplicate toggles; it just follows <see cref="_presetFile"/>.
/// </summary>
public partial class MainWindow
{
    private bool _autoBackupWarned; // show a failed automatic backup only once per session

    /// <summary>Opens the Settings window (header button or Ctrl+,) and applies the saved values.</summary>
    private void OpenSettings_Click(object sender, RoutedEventArgs e)
    {
        var before = SettingsValues.From(_presetFile);
        var dlg = new SettingsDialog(this, SettingsValues.From(_presetFile));
        if (dlg.ShowDialog() != true) return;

        var after = dlg.Values;
        after.CopyTo(_presetFile);
        if (!PresetStore.Save(_presetFile))
            AppMessageBox.Show(this, "The settings apply now, but could not be saved for the next start.",
                "Settings", MessageBoxButton.OK, MessageBoxImage.Warning);

        ApplySettings();
        if (before.Theme != after.Theme) ThemeManager.Apply(ThemeManager.Parse(after.Theme));
        if (before.LogLevel != after.LogLevel || before.LogKeepDays != after.LogKeepDays)
            Logging.Configure(after.LogLevel, after.LogKeepDays);
        if (!after.CheckForUpdates) UpdateBanner.Visibility = Visibility.Collapsed;
        else if (!before.CheckForUpdates || (before.SkippedVersion is not null && after.SkippedVersion is null))
            _ = CheckForUpdateAsync(TimeSpan.Zero);
        if (_vault is not null && (before.AutoBackupCount != after.AutoBackupCount || before.AutoBackupFolder != after.AutoBackupFolder
                                   || before.AutoBackupDaily != after.AutoBackupDaily))
        {
            _autoBackupWarned = false;
            RunAutoBackup();
        }

        Log.Info("Settings saved: auto-lock {AutoLock} min, lock on minimize {Minimize}, clipboard {Clipboard} s, " +
                 "clear on lock {ClearOnLock}, capture protection {Capture}, generator idle {Idle} min, hover reveal {Hover}, " +
                 "weak < {Weak}/{Critical} bits, old after {Old} months, auto-backups {Backups} ({When}), start tab {Tab}, " +
                 "search notes {Notes}, theme {Theme}, update check {Updates}, log {Level}/{Days} d",
            after.AutoLockMinutes, after.LockOnMinimize, after.ClipboardClearSeconds, after.ClearClipboardOnLock,
            after.CaptureProtection, after.GeneratorIdleMinutes, after.HoverReveal, after.WeakBits, after.CriticalBits,
            after.OldAfterMonths, after.AutoBackupCount, after.AutoBackupDaily ? "daily" : "every change", after.StartTab,
            after.SearchNotes, after.Theme, after.CheckForUpdates, after.LogLevel, after.LogKeepDays);
        ShowStatus("Settings saved ✓");
        if (_vault is not null) ShowEntryStatus("Settings saved ✓");
    }

    /// <summary>Applies the stored settings to the running window: timers, screen-capture protection,
    /// hover reveal, password-health thresholds and the vault list.</summary>
    private void ApplySettings()
    {
        _autoLockTimer.Interval = TimeSpan.FromMinutes(AutoLockMinutes);
        _clipboardTimer.Interval = TimeSpan.FromSeconds(ClipboardClearSeconds);
        _generatorIdleTimer.Interval = TimeSpan.FromMinutes(GeneratorIdleMinutes);

        // restart running countdowns so a shorter delay takes effect right away
        if (_autoLockTimer.IsEnabled) { _autoLockTimer.Stop(); _autoLockTimer.Start(); }
        if (_generatorIdleTimer.IsEnabled) { _generatorIdleTimer.Stop(); _generatorIdleTimer.Start(); }
        if (_clipboardTimer.IsEnabled) { _clipboardTimer.Stop(); _clipboardTimer.Start(); }

        ApplyCaptureProtection(_presetFile.CaptureProtection);
        ApplyHoverReveal();

        VaultAnalyzer.WeakBits = _presetFile.WeakBits;
        VaultAnalyzer.CriticalBits = _presetFile.CriticalBits;
        VaultAnalyzer.OldAfterMonths = _presetFile.OldAfterMonths;
        VaultHealthText.ToolTip = $"Reused = the same password in more than one item. Weak = estimated strength under " +
                                  $"{_presetFile.WeakBits} bits ({_presetFile.CriticalBits} bits for critical accounts).";
        SearchBox.ToolTip = _presetFile.SearchNotes
            ? "Search by title, username, website or notes"
            : "Search by title, username or website";

        if (_vault is not null && !IsVaultBusy)
        {
            RefreshList(EntriesList.SelectedItem as VaultEntry); // new thresholds → badges, new search scope
            UpdateEntryPasswordInfo();
        }
    }

    /// <summary>Makes an automatic backup of the vault file when one is due (Settings › Backups). Never blocks
    /// saving: a failure is logged and shown once per session.</summary>
    private void RunAutoBackup()
    {
        if (_vault is null || _presetFile.AutoBackupCount <= 0) return;
        try
        {
            var created = AutoBackup.RunIfDue(_vault.FilePath, _presetFile);
            if (created is not null) Log.Info("Automatic vault backup created (keeping {Count})", _presetFile.AutoBackupCount);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Log.Warn("Automatic vault backup failed: {Error}", ex.Message);
            if (_autoBackupWarned) return;
            _autoBackupWarned = true;
            ShowEntryStatus("Automatic backup failed – check the folder in Settings › Backups.", error: true);
        }
    }
}
