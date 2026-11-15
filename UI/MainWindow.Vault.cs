using System.ComponentModel;
using System.Runtime.InteropServices;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace Phrasia;

/// <summary>The "Vault" tab – storing passwords in an encrypted file.</summary>
public partial class MainWindow
{
    private const int AutoLockMinutes = 5;
    private const int ClipboardClearSeconds = 20;

    private Vault? _vault;
    private VaultEntry? _editing;          // null = a new (not yet saved) entry
    private string? _pendingPassword;      // a password from the generator waiting for the vault to unlock
    private bool _syncingPassword;
    private bool _suppressSelection;
    private string? _clipboardValue;

    private readonly DispatcherTimer _autoLockTimer = new() { Interval = TimeSpan.FromMinutes(AutoLockMinutes) };
    private readonly DispatcherTimer _clipboardTimer = new() { Interval = TimeSpan.FromSeconds(ClipboardClearSeconds) };
    private readonly DispatcherTimer _entryStatusTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly DispatcherTimer _lockoutTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly UnlockThrottle _throttle = new(Vault.DefaultPath);
    private int _vaultOpsRunning;          // > 0 while a long vault operation runs in the background
    private bool _lockDeferred;            // a lock was requested during such an operation
    private string? _deferredLockMessage;

    /// <summary>True while a background operation (re-key, tuning, backup…) is using the vault.</summary>
    private bool IsVaultBusy => _vaultOpsRunning > 0;

    /// <summary>Initializes the vault tab: throttle, system-event hooks and the locked screen.</summary>
    private void InitVault()
    {
        _autoLockTimer.Tick += (_, _) => LockVault($"The vault was locked after {AutoLockMinutes} minutes of inactivity.");
        _clipboardTimer.Tick += (_, _) => ClearClipboardIfOurs();
        _entryStatusTimer.Tick += (_, _) => { EntryStatusText.Text = ""; _entryStatusTimer.Stop(); };
        _lockoutTimer.Tick += (_, _) => UpdateLockout();
        VaultPathText.Text = "Vault file: " + Vault.DefaultPath;
        ShowLocked(null);
        HookSystemEvents();

        Log.Info("Vault file {State}", File.Exists(Vault.DefaultPath) ? "found" : "not created yet");
        if (Argon2Kdf.IsAvailable)
            Log.Info("Argon2id self-test passed – key derivation: {Kdf}", Vault.KdfDescription);
        else
            Log.Error("{Error} – falling back to PBKDF2-HMAC-SHA512 (format v3)", Argon2Kdf.SelfTestError);
        if (_throttle.TamperDetected)
            Log.Warn("The unlock-attempt record was missing or modified – penalty applied");
        if (_throttle.RemainingLockout > TimeSpan.Zero)
            Log.Warn("Unlocking is blocked for another {Remaining}", FormatRemaining(_throttle.RemainingLockout));
    }

    // ---------------- lock / unlock ----------------

    /// <summary>Shows the locked/create screen (fields, PIM, device-binding notice) with an optional message.</summary>
    private void ShowLocked(string? message)
    {
        bool exists = File.Exists(Vault.DefaultPath);
        LockTitle.Text = exists ? "Vault is locked" : "Create your vault";
        LockHint.Text = exists
            ? "Enter your master password."
            : $"Choose a master password (at least {MasterPasswordPolicy.MinLength} characters). If you forget it, your saved passwords CANNOT be recovered.";
        ConfirmPanel.Visibility = exists ? Visibility.Collapsed : Visibility.Visible;
        UnlockButton.Content = exists ? "Unlock" : "Create vault";
        RestoreHeaderButton.Visibility = exists ? Visibility.Visible : Visibility.Collapsed;
        EraseVaultButton.Visibility = exists ? Visibility.Visible : Visibility.Collapsed;
        EraseVaultButton.IsEnabled = true;
        UnlockButton.IsEnabled = true;
        RestoreVaultButton.IsEnabled = RestoreHeaderButton.IsEnabled = true;
        LockError.Text = message ?? "";
        MasterBox.Clear();
        MasterConfirmBox.Clear();
        MasterStrengthText.Text = "";
        SuggestionPanel.Visibility = Visibility.Collapsed;
        SuggestionBox.Text = "";

        // PIM: a mandatory iteration multiplier (only when Argon2 is available)
        PimPanel.Visibility = Argon2Kdf.IsAvailable ? Visibility.Visible : Visibility.Collapsed;
        PimBox.Clear();

        // mandatory device binding: a notice for a new vault; device key import when unlocking
        DeviceBindNotice.Visibility = !exists && Argon2Kdf.IsAvailable ? Visibility.Visible : Visibility.Collapsed;
        ImportDeviceKeyButton.Visibility = exists && Argon2Kdf.IsAvailable ? Visibility.Visible : Visibility.Collapsed;
        PimHint.Text = exists
            ? $"Enter the PIM you chose when creating the vault. Leave blank only if your vault has none."
            : $"Required secret number {Vault.MinPim}–{Vault.MaxPim} you must remember, like a second password. " +
              "Higher = slower unlock but harder to crack. It is never stored anywhere.";
        LockedPanel.Visibility = Visibility.Visible;
        UnlockedPanel.Visibility = Visibility.Collapsed;
        if (exists) UpdateLockout();
        else { LockoutText.Text = ""; _lockoutTimer.Stop(); MasterBox.IsEnabled = true; }
    }

    /// <summary>Blocks unlocking until the throttle delay after failed attempts has elapsed.</summary>
    private bool UpdateLockout()
    {
        var remaining = _throttle.RemainingLockout;
        bool locked = remaining > TimeSpan.Zero && File.Exists(Vault.DefaultPath);

        UnlockButton.IsEnabled = !locked;
        RestoreHeaderButton.IsEnabled = !locked;
        RestoreVaultButton.IsEnabled = !locked;
        MasterBox.IsEnabled = !locked;

        if (locked)
        {
            string reason = _throttle.TamperDetected
                ? "The attempt record was tampered with – a penalty was applied. "
                : $"Too many wrong attempts ({_throttle.FailedAttempts}). ";
            LockoutText.Text = reason +
                               $"Next attempt possible in {FormatRemaining(remaining)}.\n" +
                               "The wait only counts down while the app is running.";
            if (!_lockoutTimer.IsEnabled) _lockoutTimer.Start();
            _throttle.CheckpointIfDue();
        }
        else
        {
            if (_lockoutTimer.IsEnabled)
            {
                _lockoutTimer.Stop();
                _throttle.Checkpoint(); // record that the wait has been served
                MasterBox.Focus();
            }
            LockoutText.Text = "";
        }
        return locked;
    }

    /// <summary>Formats a remaining duration, e.g. "0:35", "1:02:10", "3 d 4 h 12 min".</summary>
    private static string FormatRemaining(TimeSpan t)
    {
        t = TimeSpan.FromSeconds(Math.Ceiling(t.TotalSeconds));
        if (t.TotalDays >= 1) return $"{t.Days} d {t.Hours} h {t.Minutes} min";
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}";
        return $"{t.Minutes}:{t.Seconds:00}";
    }

    /// <summary>Updates the live strength hint for a new master password.</summary>
    private void MasterBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (ConfirmPanel.Visibility != Visibility.Visible) return;
        string pw = MasterBox.Password;
        if (pw.Length == 0) { MasterStrengthText.Text = ""; return; }

        double bits = MasterPasswordPolicy.EstimateBits(pw);
        string? problem = MasterPasswordPolicy.Validate(pw);
        MasterStrengthText.Text = problem ?? $"Strength ≈ {bits:F0} bits – good ✓";
        MasterStrengthText.Foreground = problem is null
            ? System.Windows.Media.Brushes.ForestGreen
            : System.Windows.Media.Brushes.Firebrick;
    }

    /// <summary>Suggests a strong master password and shows it to memorize.</summary>
    private void SuggestMaster_Click(object sender, RoutedEventArgs e)
    {
        if (!EntropyDialog.EnsureFresh(this, "your new master password")) return;
        string pw = MasterPasswordPolicy.Suggest(); // 5 random words + digits ≈ 90 bits

        MasterBox.Password = pw;
        MasterConfirmBox.Password = pw;
        SuggestionBox.Text = pw;
        SuggestionPanel.Visibility = Visibility.Visible;
    }

    /// <summary>Allows only digits in the PIM field.</summary>
    private void PimBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
    {
        e.Handled = !e.Text.All(char.IsDigit);
    }

    /// <summary>Reads the PIM from the locked-panel field. When <paramref name="mandatory"/> (new vault) it must be in range; otherwise blank = no PIM (0). On error it shows a message and returns false.</summary>
    private bool TryReadUnlockPim(bool mandatory, out int pim)
    {
        pim = 0;
        if (!Argon2Kdf.IsAvailable) return true;
        var t = PimBox.Text.Trim();
        if (t.Length == 0)
        {
            if (!mandatory) return true;
            LockError.Text = $"Choose a PIM between {Vault.MinPim} and {Vault.MaxPim}. You will need it every time you unlock.";
            return false;
        }
        if (!int.TryParse(t, out pim) || pim < Vault.MinPim || pim > Vault.MaxPim)
        {
            LockError.Text = $"The PIM must be a number between {Vault.MinPim} and {Vault.MaxPim}" + (mandatory ? "." : ", or blank.");
            pim = 0;
            return false;
        }
        return true;
    }

    /// <summary>Unlocks an existing vault or creates a new one (off the UI thread); handles wrong password/PIM and lockout.</summary>
    private async void Unlock_Click(object sender, RoutedEventArgs e)
    {
        string pw = MasterBox.Password;
        bool exists = File.Exists(Vault.DefaultPath);

        if (exists && UpdateLockout()) return;
        if (pw.Length == 0) { LockError.Text = "Enter your master password."; return; }
        if (!exists)
        {
            var problem = MasterPasswordPolicy.Validate(pw);
            if (problem is not null) { LockError.Text = problem; return; }
            if (pw != MasterConfirmBox.Password) { LockError.Text = "Passwords do not match."; return; }
        }

        // PIM: mandatory when creating a new vault; optional when unlocking (empty = no PIM)
        if (!TryReadUnlockPim(mandatory: !exists, out int pim)) return;
        if (!exists && !EntropyDialog.EnsureFresh(this, "the salt and device secret of your new vault")) return;

        UnlockButton.IsEnabled = false;
        UnlockButton.Content = exists ? "Unlocking…" : "Creating…";
        LockError.Text = "";

        try
        {
            // key derivation takes ~1 s – off the UI thread so the window does not freeze
            var path = Vault.DefaultPath;
            _vault = await Task.Run(() => exists ? Vault.Open(path, pw, pim) : Vault.Create(path, pw, pim));

            _throttle.Reset();
            if (!exists) EntropyPool.MarkConsumed(); // the next critical operation asks for fresh movement
            Log.Info(exists ? "Vault unlocked ({Count} items)" : "New vault created", _vault.Entries.Count);
            if (_vault.WasUpgraded) Log.Info("Vault upgraded to format v{Format} ({Kdf})", _vault.FormatVersion, _vault.KdfInfo);
            else if (!exists) Log.Info("Vault key derivation tuned to this PC: {Kdf}", _vault.KdfInfo);
            Log.Info("Vault format v{Format}, key derivation: {Kdf}", _vault.FormatVersion, _vault.KdfInfo);
            MasterBox.Clear();
            MasterConfirmBox.Clear();
            PimBox.Clear();
            SuggestionBox.Text = "";
            LockedPanel.Visibility = Visibility.Collapsed;
            UnlockedPanel.Visibility = Visibility.Visible;
            SearchBox.Text = "";
            RefreshList();

            if (_pendingPassword is not null)
            {
                StartNewEntry(_pendingPassword);
                _pendingPassword = null;
            }
            else if (EntriesList.Items.Count > 0)
                EntriesList.SelectedIndex = 0;
            else
                StartNewEntry("");

            _autoLockTimer.Start();
            UpdateDeviceBindingUi();
            if (_vault.WasUpgraded)
                ShowEntryStatus($"Vault upgraded – {_vault.KdfInfo} ✓");
        }
        catch (WrongPasswordException ex)
        {
            _throttle.RegisterFailure();
            Log.Warn("Unlock failed: wrong master password (failed attempts: {Attempts}, next wait: {Wait})",
                _throttle.FailedAttempts, FormatRemaining(_throttle.RemainingLockout));
            string msg = ex.Message;
            if (_throttle.AttemptsBeforeDelay > 0)
                msg += $" Attempts left before waiting: {_throttle.AttemptsBeforeDelay}.";
            ShowLocked(msg); // also shows the countdown if a wait is required
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException
                                      or FormatException or UnauthorizedAccessException
                                      or InvalidOperationException)
        {
            Log.Error(ex, "Unlocking the vault failed");
            ShowLocked("Error: " + ex.Message);
        }
    }

    /// <summary>Submits the unlock form on Enter.</summary>
    private void MasterBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        if (sender == MasterBox && ConfirmPanel.Visibility == Visibility.Visible)
            MasterConfirmBox.Focus();
        else
            Unlock_Click(sender, e);
    }

    /// <summary>Locks the vault on user request.</summary>
    private void Lock_Click(object sender, RoutedEventArgs e) => LockVault(null);

    /// <summary>Locks the vault: disposes the key, clears the device cache and editor, and shows the locked screen.</summary>
    private void LockVault(string? message)
    {
        if (IsVaultBusy)
        {
            // a background operation is using the vault – lock right after it finishes (it cannot be interrupted safely)
            if (!_lockDeferred) (_lockDeferred, _deferredLockMessage) = (true, message);
            ShowEntryStatus("The vault will lock as soon as the current operation finishes…");
            return;
        }
        if (_vault is not null) Log.Info("Vault locked: {Reason}", message ?? "by the user");
        _autoLockTimer.Stop();
        _vault?.Dispose();
        _vault = null;
        DeviceKeyStore.ClearCache(); // do not keep the device secret in RAM after locking
        _editing = null;
        _suppressSelection = true;
        EntriesList.ItemsSource = null;
        _suppressSelection = false;
        ClearEditor();
        VaultHealthText.Text = "";
        SetAttentionFilter(null);
        ShowLocked(message);
    }

    /// <summary>Runs a long vault operation (re-key, tuning, backup…) on a background thread. Meanwhile the vault UI
    /// is disabled and lock requests (Ctrl+L, minimize, auto-lock, Windows lock/sleep) are deferred until it finishes –
    /// locking mid-operation would wipe the key the operation is using.</summary>
    private async Task<T> RunVaultOperationAsync<T>(Func<T> operation)
    {
        _vaultOpsRunning++;
        UnlockedPanel.IsEnabled = false;
        _autoLockTimer.Stop();
        try
        {
            return await Task.Run(operation);
        }
        finally
        {
            if (--_vaultOpsRunning == 0)
            {
                UnlockedPanel.IsEnabled = true;
                if (_lockDeferred)
                {
                    var message = _deferredLockMessage;
                    (_lockDeferred, _deferredLockMessage) = (false, null);
                    LockVault(message);
                }
                else if (_vault is not null)
                {
                    _autoLockTimer.Start();
                }
            }
        }
    }

    /// <summary>Overload of <see cref="RunVaultOperationAsync{T}(Func{T})"/> for operations without a result.</summary>
    private Task RunVaultOperationAsync(Action operation) =>
        RunVaultOperationAsync(() => { operation(); return true; });

    // ---------------- password analysis ----------------

    private HashSet<Guid>? _attentionFilter;

    /// <summary>Runs the local password analysis and shows the report, applying the chosen follow-up action.</summary>
    private void Analyze_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null) return;
        var analysis = VaultAnalyzer.Analyze(_vault.Entries);
        Log.Info("Password analysis: score {Score}, {Attention} of {Total} items need attention " +
                 "({Reused} reused, {Weak} weak, {Old} old)",
            analysis.Score, analysis.NeedsAttention.Count, analysis.Total,
            analysis.ReusedCount, analysis.Weak.Count, analysis.Old.Count);
        var dlg = new AnalysisReportDialog(this, analysis);
        if (dlg.ShowDialog() != true || _vault is null) return;

        switch (dlg.Action)
        {
            case AnalysisAction.ShowAttention:
                SetAttentionFilter(analysis.NeedsAttention);
                var first = (EntriesList.ItemsSource as IEnumerable<VaultEntry>)?.FirstOrDefault();
                if (first is not null) EntriesList.SelectedItem = first;
                break;

            case AnalysisAction.MarkCritical:
                foreach (var entry in analysis.SuggestedCritical) entry.Critical = true;
                if (TrySaveVault())
                {
                    RefreshList(_editing);
                    if (_editing is not null) CriticalCheck.IsChecked = _editing.Critical;
                    ShowEntryStatus($"{analysis.SuggestedCritical.Count} account(s) marked as critical ✓");
                }
                break;

            case AnalysisAction.Backup:
                BackupVault_Click(sender, e);
                break;
        }
    }

    /// <summary>Filters the entry list to a set of ids that need attention (or clears the filter).</summary>
    private void SetAttentionFilter(HashSet<Guid>? ids)
    {
        _attentionFilter = ids is { Count: > 0 } ? new HashSet<Guid>(ids) : null;
        AttentionFilterBar.Visibility = _attentionFilter is null ? Visibility.Collapsed : Visibility.Visible;
        AttentionFilterText.Text = _attentionFilter is null ? ""
            : $"Showing {_attentionFilter.Count} item(s) that need attention. Fix one: open it, click ↻, Save – and change it on the website.";
        RefreshList(EntriesList.SelectedItem as VaultEntry);
    }

    /// <summary>Clears the attention filter.</summary>
    private void ClearAttentionFilter_Click(object sender, RoutedEventArgs e) => SetAttentionFilter(null);

    /// <summary>A new password from the generator settings (empty if generation fails).</summary>
    private string TryGeneratePassword()
    {
        try { return CreateGenerator().Generate(); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException) { return ""; }
    }

    // ---------------- forgotten password: secure vault wipe ----------------

    /// <summary>Securely erases the vault after typed confirmation, then shows the create screen.</summary>
    private async void EraseVault_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new ConfirmEraseDialog(this);
        if (dlg.ShowDialog() != true) return;

        // just in case – the vault must not be open (the file could be rewritten)
        _autoLockTimer.Stop();
        _vault?.Dispose();
        _vault = null;
        _editing = null;
        _pendingPassword = null;

        UnlockButton.IsEnabled = RestoreVaultButton.IsEnabled = RestoreHeaderButton.IsEnabled = false;
        EraseVaultButton.IsEnabled = false;
        LockError.Text = "Securely erasing the vault…";
        string path = Vault.DefaultPath;
        try
        {
            int files = await Task.Run(() => Vault.SecureDelete(path));
            Log.Warn("Vault securely erased by the user ({Files} file(s) overwritten and deleted)", files);
            _throttle.Reset(); // a new vault starts with no wait from past wrong attempts

            ShowLocked(null); // the vault no longer exists → the create-new view is shown
            LockHint.Text = $"The old vault was overwritten and erased ({files} file{(files == 1 ? "" : "s")}). " +
                            $"Choose a new master password (at least {MasterPasswordPolicy.MinLength} characters) " +
                            "to create a new, empty vault.";
            MasterBox.Focus();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Error(ex, "Erasing the vault failed");
            ShowLocked("Could not erase the vault: " + ex.Message +
                       " Close other programs that may use the file (e.g. a cloud sync client) and try again.");
        }
    }

    // ---------------- device binding (PC/account) ----------------

    /// <summary>Shows the export-device-key button only when the open vault is device-bound.</summary>
    private void UpdateDeviceBindingUi()
    {
        bool bound = _vault is not null && _vault.IsDeviceBound;
        ExportDeviceKeyButton.Visibility = bound ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Exports the device key (master-password-encrypted) for migration/recovery.</summary>
    private void ExportDeviceKey_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || !_vault.IsDeviceBound) return;
        var dlg = new SaveFileDialog
        {
            Title = "Export device key",
            FileName = "phrasia-device-key.pdk",
            Filter = "Phrasia device key (*.pdk)|*.pdk|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;

        var prompt = new PasswordPrompt(this, "Enter your master password to protect the exported device key:");
        if (prompt.ShowDialog() != true) return;
        if (!EntropyDialog.EnsureFresh(this, "the protection (salt and nonce) of the exported device key")) return;

        try
        {
            DeviceKeyStore.ExportRecovery(dlg.FileName, prompt.Password);
            EntropyPool.MarkConsumed();
            Log.Info("Device key exported");
            ShowEntryStatus("Device key exported ✓ — keep it safe; it plus your password can move the vault to another PC.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Log.Warn("Device key export failed: {Error}", ex.Message);
            ShowEntryStatus("Could not export the device key: " + ex.Message, error: true);
        }
    }

    /// <summary>Imports a device key on the locked screen so a device-bound vault can be opened here.</summary>
    private async void ImportDeviceKey_Click(object sender, RoutedEventArgs e)
    {
        string pw = MasterBox.Password;
        if (pw.Length == 0)
        {
            LockError.Text = "First enter the master password used when the device key was exported, then choose the file.";
            MasterBox.Focus();
            return;
        }
        var dlg = new OpenFileDialog
        {
            Title = "Import device key",
            Filter = "Phrasia device key (*.pdk)|*.pdk|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;

        string path = dlg.FileName;
        LockError.Text = "Importing device key…";
        try
        {
            await Task.Run(() => DeviceKeyStore.ImportRecovery(path, pw));
            Log.Info("Device key imported");
            LockError.Text = "Device key imported. You can now unlock a vault bound on the original PC.";
        }
        catch (WrongPasswordException)
        {
            LockError.Text = "Wrong master password for this device-key file.";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            LockError.Text = "Import failed: " + ex.Message;
        }
    }

    // ---------------- tuning Argon2 to this computer ----------------

    /// <summary>Re-benchmarks Argon2id (chosen time or Maximum) and re-encrypts the vault, keeping PIM and binding.</summary>
    private async void TuneKdf_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || IsVaultBusy) return;
        if (!Argon2Kdf.IsAvailable)
        {
            AppMessageBox.Show(this, "Argon2id is not available on this computer (self-test failed), so the vault uses PBKDF2.",
                "Tune to this PC", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var prompt = new TuneDialog(this, _vault.KdfInfo, _presetFile.UnlockTargetSeconds);
        if (prompt.ShowDialog() != true) return;

        var vault = _vault;
        if (vault is null) return;
        string pw = prompt.Password;
        bool maximum = prompt.Maximum;
        int seconds = prompt.TargetSeconds;
        if (!EntropyDialog.EnsureFresh(this, "the new salt of your vault")) return;
        var before = vault.KdfInfo;
        ShowEntryStatus(maximum
            ? "Benchmarking Argon2id at maximum settings… (this can take a while)"
            : $"Benchmarking Argon2id on this PC for a ~{seconds} s unlock… (a few seconds)");
        try
        {
            var result = await RunVaultOperationAsync(() => vault.TuneToThisComputer(pw, seconds * 1000.0, maximum));
            EntropyPool.MarkConsumed();
            _throttle.Reset();
            if (!maximum)
            {
                // the chosen time also applies to new vaults, upgrades and master-password changes
                _presetFile.UnlockTargetSeconds = seconds;
                PresetStore.Save(_presetFile);
            }
            Log.Info("Vault key derivation re-tuned: {Before} -> {After} (estimated {Ms:F0} ms; {Reason})",
                before, vault.KdfInfo, result.EstimatedMs, result.Reason);
            ShowEntryStatus($"Tuned: {vault.KdfInfo} ✓");
            AppMessageBox.Show(this,
                $"Before: {before}\nNow: {vault.KdfInfo}\nEstimated unlock time: ~{result.EstimatedMs / 1000:F1} s" +
                (maximum ? " (maximum)" : $" (target {seconds} s)") + $"\n\n{result.Reason}\n\n" +
                (!maximum && result.EstimatedMs < seconds * 1000 * 0.75
                    ? "This computer is fast enough that the maximum settings were reached before the target time — use the Maximum option to go higher.\n\n" : "") +
                (vault.UsesPim ? "Your PIM is unchanged and still required to unlock.\n" : "") +
                "Old header backups still work, but create a new header backup and vault backup to keep them in sync.\n" +
                "If you move the vault to a much slower computer, unlocking there may take longer – just run this again there.",
                "Tuned to this PC", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (WrongPasswordException)
        {
            _throttle.RegisterFailure();
            if (_throttle.RemainingLockout > TimeSpan.Zero)
                LockVault("Wrong master password – the vault was locked.");
            else
                ShowEntryStatus("The master password is wrong.", error: true);
        }
        catch (ObjectDisposedException)
        {
            Argon2Calibrator.TargetMs = _presetFile.UnlockTargetSeconds * 1000.0; // restore the saved target
            ShowEntryStatus("The vault was locked before re-tuning finished – nothing was changed.", error: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Argon2Calibrator.TargetMs = _presetFile.UnlockTargetSeconds * 1000.0; // restore the saved target
            Log.Warn("Re-tuning failed: {Error}", ex.Message);
            ShowEntryStatus("Could not re-tune the vault – nothing was changed: " + ex.Message, error: true);
        }
    }

    // ---------------- master password change ----------------

    /// <summary>Changes the master password and re-encrypts the vault with a fresh salt.</summary>
    private async void ChangeMaster_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || IsVaultBusy) return;
        var dlg = new ChangePasswordDialog(this);
        if (dlg.ShowDialog() != true) return;

        var vault = _vault;
        if (vault is null) return; // the vault locked in the meantime
        string current = dlg.CurrentPassword, newPassword = dlg.NewPassword;
        if (!EntropyDialog.EnsureFresh(this, "the new salt of your vault")) return;

        ShowEntryStatus("Changing master password…");
        try
        {
            await RunVaultOperationAsync(() => vault.ChangeMasterPassword(current, newPassword));
            EntropyPool.MarkConsumed();
            _throttle.Reset();
            Log.Info("Master password changed, vault re-encrypted with a new salt");
            ShowEntryStatus("Master password changed ✓");
            AppMessageBox.Show(this,
                "The master password was changed and the vault was re-encrypted with a fresh salt.\n\n" +
                "Old header backups and vault backups still use the OLD password. " +
                "Create a new header backup and vault backup now.",
                "Master password changed", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (WrongPasswordException)
        {
            _throttle.RegisterFailure();
            if (_throttle.RemainingLockout > TimeSpan.Zero)
                LockVault("Wrong current master password – the vault was locked.");
            else
                ShowEntryStatus("The current master password is wrong.", error: true);
        }
        catch (ObjectDisposedException)
        {
            ShowEntryStatus("The vault was locked before the change finished – the password was NOT changed.", error: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowEntryStatus("Could not save the vault – the password was NOT changed: " + ex.Message, error: true);
        }
    }

    // ---------------- password health overview ----------------

    private const double WeakEntryBits = 60;
    private const double CriticalEntryBits = 75;

    /// <summary>Strength level 0–5 – same thresholds as the generator rating (Rate).</summary>
    private static int StrengthLevel(double bits) => bits switch
    {
        < 28 => 0, < 40 => 1, < 60 => 2, < 80 => 3, < 100 => 4, _ => 5
    };

    /// <summary>Minimum required entropy – critical accounts have a stricter threshold.</summary>
    private static double RequiredBits(bool critical) => critical ? CriticalEntryBits : WeakEntryBits;

    /// <summary>Re-evaluates the entry password info when the Critical flag changes.</summary>
    private void CriticalCheck_Changed(object sender, RoutedEventArgs e) => UpdateEntryPasswordInfo();
    private static readonly Brush WarningBrush = Frozen("#E65100");
    private static readonly Brush GoodBrush = Frozen("#2E7D32");

    /// <summary>Counts of items, reused and weak passwords – shown under the search box.</summary>
    /// <summary>Updates the vault health summary line under the search box.</summary>
    private void UpdateVaultHealth()
    {
        if (_vault is null) { VaultHealthText.Text = ""; return; }

        var counts = _vault.Entries
            .Where(x => !string.IsNullOrEmpty(x.Password))
            .GroupBy(x => x.Password)
            .ToDictionary(g => g.Key, g => g.Count());

        foreach (var x in _vault.Entries)
        {
            bool hasPw = !string.IsNullOrEmpty(x.Password);
            double bits = hasPw ? MasterPasswordPolicy.EstimateBits(x.Password) : 0;
            x.IsReused = hasPw && counts[x.Password] > 1;
            x.IsWeak = hasPw && bits < RequiredBits(x.Critical);
            x.StrengthBits = bits;
            x.StrengthLevel = StrengthLevel(bits);
            x.StrengthText = hasPw ? $"Strength ≈ {bits:F0} bits – {Rate(bits).Label}" : "No password";
        }

        int total = _vault.Entries.Count;
        int reused = _vault.Entries.Count(x => x.IsReused);
        int weak = _vault.Entries.Count(x => x.IsWeak);
        int critical = _vault.Entries.Count(x => x.Critical);

        VaultHealthText.Text = total == 0
            ? "No items yet"
            : $"{total} item{(total == 1 ? "" : "s")}  ·  {critical} critical  ·  {reused} reused  ·  {weak} weak";
        VaultHealthText.Foreground = reused + weak > 0 ? WarningBrush : GoodBrush;
    }

    /// <summary>Estimates the entry password strength and warns if the same password is reused in other entries.</summary>
    private void UpdateEntryPasswordInfo()
    {
        string pw = EntryPassword;
        if (_vault is null || pw.Length == 0) { EntryPasswordInfo.Text = ""; return; }

        double bits = MasterPasswordPolicy.EstimateBits(pw);
        var (label, _, brush) = Rate(bits);
        string text = $"Strength (estimate): ≈ {bits:F0} bits – {label}";

        var others = _vault.Entries
            .Where(x => !ReferenceEquals(x, _editing) && x.Password == pw)
            .Select(x => x.Title)
            .ToList();
        if (others.Count > 0)
        {
            text += $"\nAlso used in: {string.Join(", ", others.Take(3))}{(others.Count > 3 ? ", …" : "")}" +
                    " – use a unique password for every account.";
            brush = WarningBrush;
        }
        else if (CriticalCheck.IsChecked == true && bits < CriticalEntryBits)
        {
            text += $"\nCritical accounts deserve {CriticalEntryBits:F0}+ bits – generate a new one (↻), ideally with Recommended mode.";
            brush = WarningBrush;
        }
        else if (bits < WeakEntryBits)
        {
            text += " – consider generating a new one (↻).";
            brush = WarningBrush;
        }

        EntryPasswordInfo.Text = text;
        EntryPasswordInfo.Foreground = brush;
    }

    // ---------------- auto-lock ----------------

    /// <summary>Subscribes to session-switch and power-mode events for auto-lock/clear.</summary>
    private void HookSystemEvents()
    {
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        StateChanged += OnWindowStateChanged;
    }

    /// <summary>Unsubscribes from the system events.</summary>
    private void UnhookSystemEvents()
    {
        // SystemEvents are static – without unsubscribing the window would stay in memory
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        StateChanged -= OnWindowStateChanged;
    }

    /// <summary>Auto-locks the vault and clears generated passwords on Windows lock/logoff.</summary>
    private void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff
            or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            Dispatcher.InvokeAsync(() =>
            {
                ClearGeneratedPasswords("Hidden because Windows was locked");
                if (_vault is not null) LockVault("The vault was locked because Windows was locked.");
            });
    }

    /// <summary>Auto-locks the vault and clears generated passwords when the system suspends.</summary>
    private void OnPowerModeChanged(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend)
            Dispatcher.InvokeAsync(() =>
            {
                ClearGeneratedPasswords("Hidden because the computer went to sleep");
                if (_vault is not null) LockVault("The vault was locked because the computer went to sleep.");
            });
    }

    /// <summary>Clears generated passwords when the window is minimized.</summary>
    private void OnWindowStateChanged(object? sender, EventArgs e)
    {
        if (WindowState != WindowState.Minimized) return;
        ClearGeneratedPasswords("Hidden when the window was minimized");
        if (_vault is not null) LockVault("The vault was locked when the window was minimized.");
    }

    // ---------------- screen-capture protection ----------------

    [DllImport("user32.dll", SetLastError = true)]
    /// <summary>P/Invoke: sets the window display affinity (used to exclude from screen capture).</summary>
    private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

    private const uint WDA_NONE = 0x0, WDA_MONITOR = 0x1, WDA_EXCLUDEFROMCAPTURE = 0x11;

    /// <summary>Applies screen-capture protection once the window handle exists.</summary>
    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyCaptureProtection(CaptureProtectionCheck.IsChecked == true);
    }

    /// <summary>Toggles screen-capture protection for the window.</summary>
    private void CaptureProtection_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        ApplyCaptureProtection(CaptureProtectionCheck.IsChecked == true);
    }

    /// <summary>Applies or removes screen-capture protection for the main window.</summary>
    private void ApplyCaptureProtection(bool on)
    {
        if (new WindowInteropHelper(this).Handle == IntPtr.Zero) return;
        Log.Info("Screen-capture protection {State}", on ? "on" : "off");
        ApplyCaptureProtection(this, on);
    }

    /// <summary>True when "Hide from screen capture" is enabled (dialogs that show secrets follow it).</summary>
    internal bool IsCaptureProtectionOn => CaptureProtectionCheck.IsChecked == true;

    /// <summary>Windows 10 2004+: the window is fully excluded from screenshots / recording / screen sharing. Older Windows: a black area is captured instead of the window content. Call once the window handle exists.</summary>
    internal static void ApplyCaptureProtection(Window window, bool on)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;
        if (!on)
        {
            SetWindowDisplayAffinity(hwnd, WDA_NONE);
            return;
        }
        if (!SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE))
            SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
    }

    // ---------------- backups ----------------

    /// <summary>Exports an encrypted header backup (salt + KDF parameters) after confirming the master password.</summary>
    private async void BackupHeader_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || IsVaultBusy) return;
        var dlg = new SaveFileDialog
        {
            Title = "Save header backup",
            FileName = $"vault-header-{DateTime.Now:yyyyMMdd}.bak",
            Filter = "Header backup (*.bak)|*.bak|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;

        var prompt = new PasswordPrompt(this, "Enter your master password to create the header backup:");
        if (prompt.ShowDialog() != true) return;

        var vault = _vault;
        if (vault is null) return; // the vault may have auto-locked in the meantime
        string pw = prompt.Password, path = dlg.FileName;
        ShowEntryStatus("Creating backup…");
        try
        {
            await RunVaultOperationAsync(() => vault.ExportHeaderBackup(path, pw));
            ShowEntryStatus("Header backup saved ✓");
            Log.Info("Header backup created");
        }
        catch (WrongPasswordException)
        {
            _throttle.RegisterFailure();
            if (_throttle.RemainingLockout > TimeSpan.Zero)
                LockVault("Wrong master password during backup – the vault was locked.");
            else
                ShowEntryStatus("Wrong master password.", error: true);
        }
        catch (ObjectDisposedException)
        {
            ShowEntryStatus("The vault was locked before the header backup was written.", error: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowEntryStatus("Could not save the backup: " + ex.Message, error: true);
        }
    }

    /// <summary>Saves a copy of the whole encrypted vault file as a backup.</summary>
    private void BackupVault_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || IsVaultBusy) return;
        var dlg = new SaveFileDialog
        {
            Title = "Save vault backup",
            FileName = $"vault-{DateTime.Now:yyyyMMdd}.pgv",
            Filter = "Vault (*.pgv)|*.pgv|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            if (TrySaveVault())
            {
                File.Copy(_vault.FilePath, dlg.FileName, overwrite: true);
                ShowEntryStatus("Vault backup saved ✓");
                Log.Info("Vault backup created ({Count} items)", _vault.Entries.Count);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowEntryStatus("Could not save the backup: " + ex.Message, error: true);
        }
    }

    /// <summary>Locked screen: replaces (or on a new PC creates) the vault from a backup.</summary>
    private async void RestoreVault_Click(object sender, RoutedEventArgs e)
    {
        if (UpdateLockout()) return;
        string pw = MasterBox.Password;
        if (pw.Length == 0)
        {
            LockError.Text = "First enter the password the backup is protected with, then choose the backup.";
            MasterBox.Focus();
            return;
        }
        if (!TryReadUnlockPim(mandatory: false, out int pim)) return;

        var dlg = new OpenFileDialog
        {
            Title = "Choose a vault backup",
            Filter = "Vault (*.pgv)|*.pgv|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;

        string vaultPath = Vault.DefaultPath, backupPath = dlg.FileName;
        if (File.Exists(vaultPath))
        {
            var answer = AppMessageBox.Show(this,
                "The current vault will be replaced with the backup.\n" +
                "The original file will be kept as vault.pgv.before-restore.\n\nContinue?",
                "Restore vault", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes) return;
        }

        UnlockButton.IsEnabled = RestoreVaultButton.IsEnabled = RestoreHeaderButton.IsEnabled = false;
        LockError.Text = "Verifying and restoring the backup…";
        try
        {
            await Task.Run(() => Vault.RestoreFromBackup(vaultPath, backupPath, pw, pim));
            Log.Warn("Vault replaced with a backup (previous file kept as .before-restore)");
            LockError.Text = "";
            Unlock_Click(sender, e); // the password is still in the field – unlock the restored vault directly
        }
        catch (WrongPasswordException)
        {
            _throttle.RegisterFailure();
            ShowLocked("Wrong password for this backup (or the backup is damaged).");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
                                      or JsonException or FormatException)
        {
            ShowLocked("Restore failed: " + ex.Message);
        }
    }

    /// <summary>Unlocked vault: merges entries from a backup into the current vault.</summary>
    private async void ImportFromBackup_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || IsVaultBusy) return;
        var dlg = new OpenFileDialog
        {
            Title = "Choose a vault backup to import",
            Filter = "Vault (*.pgv)|*.pgv|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;

        if (Path.GetFullPath(dlg.FileName).Equals(Path.GetFullPath(_vault.FilePath), StringComparison.OrdinalIgnoreCase))
        {
            ShowEntryStatus("This is the current vault, not a backup.", error: true);
            return;
        }

        var prompt = new PasswordPrompt(this,
            "Enter the password the backup is protected with (if you have not changed your master password since, it is the same one):",
            askPim: Argon2Kdf.IsAvailable);
        if (prompt.ShowDialog() != true) return;

        string pw = prompt.Password, path = dlg.FileName;
        int pim = prompt.Pim;
        ShowEntryStatus("Loading backup…");
        try
        {
            var items = await RunVaultOperationAsync(() => Vault.ReadEntriesFromBackup(path, pw, pim));
            if (_vault is null) return; // the vault locked in the meantime

            var (added, updated, skipped) = _vault.Merge(items);
            Log.Info("Imported from backup: {Added} new, {Updated} updated, {Skipped} unchanged", added, updated, skipped);
            if (added + updated > 0 && !TrySaveVault()) return;

            RefreshList(_editing);
            ShowEntryStatus($"Import: {added} new, {updated} updated, {skipped} unchanged ✓");
        }
        catch (WrongPasswordException)
        {
            _throttle.RegisterFailure();
            if (_throttle.RemainingLockout > TimeSpan.Zero)
                LockVault("Wrong backup password – the vault was locked.");
            else
                ShowEntryStatus("Wrong backup password (or the backup is damaged).", error: true);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
                                      or JsonException or FormatException)
        {
            ShowEntryStatus("Import failed: " + ex.Message, error: true);
        }
    }

    /// <summary>Locked screen: VeraCrypt-style header tool – checks the vault header against a header backup without changing anything, or restores the header from it (then unlocks).</summary>
    private async void RestoreHeader_Click(object sender, RoutedEventArgs e)
    {
        if (UpdateLockout()) return;
        var tool = new HeaderToolsDialog(this, MasterBox.Password, PimBox.Text, CheckHeaderAsync);
        bool restore = tool.ShowDialog() == true && tool.RestoreRequested;
        if (UpdateLockout() || !restore) return;

        var answer = AppMessageBox.Show(this,
            "The vault header will be replaced with the header from the backup.\n" +
            "The original file will first be kept as vault.pgv.before-restore.\n\nContinue?",
            "Restore header", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        string pw = tool.Password, vaultPath = Vault.DefaultPath, backupPath = tool.BackupPath;
        int pim = tool.Pim;
        MasterBox.Password = pw;   // unlock right after a successful restore
        PimBox.Text = tool.PimText;
        UnlockButton.IsEnabled = RestoreHeaderButton.IsEnabled = false;
        LockError.Text = "Restoring header…";
        try
        {
            await Task.Run(() => Vault.RestoreHeader(vaultPath, backupPath, pw, pim));
            Log.Warn("Vault header restored from a backup");
            LockError.Text = "";
            Unlock_Click(sender, e); // the password is in the field – unlock directly
        }
        catch (WrongPasswordException)
        {
            _throttle.RegisterFailure();
            ShowLocked("Wrong master password for this backup.");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException)
        {
            ShowLocked("Restore failed: " + ex.Message);
        }
    }

    /// <summary>Runs the read-only header check for <see cref="HeaderToolsDialog"/> and returns a readable report. Wrong passwords count toward the unlock throttle.</summary>
    private async Task<string> CheckHeaderAsync(string backupPath, string pw, int pim)
    {
        if (_throttle.RemainingLockout > TimeSpan.Zero)
            return $"Too many wrong attempts – try again in {FormatRemaining(_throttle.RemainingLockout)}.";
        string vaultPath = Vault.DefaultPath;
        if (!File.Exists(vaultPath)) return "There is no vault file to check.";
        try
        {
            var r = await Task.Run(() => Vault.CheckHeader(vaultPath, backupPath, pw, pim));
            Log.Info("Header check: backup format v{Backup}, vault opens: {Opens}, identical: {Same}, restore would help: {Helps}",
                r.BackupFormat, r.VaultOpens, r.HeaderMatchesBackup, r.BackupRepairsVault);
            return FormatHeaderReport(r);
        }
        catch (WrongPasswordException)
        {
            _throttle.RegisterFailure();
            var wait = _throttle.RemainingLockout;
            return "✗ This header backup does not open with this master password (or the file is not a Phrasia header backup)." +
                   (wait > TimeSpan.Zero ? $"\n\nToo many wrong attempts – next attempt in {FormatRemaining(wait)}." : "");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return "✗ The check failed: " + ex.Message;
        }
    }

    /// <summary>Turns a header-check result into a short report with a recommendation.</summary>
    private static string FormatHeaderReport(Vault.HeaderCheckReport r)
    {
        var lines = new List<string>
        {
            "✓ The header backup opens with this password.",
            $"     Backup: format v{r.BackupFormat} · {r.BackupKdf}{(r.BackupDeviceBound ? " · device-bound" : "")}",
            r.VaultOpens
                ? $"✓ The vault opens with its current header (format v{r.VaultFormat})."
                : "✗ The vault does not open with its current header and this password / PIM.",
            r.HeaderMatchesBackup
                ? "✓ The vault header is identical to this backup."
                : "• The vault header differs from this backup (normal after a master-password change or re-tuning – the backup is then outdated).",
            "",
            r.NeedsDeviceKey ? "Result: the vault is bound to another computer / Windows account. Import the device key first (\"Import device key…\"), then check again."
            : r.VaultTooDamaged ? "Result: the vault file is too badly damaged for a header repair – use \"Restore vault from backup…\"."
            : r.VaultOpens ? "Result: the header is fine – nothing to repair, restoring is not needed."
            : r.BackupRepairsVault ? "Result: restoring the header from this backup WILL make the vault open again → \"Restore header…\"."
            : "Result: restoring from this backup would not help. Check the PIM; otherwise the backup belongs to a different vault or the vault content itself is damaged (then use \"Restore vault from backup…\")."
        };
        return string.Join("\n", lines);
    }

    // ---------------- entry list ----------------

    /// <summary>Rebuilds the entry list (search + attention filter) and optionally selects one.</summary>
    private void RefreshList(VaultEntry? select = null)
    {
        if (_vault is null) return;
        string q = SearchBox.Text.Trim();

        UpdateVaultHealth(); // sets the IsReused / IsWeak flags for the badges

        var items = _vault.Entries
            .Where(x => _attentionFilter is null || _attentionFilter.Contains(x.Id))
            .Where(x => q.Length == 0
                        || x.Title.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                        || x.Username.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                        || x.Url.Contains(q, StringComparison.CurrentCultureIgnoreCase))
            .OrderByDescending(x => x.Critical)          // critical accounts on top
            .ThenBy(x => x.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        _suppressSelection = true;
        EntriesList.ItemsSource = null;                 // the flags are not INotifyPropertyChanged → rebind
        EntriesList.ItemsSource = items;
        EntriesList.SelectedItem = select;
        _suppressSelection = false;
    }

    private void Search_TextChanged(object sender, TextChangedEventArgs e) =>
        RefreshList(EntriesList.SelectedItem as VaultEntry);

    /// <summary>Loads the selected entry into the editor.</summary>
    private void EntriesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressSelection) return;
        if (EntriesList.SelectedItem is VaultEntry entry) LoadEntry(entry);
    }

    // ---------------- editor ----------------

    /// <summary>Loads an existing entry into the editor fields.</summary>
    private void LoadEntry(VaultEntry entry)
    {
        _editing = entry;
        EditorTitle.Text = entry.Title;
        TitleBox.Text = entry.Title;
        UserBox.Text = entry.Username;
        SetEntryPassword(entry.Password);
        UrlBox.Text = entry.Url;
        NoteBox.Text = entry.Note;
        CriticalCheck.IsChecked = entry.Critical;
        DeleteButton.IsEnabled = true;
        EntryInfoText.Text = $"Created {entry.Created:yyyy-MM-dd HH:mm}  ·  modified {entry.Modified:yyyy-MM-dd HH:mm}";
    }

    /// <summary>Starts editing a new (unsaved) entry, optionally pre-filled with a password.</summary>
    private void StartNewEntry(string password)
    {
        _editing = null;
        _suppressSelection = true;
        EntriesList.SelectedItem = null;
        _suppressSelection = false;

        ClearEditor();
        SetEntryPassword(password);
        EditorTitle.Text = "New item";
        DeleteButton.IsEnabled = false;
        TitleBox.Focus();
    }

    /// <summary>Clears the editor fields.</summary>
    private void ClearEditor()
    {
        EditorTitle.Text = "";
        TitleBox.Text = UserBox.Text = UrlBox.Text = NoteBox.Text = "";
        CriticalCheck.IsChecked = false;
        SetEntryPassword("");
        ShowPasswordCheck.IsChecked = false;
        EntryInfoText.Text = "";
    }

    /// <summary>Starts a new, empty entry.</summary>
    private void NewEntry_Click(object sender, RoutedEventArgs e) => StartNewEntry("");

    /// <summary>Validates and saves the editor entry, then persists the vault and offers the next entry.</summary>
    private void SaveEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null) return;
        if (string.IsNullOrWhiteSpace(TitleBox.Text))
        {
            ShowEntryStatus("Enter a title for the item.", error: true);
            TitleBox.Focus();
            return;
        }

        bool isNew = _editing is null;
        var entry = _editing ?? new VaultEntry();
        string newPassword = EntryPassword;
        if (isNew || entry.Password != newPassword) entry.PasswordChanged = DateTime.Now;
        entry.Title = TitleBox.Text.Trim();
        entry.Username = UserBox.Text.Trim();
        entry.Password = EntryPassword;
        entry.Url = UrlBox.Text.Trim();
        entry.Note = NoteBox.Text;
        entry.Critical = CriticalCheck.IsChecked == true;
        entry.Modified = DateTime.Now;
        if (_editing is null) _vault.Entries.Add(entry);

        if (!TrySaveVault()) return;
        Log.Debug(isNew ? "Item added" : "Item updated");

        if (isNew)
        {
            // new entry saved → prepare the next one with a fresh password (no need to click New item)
            RefreshList();
            StartNewEntry(TryGeneratePassword());
            ShowEntryStatus($"\"{entry.Title}\" saved ✓ – the next item is ready");
        }
        else if (_attentionFilter is not null)
        {
            // "needs attention" mode: the fixed entry disappears, the next one to handle opens
            var stillBad = VaultAnalyzer.Analyze(_vault.Entries).NeedsAttention;
            stillBad.IntersectWith(_attentionFilter);
            if (stillBad.Count == 0)
            {
                SetAttentionFilter(null);
                RefreshList(entry);
                LoadEntry(entry);
                ShowEntryStatus("Saved ✓ – all flagged items are fixed. Run Analyze again to check.");
            }
            else
            {
                bool fixedNow = !stillBad.Contains(entry.Id);
                SetAttentionFilter(stillBad);
                var next = fixedNow
                    ? (EntriesList.ItemsSource as IEnumerable<VaultEntry>)?.FirstOrDefault()
                    : entry;
                if (next is not null) { EntriesList.SelectedItem = next; LoadEntry(next); }
                ShowEntryStatus(fixedNow
                    ? $"Saved ✓ – fixed. {stillBad.Count} item(s) left."
                    : "Saved ✓ – this item still needs attention.");
            }
        }
        else
        {
            RefreshList(entry);
            LoadEntry(entry);
            ShowEntryStatus("Saved ✓");
        }
    }

    /// <summary>Deletes the selected entry after confirmation and persists the vault.</summary>
    private void DeleteEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || _editing is null) return;
        var answer = AppMessageBox.Show(this, $"Really delete \"{_editing.Title}\"?", "Delete",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        _vault.Entries.Remove(_editing);
        if (!TrySaveVault()) return;
        Log.Debug("Item deleted");

        RefreshList();
        if (EntriesList.Items.Count > 0) EntriesList.SelectedIndex = 0;
        else StartNewEntry("");
        ShowEntryStatus("Deleted");
    }

    /// <summary>Saves the vault to disk, showing an error and returning false on failure.</summary>
    private bool TrySaveVault()
    {
        try
        {
            _vault!.Save();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Error(ex, "Saving the vault failed");
            AppMessageBox.Show(this, "Could not save the vault:\n" + ex.Message, "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
    }

    /// <summary>Copies the entry username to the clipboard.</summary>
    private void CopyUser_Click(object sender, RoutedEventArgs e)
    {
        if (CopySecure(UserBox.Text)) ShowEntryStatus("Username copied ✓");
    }

    /// <summary>Copies the entry password to the clipboard (auto-clearing).</summary>
    private void CopyEntryPassword_Click(object sender, RoutedEventArgs e)
    {
        if (CopySecure(EntryPassword)) ShowEntryStatus($"Password copied ✓ (cleared in {ClipboardClearSeconds} s)");
    }

    /// <summary>Fills the entry password with a freshly generated one.</summary>
    private void GenerateEntryPassword_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            SetEntryPassword(CreateGenerator().Generate());
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException)
        {
            ShowEntryStatus("Generator: " + ex.Message, error: true);
        }
    }

    /// <summary>The "Save to vault" button on the Generator tab.</summary>
    private void SaveToVault_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_current)) return;
        MainTabs.SelectedItem = VaultTab;

        if (_vault is null)
        {
            if (_pendingPassword is null)
                LockHint.Text += "\nAfter unlocking, the generated password will be pre-filled into a new item.";
            _pendingPassword = _current;
            LockError.Text = "";
            MasterBox.Focus();
        }
        else
        {
            StartNewEntry(_current);
        }
    }

    // ---------------- show / hide password ----------------

    private string EntryPassword =>
        ShowPasswordCheck.IsChecked == true ? EntryPasswordText.Text : EntryPasswordBox.Password;

    /// <summary>Sets the entry password field (plain or masked) and updates its info.</summary>
    private void SetEntryPassword(string pw)
    {
        _syncingPassword = true;
        EntryPasswordBox.Password = pw;
        EntryPasswordText.Text = pw;
        _syncingPassword = false;
        UpdateEntryPasswordInfo();
    }

    /// <summary>Syncs the masked password box into state and updates the info.</summary>
    private void EntryPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingPassword) return;
        _syncingPassword = true;
        EntryPasswordText.Text = EntryPasswordBox.Password;
        _syncingPassword = false;
        UpdateEntryPasswordInfo();
    }

    /// <summary>Syncs the visible password text box into state and updates the info.</summary>
    private void EntryPasswordText_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_syncingPassword) return;
        _syncingPassword = true;
        EntryPasswordBox.Password = EntryPasswordText.Text;
        _syncingPassword = false;
        UpdateEntryPasswordInfo();
    }

    /// <summary>Toggles between the masked and visible entry password fields.</summary>
    private void ShowPassword_Changed(object sender, RoutedEventArgs e)
    {
        bool show = ShowPasswordCheck.IsChecked == true;
        EntryPasswordText.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        EntryPasswordBox.Visibility = show ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>Shows a transient status message in the editor (red when an error).</summary>
    private void ShowEntryStatus(string msg, bool error = false)
    {
        EntryStatusText.Text = msg;
        EntryStatusText.Foreground = error ? System.Windows.Media.Brushes.Firebrick : System.Windows.Media.Brushes.ForestGreen;
        _entryStatusTimer.Stop();
        _entryStatusTimer.Start();
    }

    // ---------------- secure clipboard ----------------

    /// <summary>Copies text so it is not stored in clipboard history (Win+V) or the cloud, and clears it after <see cref="ClipboardClearSeconds"/> s (if still present).</summary>
    private bool CopySecure(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        try
        {
            var data = new DataObject();
            data.SetText(text, TextDataFormat.UnicodeText);
            data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(BitConverter.GetBytes(0)));
            data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
            data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
            Clipboard.SetDataObject(data, true);

            _clipboardValue = text;
            _clipboardTimer.Stop();
            _clipboardTimer.Start();
            return true;
        }
        catch (ExternalException)
        {
            return false;
        }
    }

    /// <summary>Clears the clipboard only if it still holds the value this app copied.</summary>
    private void ClearClipboardIfOurs()
    {
        _clipboardTimer.Stop();
        if (_clipboardValue is null) return;
        try
        {
            if (Clipboard.ContainsText() && Clipboard.GetText() == _clipboardValue)
                Clipboard.Clear();
        }
        catch (ExternalException) { /* another app holds the clipboard – ignore */ }
        _clipboardValue = null;
    }

    // ---------------- window ----------------

    /// <summary>Global shortcuts (Ctrl+L lock, Ctrl+C/S/N) and idle-timer refresh.</summary>
    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (_vault is not null && !IsVaultBusy) { _autoLockTimer.Stop(); _autoLockTimer.Start(); }
        TouchGeneratorIdleTimer();

        if (Keyboard.Modifiers == ModifierKeys.Control)
        {
            // Ctrl+S – save the entry, Ctrl+N – new entry (in an unlocked vault)
            if (_vault is not null && !IsVaultBusy && MainTabs.SelectedItem == VaultTab && UnlockedPanel.Visibility == Visibility.Visible)
            {
                if (e.Key == Key.S) { SaveEntry_Click(sender, e); e.Handled = true; return; }
                if (e.Key == Key.N) { StartNewEntry(TryGeneratePassword()); e.Handled = true; return; }
            }
            // Ctrl+L – lock the vault immediately
            if (e.Key == Key.L && _vault is not null)
            {
                LockVault("The vault was locked (Ctrl+L).");
                e.Handled = true;
                return;
            }
            // Ctrl+C on the Generator tab – copy the password (unless focus is in a text field)
            if (e.Key == Key.C && MainTabs.SelectedIndex == 0 && Keyboard.FocusedElement is not TextBox
                && !string.IsNullOrEmpty(_current))
            {
                CopyToClipboard(_current);
                e.Handled = true;
                return;
            }
        }

        // Enter on the Generator tab = new password (unless focus is in a text field or on a button)
        if (e.Key == Key.Enter && MainTabs.SelectedIndex == 0
            && Keyboard.FocusedElement is not (TextBox or ButtonBase))
        {
            Regenerate();
            e.Handled = true;
        }
    }

    /// <summary>Refreshes the generator idle timer on mouse activity.</summary>
    private void Window_PreviewMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (_vault is not null && !IsVaultBusy) { _autoLockTimer.Stop(); _autoLockTimer.Start(); }
        TouchGeneratorIdleTimer();
    }

    /// <summary>On close: checkpoints the throttle, clears secrets, and saves last settings.</summary>
    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (IsVaultBusy)
        {
            // interrupting a re-key/tuning is not safe – let it finish first
            e.Cancel = true;
            ShowEntryStatus("Please wait – a vault operation is still running.", error: true);
            return;
        }
        _throttle.Checkpoint(); // record the served wait time
        SaveLastSettings();     // the generator restores these settings on next launch
        ClearGeneratedPasswords("Closing");
        _pendingPassword = null;
        UnhookSystemEvents();
        ClearClipboardIfOurs();
        _vault?.Dispose();
    }
}
