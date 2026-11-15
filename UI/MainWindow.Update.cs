using System.Net.Http;
using System.Windows;

namespace Phrasia;

/// <summary>Startup update check: shows a banner with a link to the GitHub release when a newer version exists.</summary>
public partial class MainWindow
{
    private UpdateInfo? _update;
    private bool _updateInitDone;

    /// <summary>Restores the setting and, when enabled, checks GitHub in the background a few seconds after start.</summary>
    private void InitUpdateCheck()
    {
        UpdateCheckBox.IsChecked = _presetFile.CheckForUpdates;
        _updateInitDone = true;
        if (_presetFile.CheckForUpdates) _ = CheckForUpdateAsync(TimeSpan.FromSeconds(3));
    }

    /// <summary>Queries GitHub; any failure (offline, proxy, rate limit) is only logged – the app works the same.</summary>
    private async Task CheckForUpdateAsync(TimeSpan delay)
    {
        try
        {
            await Task.Delay(delay);
            var current = typeof(MainWindow).Assembly.GetName().Version ?? new Version(1, 0, 0);
            var update = await UpdateChecker.CheckAsync(current);
            if (update is null)
            {
                Log.Info("Update check: Phrasia {Version} is up to date", AppVersion);
                return;
            }
            if (update.Version.ToString(3) == _presetFile.SkippedVersion)
            {
                Log.Info("Update check: {Version} available but skipped by the user", update.Version.ToString(3));
                return;
            }
            Log.Info("Update check: {Version} available", update.Version.ToString(3));
            _update = update;
            UpdateText.Text = $"Phrasia {update.Version.ToString(3)} is available – you have {AppVersion}.";
            UpdateBanner.Visibility = Visibility.Visible;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException
                                      or System.IO.IOException)
        {
            Log.Info("Update check skipped: {Reason}", ex.Message); // offline etc. – not an error for the user
        }
    }

    /// <summary>Opens the release page in the browser (always a github.com/LUKICSLA/Phrasia link).</summary>
    private void UpdateDownload_Click(object sender, RoutedEventArgs e) =>
        OpenUrl(_update?.Url is { } url && UpdateChecker.IsTrustedReleaseUrl(url) ? url : UpdateChecker.ReleasesPage);

    /// <summary>Remembers the offered version so it is not shown again.</summary>
    private void UpdateSkip_Click(object sender, RoutedEventArgs e)
    {
        if (_update is not null)
        {
            _presetFile.SkippedVersion = _update.Version.ToString(3);
            PresetStore.Save(_presetFile);
        }
        UpdateBanner.Visibility = Visibility.Collapsed;
    }

    /// <summary>Hides the banner until the next start.</summary>
    private void UpdateDismiss_Click(object sender, RoutedEventArgs e) => UpdateBanner.Visibility = Visibility.Collapsed;

    /// <summary>Turns the startup check on/off; turning it on checks right away.</summary>
    private void UpdateCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (!_updateInitDone) return;
        bool on = UpdateCheckBox.IsChecked == true;
        if (_presetFile.CheckForUpdates == on) return;
        _presetFile.CheckForUpdates = on;
        PresetStore.Save(_presetFile);
        Log.Info("Update check {State}", on ? "enabled" : "disabled");
        if (on) _ = CheckForUpdateAsync(TimeSpan.Zero);
        else UpdateBanner.Visibility = Visibility.Collapsed;
    }
}
