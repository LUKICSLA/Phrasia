using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace Phrasia;

/// <summary>Presets – saved generator settings and restoring the last-used settings at startup.</summary>
public partial class MainWindow
{
    /// <summary>Presets and all app settings – loaded before the window is built so the screen-capture
    /// protection and timers are right from the first frame.</summary>
    private PresetFile _presetFile = PresetStore.Load();
    private bool _suppressPresetSelection;

    /// <summary>Loads presets and restores the last settings. Returns true if any were restored.</summary>
    private bool InitPresets()
    {
        RefreshPresetCombo(null);
        Argon2Calibrator.TargetMs = _presetFile.UnlockTargetSeconds * 1000.0; // clamped to 1–10 s
        ApplySettings(); // timers, screen-capture protection, thresholds, logging
        if (_presetFile.StartTab == "vault") MainTabs.SelectedItem = VaultTab;

        var last = _presetFile.Last;
        if (last is null) return false;

        ApplyPreset(last, announce: false);
        if (last.Recommended) RecommendedCheck.IsChecked = true; // enables and locks the recommended settings
        return true;
    }

    /// <summary>Rebuilds the preset combo and optionally selects one.</summary>
    private void RefreshPresetCombo(GeneratorPreset? select)
    {
        _suppressPresetSelection = true;
        PresetCombo.ItemsSource = null;
        PresetCombo.ItemsSource = _presetFile.Presets.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        PresetCombo.SelectedItem = select;
        _suppressPresetSelection = false;
        UpdatePresetButtons();
    }

    /// <summary>Enables/disables the save and delete buttons and updates the hint.</summary>
    private void UpdatePresetButtons()
    {
        bool locked = RecommendedCheck.IsChecked == true;
        PresetCombo.IsEnabled = !locked && _presetFile.Presets.Count > 0;
        DeletePresetButton.IsEnabled = !locked && PresetCombo.SelectedItem is GeneratorPreset;
        PresetHint.Text = _presetFile.Presets.Count == 0
            ? "Set up the generator the way you like, then click Save to reuse it later."
            : locked ? "Turn off Recommended mode to load a preset."
            : $"{_presetFile.Presets.Count} saved preset{(_presetFile.Presets.Count == 1 ? "" : "s")}.";
    }

    /// <summary>The current generator settings captured as a preset.</summary>
    private GeneratorPreset CapturePreset(string name) => new()
    {
        Name = name,
        Lang = SelTag(LangCombo),
        Case = SelTag(CaseCombo),
        Separator = SelTag(SeparatorCombo),
        CustomSeparator = CustomSeparatorBox.Text,
        Symbols = SymbolsBox.Text,
        Numbers = SelTag(NumbersCombo),
        Words = (int)WordsSlider.Value,
        Digits = (int)DigitsSlider.Value,
        MinLen = (int)MinLenSlider.Value,
        MaxLen = (int)MaxLenSlider.Value,
        Strip = NoDiacriticsCheck.IsChecked == true,
        Unique = UniqueCheck.IsChecked == true,
        Extra = ExtraRandomCheck.IsChecked == true,
        Variants = (int)VariantsSlider.Value
    };

    /// <summary>Applies a preset to the controls (values are clamped to the allowed range).</summary>
    private void ApplyPreset(GeneratorPreset p, bool announce)
    {
        _applyingPreset = true;
        try
        {
            // a custom word list from a file – only if the file still exists
            if (p.Lang.StartsWith("path:"))
            {
                string path = p.Lang["path:".Length..];
                if (File.Exists(path)) LangCombo.SelectedItem = AddWordlistItem(path);
            }
            else SelectByTag(LangCombo, p.Lang);

            SelectByTag(CaseCombo, p.Case);
            SelectByTag(SeparatorCombo, p.Separator);
            SelectByTag(NumbersCombo, p.Numbers);
            CustomSeparatorBox.Text = p.CustomSeparator ?? "";
            if (!string.IsNullOrEmpty(p.Symbols)) SymbolsBox.Text = p.Symbols;

            MaxLenSlider.Value = Clamp(p.MaxLen, MaxLenSlider);
            MinLenSlider.Value = Math.Min(Clamp(p.MinLen, MinLenSlider), MaxLenSlider.Value);
            WordsSlider.Value = Clamp(p.Words, WordsSlider);
            DigitsSlider.Value = Clamp(p.Digits, DigitsSlider);
            VariantsSlider.Value = Clamp(p.Variants, VariantsSlider);

            NoDiacriticsCheck.IsChecked = p.Strip;
            UniqueCheck.IsChecked = p.Unique;
            ExtraRandomCheck.IsChecked = p.Extra;
        }
        finally
        {
            _applyingPreset = false;
        }
        Regenerate();
        if (announce) ShowStatus($"Preset \"{p.Name}\" loaded ✓");

        static double Clamp(int v, System.Windows.Controls.Primitives.RangeBase s) =>
            Math.Max(s.Minimum, Math.Min(s.Maximum, v));
    }

    /// <summary>Applies the newly selected preset.</summary>
    private void PresetCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressPresetSelection || !IsLoaded) return;
        if (PresetCombo.SelectedItem is GeneratorPreset p) ApplyPreset(p, announce: true);
        UpdatePresetButtons();
    }

    /// <summary>Prompts for a name and saves the current settings as a preset.</summary>
    private void SavePreset_Click(object sender, RoutedEventArgs e)
    {
        string suggested = (PresetCombo.SelectedItem as GeneratorPreset)?.Name ?? "";
        var dlg = new TextInputDialog(this, "Save preset", "Name for the current generator settings:", suggested);
        if (dlg.ShowDialog() != true) return;

        string name = dlg.Value;
        var existing = _presetFile.Presets.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.CurrentCultureIgnoreCase));
        if (existing is not null)
        {
            var answer = AppMessageBox.Show(this, $"A preset named \"{existing.Name}\" already exists. Overwrite it?",
                "Save preset", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes) return;
            _presetFile.Presets.Remove(existing);
        }

        var preset = CapturePreset(name);
        _presetFile.Presets.Add(preset);
        if (!PresetStore.Save(_presetFile))
        {
            ShowStatus("Could not save the preset.");
            return;
        }
        RefreshPresetCombo(preset);
        Log.Info("Preset saved ({Count} presets)", _presetFile.Presets.Count);
        ShowStatus($"Preset \"{name}\" saved ✓");
    }

    /// <summary>Deletes the selected preset after confirmation.</summary>
    private void DeletePreset_Click(object sender, RoutedEventArgs e)
    {
        if (PresetCombo.SelectedItem is not GeneratorPreset p) return;
        var answer = AppMessageBox.Show(this, $"Delete the preset \"{p.Name}\"?", "Delete preset",
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        _presetFile.Presets.Remove(p);
        PresetStore.Save(_presetFile);
        Log.Info("Preset deleted ({Count} presets)", _presetFile.Presets.Count);
        RefreshPresetCombo(null);
        ShowStatus($"Preset \"{p.Name}\" deleted");
    }

    /// <summary>Clears the preset selection on a manual change – it is no longer exactly that preset.</summary>
    private void ClearPresetSelectionAfterManualChange()
    {
        if (_applyingPreset || PresetCombo.SelectedItem is null) return;
        _suppressPresetSelection = true;
        PresetCombo.SelectedItem = null;
        _suppressPresetSelection = false;
        UpdatePresetButtons();
    }

    /// <summary>Saves the current settings as the "last" settings – called when the window closes.</summary>
    private void SaveLastSettings()
    {
        bool recommended = RecommendedCheck.IsChecked == true;
        // in Recommended mode the user's own pre-Recommended settings are saved
        if (recommended && _beforeRecommended is not null) RestoreSnapshotSilently(_beforeRecommended);
        var last = CapturePreset("(last used)");
        last.Recommended = recommended;
        _presetFile.Last = last;
        PresetStore.Save(_presetFile);
    }

    /// <summary>Restores a settings snapshot without side effects (used by Recommended mode).</summary>
    private void RestoreSnapshotSilently(SettingsSnapshot s) => RestoreSnapshot(s);
}
