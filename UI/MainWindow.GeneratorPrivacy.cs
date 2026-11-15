using System.ComponentModel;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Threading;

namespace Phrasia;

/// <summary>One variant password in the list – shown masked by default.</summary>
public sealed class VariantItem : INotifyPropertyChanged
{
    /// <summary>The mask is always the same length – it does not reveal the password length.</summary>
    public const string MaskText = "••••••••••••••••••••";

    /// <summary>Creates a variant item with its value and initial reveal flags.</summary>
    public VariantItem(string value, bool showPlain, bool hoverReveal)
    {
        Value = value;
        _showPlain = showPlain;
        _hoverReveal = hoverReveal;
    }

    private bool _hoverReveal;
    /// <summary>Reveal on mouse hover – off by default.</summary>
    public bool HoverReveal
    {
        get => _hoverReveal;
        set { if (_hoverReveal == value) return; _hoverReveal = value; PropertyChanged?.Invoke(this, new(nameof(HoverReveal))); }
    }

    public string Value { get; private set; }
    public string Mask => MaskText;

    private bool _showPlain;
    /// <summary>Whether this variant is currently shown in plaintext.</summary>
    public bool ShowPlain
    {
        get => _showPlain;
        set { if (_showPlain == value) return; _showPlain = value; PropertyChanged?.Invoke(this, new(nameof(ShowPlain))); }
    }

    /// <summary>Drops the reference to the password (a .NET string cannot be zeroed, but no reference remains).</summary>
    public void Forget() => Value = "";

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>
/// Safe handling of generated passwords in the generator:
///  - automatic clearing on minimize, Windows lock, sleep, idle and close,
///  - masked variants (revealed on hover or via the Show toggle),
///  - no references to old passwords remain after clearing.
/// Note: .NET strings are immutable and cannot be zeroed – shortening their on-screen lifetime and
/// dropping references is what is practically possible in WPF.
/// </summary>
public partial class MainWindow
{
    private const int GeneratorIdleMinutes = 3;
    private readonly DispatcherTimer _generatorIdleTimer = new() { Interval = TimeSpan.FromMinutes(GeneratorIdleMinutes) };
    private bool _generatorCleared;

    /// <summary>Wires the idle timer and the auto-clear triggers for generated passwords.</summary>
    private void InitGeneratorPrivacy()
    {
        _generatorIdleTimer.Tick += (_, _) =>
            ClearGeneratedPasswords($"Hidden after {GeneratorIdleMinutes} minutes of inactivity");
    }

    /// <summary>Restarts the idle countdown (called on every key press / click).</summary>
    private void TouchGeneratorIdleTimer()
    {
        if (_generatorCleared || string.IsNullOrEmpty(_current)) return;
        _generatorIdleTimer.Stop();
        _generatorIdleTimer.Start();
    }

    /// <summary>Shows new passwords and starts the idle countdown.</summary>
    private void ShowGeneratedPasswords(string main, IEnumerable<string> variants)
    {
        ForgetVariants();
        _generatorCleared = false;
        _current = main;
        UpdateMainPasswordDisplay();
        bool plain = ShowVariantsCheck.IsChecked == true;
        bool hover = HoverRevealCheck.IsChecked == true;
        VariantsList.ItemsSource = variants.Select(v => new VariantItem(v, plain, hover)).ToList();
        _generatorIdleTimer.Stop();
        _generatorIdleTimer.Start();
    }

    /// <summary>Clears the password and variants from the screen and drops references to them.</summary>
    private void ClearGeneratedPasswords(string reason)
    {
        _generatorIdleTimer.Stop();
        if (_generatorCleared) return;
        _generatorCleared = true;

        _current = "";
        ForgetVariants();
        VariantsList.ItemsSource = null;

        PasswordText.Inlines.Clear();
        PasswordText.Inlines.Add(new Run(reason + " – press Generate for a new one.")
        {
            FontSize = 15,
            FontFamily = FontFamily,
            Foreground = (System.Windows.Media.Brush)FindResource("SubtleBrush")
        });
        Log.Debug("Generated passwords cleared: {Reason}", reason);
    }

    /// <summary>Drops the reference to every variant password.</summary>
    private void ForgetVariants()
    {
        if (VariantsList.ItemsSource is IEnumerable<VariantItem> old)
            foreach (var v in old) v.Forget();
    }

    // ---------------- main password: mask / reveal ----------------

    private bool _mainPasswordHover;

    /// <summary>Main password: revealed on hover or when Show is on, otherwise a fixed-length mask.</summary>
    private void UpdateMainPasswordDisplay()
    {
        if (_generatorCleared || string.IsNullOrEmpty(_current)) return; // cleared – the info text is kept

        bool hoverReveal = HoverRevealCheck.IsChecked == true && _mainPasswordHover;
        if (ShowPasswordMainCheck.IsChecked == true || hoverReveal)
        {
            RenderPassword(_current);
            return;
        }

        PasswordText.Inlines.Clear();
        PasswordText.Inlines.Add(new Run(VariantItem.MaskText)
        {
            Foreground = (System.Windows.Media.Brush)FindResource("SubtleBrush")
        });
    }

    /// <summary>Applies the hover-reveal toggle to the main password and variants.</summary>
    private void HoverReveal_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        bool on = HoverRevealCheck.IsChecked == true;
        if (VariantsList.ItemsSource is IEnumerable<VariantItem> items)
            foreach (var v in items) v.HoverReveal = on;
        UpdateMainPasswordDisplay();
        _presetFile.HoverReveal = on;
    }

    /// <summary>Applies the Show toggle for the main password.</summary>
    private void ShowPasswordMain_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        UpdateMainPasswordDisplay();
    }

    /// <summary>Reveals the main password on hover when hover-reveal is enabled.</summary>
    private void PasswordBorder_MouseEnter(object sender, System.Windows.Input.MouseEventArgs e)
    {
        _mainPasswordHover = true;
        UpdateMainPasswordDisplay();
    }

    /// <summary>Re-masks the main password when the mouse leaves (if revealed only on hover).</summary>
    private void PasswordBorder_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e)
    {
        _mainPasswordHover = false;
        UpdateMainPasswordDisplay();
    }

    /// <summary>Shows or hides the list of variant passwords.</summary>
    private void ShowVariants_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        bool plain = ShowVariantsCheck.IsChecked == true;
        if (VariantsList.ItemsSource is IEnumerable<VariantItem> items)
            foreach (var v in items) v.ShowPlain = plain;
    }
}
