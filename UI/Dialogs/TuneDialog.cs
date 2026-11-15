using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>
/// "Tune to this PC" dialog: pick the target unlock time (1–10 s) or Maximum, confirmed by the master password.
/// Longer time = more Argon2id memory/passes = slower guessing for an attacker.
/// </summary>
internal sealed class TuneDialog : Window
{
    private readonly PasswordBox _box = new()
    {
        Margin = new Thickness(0, 6, 0, 0)
    };
    private readonly ComboBox _target = new() { Margin = new Thickness(0, 6, 0, 0) };
    private readonly TextBlock _hint = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0), Opacity = 0.75, FontSize = 12 };

    /// <summary>The master password entered for confirmation.</summary>
    public string Password => _box.Password;
    /// <summary>Selected combo tag: -1 = maximum, otherwise the target seconds.</summary>
    private int SelectedTag => (_target.SelectedItem as ComboBoxItem)?.Tag is int s ? s : 1;
    /// <summary>True when the "Maximum (hardest this PC allows)" option is selected.</summary>
    public bool Maximum => SelectedTag == -1;
    /// <summary>Target unlock time in seconds (10 when Maximum is chosen).</summary>
    public int TargetSeconds => Maximum ? 10 : SelectedTag;

    /// <summary>Builds the dialog with the time choices plus a Maximum option, preselecting the current setting.</summary>
    public TuneDialog(Window owner, string currentKdf, int currentTargetSeconds)
    {
        Owner = owner;
        Title = "Tune to this PC";
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)Application.Current.Resources["WindowBrush"];

        foreach (var s in Argon2Calibrator.TargetChoicesSeconds)
        {
            var label = s switch
            {
                1 => "1 second (recommended)",
                2 => "2 seconds",
                3 => "3 seconds",
                5 => "5 seconds",
                _ => $"{s} seconds (maximum)"
            };
            var item = new ComboBoxItem { Content = label, Tag = s };
            _target.Items.Add(item);
            if (s == currentTargetSeconds) _target.SelectedItem = item;
        }
        _target.Items.Add(new ComboBoxItem { Content = "Maximum (hardest this PC allows)", Tag = -1 });
        if (_target.SelectedItem is null) _target.SelectedIndex = 0;
        _target.SelectionChanged += (_, _) => UpdateHint();
        UpdateHint();

        var ok = new Button { Content = "Tune", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 16, 8, 0), Style = (Style)Application.Current.Resources["PrimaryButton"] };
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90, Margin = new Thickness(0, 16, 0, 0), Style = (Style)Application.Current.Resources["GhostButton"] };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        var root = new StackPanel { Margin = new Thickness(18), Width = 380 };
        root.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Text = "Phrasia will benchmark Argon2id on this computer and re-encrypt the vault with as much memory " +
                   "and as many passes as fit into the chosen unlock time (never less than 64 MiB, 3 passes, 4 lanes)."
        });
        root.Children.Add(new TextBlock { Text = "Current: " + currentKdf, Margin = new Thickness(0, 8, 0, 0), Opacity = 0.75, FontSize = 12 });
        root.Children.Add(new TextBlock { Text = "Unlock time", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 12, 0, 0) });
        root.Children.Add(_target);
        root.Children.Add(_hint);
        root.Children.Add(new TextBlock { Text = "Master password", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 12, 0, 0) });
        root.Children.Add(_box);
        root.Children.Add(buttons);
        Content = root;

        Loaded += (_, _) => _box.Focus();
    }

    /// <summary>Updates the explanatory hint to match the selected unlock time (or Maximum).</summary>
    private void UpdateHint() => _hint.Text = Maximum
        ? "Uses the most memory, passes and threads this computer allows, ignoring the time target. " +
          "Choose this if even 10 s is too fast here. Unlocking may take many seconds — and much longer on a slower PC."
        : TargetSeconds switch
        {
            1 => "Good balance – every guess costs an attacker about 1 s of this computer's work.",
            <= 3 => $"Each password guess becomes about {TargetSeconds}× more expensive than at 1 s. You wait {TargetSeconds} s on every unlock.",
            _ => $"Each guess costs about {TargetSeconds}× more than at 1 s. Unlocking (and auto-lock re-unlocks) will take ~{TargetSeconds} s, " +
                 "and much longer on a slower computer."
        };
}
