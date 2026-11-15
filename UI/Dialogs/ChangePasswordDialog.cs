using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>Dialog for changing the master password (current, new, confirm) with live strength validation.</summary>
internal sealed class ChangePasswordDialog : Window
{
    private readonly PasswordBox _current = NewBox();
    private readonly PasswordBox _new = NewBox();
    private readonly PasswordBox _confirm = NewBox();
    private readonly TextBlock _info = new() { FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
    private readonly Button _ok;
    private readonly TextBox _suggestion = new() { IsReadOnly = true, FontSize = 15, Margin = new Thickness(0, 4, 0, 0) };
    private readonly StackPanel _suggestionPanel = new() { Visibility = Visibility.Collapsed, Margin = new Thickness(0, 8, 0, 0) };

    /// <summary>The current master password entered by the user.</summary>
    public string CurrentPassword => _current.Password;
    /// <summary>The new master password entered by the user.</summary>
    public string NewPassword => _new.Password;

    /// <summary>Builds the dialog and wires live validation of the three password fields.</summary>
    public ChangePasswordDialog(Window owner)
    {
        Owner = owner;
        Title = "Change master password";
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)Application.Current.Resources["WindowBrush"];

        _ok = new Button
        {
            Content = "Change password", IsDefault = true, IsEnabled = false, Margin = new Thickness(0, 16, 8, 0),
            Style = (Style)Application.Current.Resources["PrimaryButton"]
        };
        _ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button
        {
            Content = "Cancel", IsCancel = true, Margin = new Thickness(0, 16, 0, 0),
            Style = (Style)Application.Current.Resources["GhostButton"]
        };

        var suggest = new Button
        {
            Content = "Suggest a strong password", HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(0, 8, 0, 0), Style = (Style)Application.Current.Resources["SecondaryButton"]
        };
        suggest.Click += (_, _) =>
        {
            if (!EntropyDialog.EnsureFresh(this, "your new master password")) return;
            string pw = MasterPasswordPolicy.Suggest();
            _suggestion.Text = pw;
            _suggestionPanel.Visibility = Visibility.Visible;
            _new.Password = pw;
            _confirm.Password = pw;
        };
        if (Application.Current.TryFindResource("MonoFont") is FontFamily mono) _suggestion.FontFamily = mono;
        _suggestionPanel.Children.Add(new TextBlock
        {
            Text = "Memorize it (or write it on paper and keep it somewhere safe):",
            TextWrapping = TextWrapping.Wrap, FontSize = 12,
            Foreground = (Brush)Application.Current.Resources["MutedBrush"]
        });
        _suggestionPanel.Children.Add(_suggestion);

        _new.PasswordChanged += (_, _) =>
        {
            // a suggestion that is no longer the new password must not stay on screen
            if (_suggestionPanel.Visibility == Visibility.Visible && _new.Password != _suggestion.Text)
            {
                _suggestion.Text = "";
                _suggestionPanel.Visibility = Visibility.Collapsed;
            }
            Validate();
        };
        _confirm.PasswordChanged += (_, _) => Validate();
        _current.PasswordChanged += (_, _) => Validate();

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(_ok);
        buttons.Children.Add(cancel);

        var root = new StackPanel { Margin = new Thickness(22), Width = 380 };
        root.Children.Add(new TextBlock
        {
            Text = "The vault will be re-encrypted with a new key and a fresh salt. " +
                   "Existing header backups stop working – create a new one afterwards.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.Resources["MutedBrush"]
        });
        root.Children.Add(Label("Current master password"));
        root.Children.Add(_current);
        root.Children.Add(Label("New master password"));
        root.Children.Add(_new);
        root.Children.Add(suggest);
        root.Children.Add(_suggestionPanel);
        root.Children.Add(Label("Confirm new master password"));
        root.Children.Add(_confirm);
        root.Children.Add(_info);
        root.Children.Add(buttons);
        Content = root;

        Loaded += (_, _) => _current.Focus();
        // the dialog can show a password in plain text – follow the main window's screen-capture protection
        SourceInitialized += (_, _) =>
        {
            if (owner is MainWindow main && main.IsCaptureProtectionOn) MainWindow.ApplyCaptureProtection(this, true);
        };
        Closed += (_, _) => _suggestion.Text = "";
    }

    /// <summary>Checks the fields (presence, policy, difference, match) and updates the hint and OK button.</summary>
    private void Validate()
    {
        string pw = _new.Password;
        string? problem =
            _current.Password.Length == 0 ? "Enter your current master password." :
            pw.Length == 0 ? "" :
            MasterPasswordPolicy.Validate(pw) ??
            (pw == _current.Password ? "The new password must be different from the current one." :
             _confirm.Password != pw ? "The new passwords do not match." : null);

        _ok.IsEnabled = problem is null;
        _info.Text = problem ?? $"New password strength ≈ {MasterPasswordPolicy.EstimateBits(pw):F0} bits – good.";
        _info.Foreground = problem is null ? Brushes.ForestGreen : Brushes.Firebrick;
    }

    /// <summary>Creates an empty password box.</summary>
    private static PasswordBox NewBox() => new();

    /// <summary>Creates a bold field label with top margin.</summary>
    private static TextBlock Label(string text) => new()
    {
        Text = text,
        FontWeight = FontWeights.SemiBold,
        Margin = new Thickness(0, 14, 0, 0)
    };
}
