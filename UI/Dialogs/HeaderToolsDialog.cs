using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace Phrasia;

/// <summary>
/// VeraCrypt-style header tool for a locked vault: checks the vault header against a header backup (*.bak)
/// without changing anything, or asks the main window to restore the header from that backup.
/// </summary>
internal sealed class HeaderToolsDialog : Window
{
    private readonly TextBox _file = new();
    private readonly PasswordBox _password = new();
    private readonly TextBox _pim = new() { MaxLength = 3 };
    private readonly TextBlock _result = new() { TextWrapping = TextWrapping.Wrap, FontSize = 12 };
    private readonly Border _resultBox;
    private readonly Button _check;
    private readonly Button _restore;
    private readonly Func<string, string, int, Task<string>> _runCheck;

    /// <summary>True when the user chose "Restore header…" (the main window then performs the restore).</summary>
    public bool RestoreRequested { get; private set; }
    /// <summary>The selected header backup file.</summary>
    public string BackupPath => _file.Text.Trim();
    /// <summary>The entered master password.</summary>
    public string Password => _password.Password;
    /// <summary>The PIM as typed (blank = none).</summary>
    public string PimText => _pim.Text.Trim();
    /// <summary>The entered PIM (0 = blank/none).</summary>
    public int Pim => int.TryParse(PimText, out var v) ? v : 0;

    /// <summary>Builds the dialog, pre-filled with the password/PIM typed on the lock screen; <paramref name="runCheck"/> performs the read-only check and returns a report.</summary>
    public HeaderToolsDialog(Window owner, string password, string pim, Func<string, string, int, Task<string>> runCheck)
    {
        _runCheck = runCheck;
        Owner = owner;
        Title = "Vault header – check / restore";
        Width = 560;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)owner.FindResource("WindowBrush");
        Foreground = (Brush)owner.FindResource("TextBrush");

        _password.Password = password;
        _pim.Text = pim;
        _pim.PreviewTextInput += (_, ev) => ev.Handled = !ev.Text.All(char.IsDigit);

        var root = new StackPanel { Margin = new Thickness(18) };
        root.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            FontSize = 12,
            Opacity = 0.85,
            Text = "The header at the start of the vault file holds its salt and key-derivation settings. If it gets " +
                   "damaged, the vault will not open even with the correct password and PIM.\n\n" +
                   "Choose a header backup (*.bak – created with \"Header backup\" in the unlocked vault). " +
                   "\"Check\" only verifies and never changes anything. \"Restore header…\" replaces the vault header " +
                   "with the one from the backup (the original file is kept as *.before-restore)."
        });

        root.Children.Add(Label("Header backup file"));
        var browse = new Button { Content = "Browse…", Margin = new Thickness(8, 0, 0, 0), Style = (Style)Application.Current.Resources["SecondaryButton"] };
        browse.Click += (_, _) => Browse();
        var fileRow = new DockPanel();
        DockPanel.SetDock(browse, Dock.Right);
        fileRow.Children.Add(browse);
        fileRow.Children.Add(_file);
        root.Children.Add(fileRow);

        root.Children.Add(Label("Master password (the one the backup was created with)"));
        root.Children.Add(_password);
        root.Children.Add(Label("PIM (leave blank for vaults without a PIM)"));
        root.Children.Add(_pim);

        _resultBox = new Border
        {
            Child = _result,
            Padding = new Thickness(12, 10, 12, 10),
            Margin = new Thickness(0, 14, 0, 0),
            CornerRadius = new CornerRadius(8),
            BorderThickness = new Thickness(1),
            BorderBrush = (Brush)owner.FindResource("LineBrush"),
            Background = (Brush)owner.FindResource("SurfaceBrush"),
            Visibility = Visibility.Collapsed
        };
        root.Children.Add(_resultBox);

        _check = new Button { Content = "Check", IsDefault = true, MinWidth = 100, Margin = new Thickness(0, 16, 8, 0), Style = (Style)Application.Current.Resources["PrimaryButton"] };
        _check.Click += async (_, _) => await CheckAsync();
        _restore = new Button { Content = "Restore header…", Margin = new Thickness(0, 16, 8, 0), Style = (Style)Application.Current.Resources["SecondaryButton"] };
        _restore.Click += (_, _) =>
        {
            if (!Validate()) return;
            RestoreRequested = true;
            DialogResult = true;
        };
        var close = new Button { Content = "Close", IsCancel = true, MinWidth = 90, Margin = new Thickness(0, 16, 0, 0), Style = (Style)Application.Current.Resources["GhostButton"] };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(_check);
        buttons.Children.Add(_restore);
        buttons.Children.Add(close);
        root.Children.Add(buttons);

        Content = root;
        Loaded += (_, _) => { if (_password.Password.Length == 0) _password.Focus(); else _file.Focus(); };
    }

    /// <summary>Small caption above an input.</summary>
    private static TextBlock Label(string text) => new()
    {
        Text = text,
        FontSize = 12,
        Opacity = 0.8,
        Margin = new Thickness(0, 12, 0, 4)
    };

    /// <summary>Lets the user pick the header backup file.</summary>
    private void Browse()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Choose a header backup",
            Filter = "Header backup (*.bak)|*.bak|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) == true) _file.Text = dlg.FileName;
    }

    /// <summary>Validates the inputs and shows the problem in the result box.</summary>
    private bool Validate()
    {
        string? error = null;
        if (BackupPath.Length == 0 || !File.Exists(BackupPath)) error = "Choose an existing header backup file.";
        else if (Password.Length == 0) error = "Enter the master password the backup was created with.";
        else if (PimText.Length > 0 && (Pim < Vault.MinPim || Pim > Vault.MaxPim))
            error = $"The PIM must be a number between {Vault.MinPim} and {Vault.MaxPim}, or blank.";
        if (error is null) return true;
        ShowResult(error, isError: true);
        return false;
    }

    /// <summary>Runs the read-only check and shows its report.</summary>
    private async Task CheckAsync()
    {
        if (!Validate()) return;
        _check.IsEnabled = _restore.IsEnabled = false;
        ShowResult("Checking… (key derivation takes a few seconds)", isError: false);
        try
        {
            ShowResult(await _runCheck(BackupPath, Password, Pim), isError: false);
        }
        finally
        {
            _check.IsEnabled = _restore.IsEnabled = true;
        }
    }

    /// <summary>Shows a message or report in the result box.</summary>
    private void ShowResult(string text, bool isError)
    {
        _result.Text = text;
        _result.Foreground = isError ? ThemeManager.Brush("DangerBrush") : Foreground;
        _resultBox.Visibility = Visibility.Visible;
    }
}
