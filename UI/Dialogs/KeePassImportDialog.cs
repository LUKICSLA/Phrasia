using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace Phrasia;

/// <summary>What kind of file is being imported.</summary>
internal enum ImportFileKind { Kdbx, KeePassXml, Csv }

/// <summary>
/// Import options: for a KeePass database the password and/or key file; for every kind what to carry over
/// into the notes; for plain-text exports an offer to securely delete the file afterwards.
/// </summary>
internal sealed class KeePassImportDialog : Window
{
    private readonly PasswordBox _password = new() { Margin = new Thickness(0, 6, 0, 0) };
    private readonly TextBox _keyFile = new() { IsReadOnly = true, Margin = new Thickness(0, 6, 0, 0) };
    private readonly CheckBox _includeGroup = Toggle("Write the folder / group path into the note", true);
    private readonly CheckBox _includeFields = Toggle("Keep custom fields, tags and 2FA (TOTP) secrets in the note", true);
    private readonly CheckBox _deleteSource = Toggle("Securely delete the export file after a successful import", false);
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0), FontSize = 12 };
    private readonly ImportFileKind _kind;

    public string? Password => _kind == ImportFileKind.Kdbx ? _password.Password : null;
    public string? KeyFilePath => string.IsNullOrEmpty(_keyFile.Text) ? null : _keyFile.Text;
    public ImportOptions Options => new(_includeGroup.IsChecked == true, _includeFields.IsChecked == true);
    public bool DeleteSourceAfterImport => _kind != ImportFileKind.Kdbx && _deleteSource.IsChecked == true;

    public KeePassImportDialog(Window owner, string path, ImportFileKind kind)
    {
        _kind = kind;
        Owner = owner;
        Title = kind switch
        {
            ImportFileKind.Kdbx => "Import from KeePass",
            ImportFileKind.KeePassXml => "Import KeePass XML export",
            _ => "Import CSV export"
        };
        SizeToContent = SizeToContent.Height;
        Width = 480;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)Application.Current.Resources["WindowBrush"];
        Foreground = (Brush)Application.Current.Resources["TextBrush"];
        _error.Foreground = (Brush)Application.Current.Resources["DangerBrush"];

        var root = new StackPanel { Margin = new Thickness(22, 18, 22, 18) };
        root.Children.Add(new TextBlock { Text = "File", FontWeight = FontWeights.SemiBold });
        root.Children.Add(new TextBlock
        {
            Text = path,
            TextWrapping = TextWrapping.Wrap,
            Style = (Style)Application.Current.Resources["HintText"],
            Margin = new Thickness(0, 4, 0, 0),
        });

        if (kind == ImportFileKind.Kdbx)
        {
            root.Children.Add(new TextBlock
            {
                Text = "The database is decrypted only in memory and is not changed. Items are added to your vault as new items.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 12, 0, 0),
            });
            root.Children.Add(new TextBlock { Text = "KeePass master password", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 14, 0, 0) });
            root.Children.Add(_password);

            root.Children.Add(new TextBlock { Text = "Key file (only if the database uses one)", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 12, 0, 0) });
            var browse = new Button { Content = "Browse…", Style = (Style)Application.Current.Resources["GhostButton"], Margin = new Thickness(8, 6, 0, 0) };
            browse.Click += (_, _) => BrowseKeyFile();
            var clear = new Button { Content = "✕", Style = (Style)Application.Current.Resources["GhostButton"], Margin = new Thickness(6, 6, 0, 0), ToolTip = "Do not use a key file" };
            clear.Click += (_, _) => _keyFile.Text = "";
            var keyRow = new DockPanel();
            DockPanel.SetDock(clear, Dock.Right);
            DockPanel.SetDock(browse, Dock.Right);
            keyRow.Children.Add(clear);
            keyRow.Children.Add(browse);
            keyRow.Children.Add(_keyFile);
            root.Children.Add(keyRow);
        }
        else
        {
            root.Children.Add(new Border
            {
                Background = (Brush)Application.Current.Resources["WarningSoftBrush"],
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12, 8, 12, 8),
                Margin = new Thickness(0, 12, 0, 0),
                Child = new TextBlock
                {
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = (Brush)Application.Current.Resources["WarningBrush"],
                    FontSize = 12,
                    Text = "This export holds all your passwords in plain text. Anyone or any program that can read the file can read them. " +
                           "Delete it as soon as the import is done – the option below overwrites it before deleting.",
                },
            });
        }

        root.Children.Add(new TextBlock
        {
            Text = "OPTIONS",
            Style = (Style)Application.Current.Resources["SectionLabel"],
        });
        root.Children.Add(_includeGroup);
        root.Children.Add(_includeFields);
        if (kind != ImportFileKind.Kdbx) root.Children.Add(_deleteSource);
        root.Children.Add(new TextBlock
        {
            Text = "Items that are already in your vault (same title, username, password and website) are skipped, " +
                   "so importing the same file twice adds nothing." +
                   (kind == ImportFileKind.Csv ? "" : " The KeePass recycle bin is not imported; attachments are listed by name in the note."),
            Style = (Style)Application.Current.Resources["HintText"],
            FontSize = 12,
            Margin = new Thickness(0, 12, 0, 0),
        });
        root.Children.Add(_error);

        var ok = new Button { Content = "Continue", IsDefault = true, MinWidth = 100, Margin = new Thickness(0, 16, 8, 0), Style = (Style)Application.Current.Resources["PrimaryButton"] };
        ok.Click += (_, _) => Accept();
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90, Margin = new Thickness(0, 16, 0, 0), Style = (Style)Application.Current.Resources["GhostButton"] };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        root.Children.Add(buttons);
        Content = root;

        SourceInitialized += (_, _) =>
        {
            if (owner is MainWindow main && main.IsCaptureProtectionOn) MainWindow.ApplyCaptureProtection(this, true);
        };
        Loaded += (_, _) => { if (kind == ImportFileKind.Kdbx) _password.Focus(); };
    }

    /// <summary>Validates the input and closes with OK.</summary>
    private void Accept()
    {
        if (_kind == ImportFileKind.Kdbx && _password.Password.Length == 0 && KeyFilePath is null)
        {
            _error.Text = "Enter the KeePass master password, choose a key file, or both.";
            _password.Focus();
            return;
        }
        if (KeyFilePath is not null && !File.Exists(KeyFilePath))
        {
            _error.Text = "The key file no longer exists.";
            return;
        }
        DialogResult = true;
    }

    private void BrowseKeyFile()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Choose the KeePass key file",
            Filter = "KeePass key files (*.keyx;*.key)|*.keyx;*.key|All files (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == true) _keyFile.Text = dlg.FileName;
    }

    private static CheckBox Toggle(string text, bool on) => new()
    {
        Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap },
        IsChecked = on,
        Margin = new Thickness(0, 10, 0, 0),
    };
}
