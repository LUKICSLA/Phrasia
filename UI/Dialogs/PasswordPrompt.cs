using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>Modal dialog that asks for the master password (to confirm sensitive actions), optionally a PIM.</summary>
internal sealed class PasswordPrompt : Window
{
    private readonly PasswordBox _box = new()
    {
        Margin = new Thickness(0, 10, 0, 0)
    };
    private readonly TextBox? _pimBox;

    /// <summary>The password the user entered.</summary>
    public string Password => _box.Password;

    /// <summary>The entered PIM (0 = blank/none); only present when the prompt was created with askPim.</summary>
    public int Pim => _pimBox is not null && int.TryParse(_pimBox.Text.Trim(), out var v) ? v : 0;

    /// <summary>Builds the dialog with a message, a password box, and (when askPim) an optional numeric PIM box.</summary>
    public PasswordPrompt(Window owner, string message, bool askPim = false)
    {
        Owner = owner;
        Title = "Confirm with master password";
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)Application.Current.Resources["WindowBrush"];

        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 16, 8, 0), Style = (Style)Application.Current.Resources["PrimaryButton"] };
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90, Margin = new Thickness(0, 16, 0, 0), Style = (Style)Application.Current.Resources["GhostButton"] };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        var root = new StackPanel { Margin = new Thickness(18), Width = 340 };
        root.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        root.Children.Add(_box);
        if (askPim)
        {
            _pimBox = new TextBox { Margin = new Thickness(0, 10, 0, 0), MaxLength = 3 };
            _pimBox.PreviewTextInput += (_, ev) => ev.Handled = !ev.Text.All(char.IsDigit);
            root.Children.Add(new TextBlock
            {
                Text = "PIM (leave blank if the backup has none):",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 10, 0, 0),
                FontSize = 12,
                Opacity = 0.8
            });
            root.Children.Add(_pimBox);
        }
        root.Children.Add(buttons);
        Content = root;

        Loaded += (_, _) => _box.Focus();
    }
}
