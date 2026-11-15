using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>Modal dialog for entering a short, non-empty text value (e.g. a preset name).</summary>
internal sealed class TextInputDialog : Window
{
    private readonly TextBox _box;

    /// <summary>The trimmed text the user entered.</summary>
    public string Value => _box.Text.Trim();

    /// <summary>Builds the dialog; the Save button stays disabled while the field is empty.</summary>
    public TextInputDialog(Window owner, string title, string message, string initial = "", int maxLength = 40)
    {
        Owner = owner;
        Title = title;
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)Application.Current.Resources["WindowBrush"];

        _box = new TextBox { Text = initial, MaxLength = maxLength };

        var ok = new Button
        {
            Content = "Save", IsDefault = true, IsEnabled = initial.Trim().Length > 0,
            Margin = new Thickness(0, 16, 8, 0), Style = (Style)Application.Current.Resources["PrimaryButton"]
        };
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button
        {
            Content = "Cancel", IsCancel = true, Margin = new Thickness(0, 16, 0, 0),
            Style = (Style)Application.Current.Resources["GhostButton"]
        };
        _box.TextChanged += (_, _) => ok.IsEnabled = _box.Text.Trim().Length > 0;

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        var root = new StackPanel { Margin = new Thickness(22), Width = 340 };
        root.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, FontWeight = FontWeights.SemiBold });
        root.Children.Add(_box);
        root.Children.Add(buttons);
        Content = root;

        Loaded += (_, _) => { _box.Focus(); _box.SelectAll(); };
    }
}
