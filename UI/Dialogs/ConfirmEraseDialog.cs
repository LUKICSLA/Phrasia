using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>
/// Confirmation dialog for irreversible vault erasure: the user must type the word ERASE
/// to enable the destructive button.
/// </summary>
internal sealed class ConfirmEraseDialog : Window
{
    private const string ConfirmWord = "ERASE";

    /// <summary>Builds the dialog; the erase button enables only when the confirmation word matches.</summary>
    public ConfirmEraseDialog(Window owner)
    {
        Owner = owner;
        Title = "Erase vault";
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)Application.Current.Resources["WindowBrush"];

        var danger = new SolidColorBrush(Color.FromRgb(0xC6, 0x28, 0x28));
        danger.Freeze();

        var box = new TextBox { FontFamily = new FontFamily("Cascadia Mono, Consolas") };

        var erase = new Button
        {
            Content = "Erase vault permanently",
            IsEnabled = false,
            Margin = new Thickness(0, 16, 8, 0),
            Background = danger,
            Style = (Style)Application.Current.Resources["PrimaryButton"]
        };
        erase.Click += (_, _) => DialogResult = true;

        var cancel = new Button
        {
            Content = "Cancel",
            IsCancel = true,
            IsDefault = true,
            Margin = new Thickness(0, 16, 0, 0),
            Style = (Style)Application.Current.Resources["GhostButton"]
        };

        box.TextChanged += (_, _) => erase.IsEnabled = box.Text.Trim() == ConfirmWord;

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(erase);
        buttons.Children.Add(cancel);

        var root = new StackPanel { Margin = new Thickness(22), Width = 400 };
        root.Children.Add(new TextBlock
        {
            Text = "Forgot your master password?",
            FontSize = 17,
            FontWeight = FontWeights.Bold
        });
        root.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0),
            Foreground = (Brush)Application.Current.Resources["MutedBrush"],
            Text = "Without the master password the vault cannot be decrypted – not even by the author of this app. " +
                   "You can erase it and start over with a new, empty vault."
        });
        root.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 10, 0, 0),
            Foreground = danger,
            FontWeight = FontWeights.SemiBold,
            Text = "All saved passwords will be lost for good. The vault file is overwritten with random data " +
                   "before it is deleted. Backups you saved elsewhere are not touched."
        });
        root.Children.Add(new TextBlock
        {
            Text = $"Type {ConfirmWord} to confirm:",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 16, 0, 0)
        });
        root.Children.Add(box);
        root.Children.Add(buttons);
        Content = root;

        Loaded += (_, _) => box.Focus();
    }
}
