using System.Media;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Phrasia;

/// <summary>
/// Message box in the app's design – a drop-in replacement for <see cref="MessageBox"/>: same buttons, icons,
/// default button and results, the matching system sound, Enter = default button, Esc/× = the safe choice
/// (Cancel, or No for Yes/No), Ctrl+C copies the text. Falls back to the system message box if it cannot be built.
/// </summary>
internal sealed class AppMessageBox : Window
{
    private static readonly Color ErrorColor = Color.FromRgb(0xC6, 0x28, 0x28);
    private static readonly Color WarningColor = Color.FromRgb(0xE6, 0x51, 0x00);
    private static readonly Color AccentColor = Color.FromRgb(0x6D, 0x4A, 0xFF);

    private readonly string _text;
    private readonly MessageBoxResult _closeResult;
    private MessageBoxResult _result;

    /// <summary>Shows a message owned by <paramref name="owner"/> and returns the button the user chose.</summary>
    public static MessageBoxResult Show(Window? owner, string text, string caption = MainWindow.AppName,
        MessageBoxButton buttons = MessageBoxButton.OK, MessageBoxImage icon = MessageBoxImage.None,
        MessageBoxResult defaultResult = MessageBoxResult.None)
    {
        AppMessageBox box;
        try
        {
            box = new AppMessageBox(owner, text, caption, buttons, icon, defaultResult);
        }
        catch (Exception)
        {
            // e.g. very early startup or shutdown without app resources – use the system message box instead
            return owner is { IsLoaded: true, IsVisible: true }
                ? MessageBox.Show(owner, text, caption, buttons, icon, defaultResult)
                : MessageBox.Show(text, caption, buttons, icon, defaultResult);
        }
        PlaySound(icon);
        box.ShowDialog();
        return box._result;
    }

    /// <summary>Shows a message without an owner window (centred on the screen).</summary>
    public static MessageBoxResult Show(string text, string caption = MainWindow.AppName,
        MessageBoxButton buttons = MessageBoxButton.OK, MessageBoxImage icon = MessageBoxImage.None,
        MessageBoxResult defaultResult = MessageBoxResult.None) =>
        Show(null, text, caption, buttons, icon, defaultResult);

    /// <summary>Builds the window: optional icon, wrapped text and the buttons for <paramref name="buttons"/>.</summary>
    private AppMessageBox(Window? owner, string text, string caption, MessageBoxButton buttons,
        MessageBoxImage icon, MessageBoxResult defaultResult)
    {
        _text = text;
        if (owner is { IsLoaded: true, IsVisible: true }) Owner = owner;
        Title = caption;
        WindowStartupLocation = Owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner;
        ShowInTaskbar = Owner is null;
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        MinWidth = 340;
        FontFamily = (owner ?? Application.Current?.MainWindow)?.FontFamily ?? SystemFonts.MessageFontFamily;
        FontSize = 13;
        Background = Res("WindowBrush", Color.FromRgb(0xF5, 0xF6, 0xFA));
        Foreground = Res("TextBrush", Color.FromRgb(0x1E, 0x1F, 0x2B));

        // closing without a button (Esc / ×) returns the safe choice, like the system message box
        _closeResult = buttons switch
        {
            MessageBoxButton.OKCancel or MessageBoxButton.YesNoCancel => MessageBoxResult.Cancel,
            MessageBoxButton.YesNo => MessageBoxResult.No,
            _ => MessageBoxResult.OK
        };
        _result = _closeResult;

        var root = new Grid { Margin = new Thickness(22, 20, 22, 18) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var badge = IconBadge(icon);
        if (badge is not null) root.Children.Add(badge);

        var message = new TextBlock
        {
            Text = text,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 440,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(badge is null ? 0 : 14, 0, 0, 0)
        };
        Grid.SetColumn(message, 1);
        root.Children.Add(message);

        var specs = buttons switch
        {
            MessageBoxButton.OKCancel => new[] { (MessageBoxResult.OK, "OK"), (MessageBoxResult.Cancel, "Cancel") },
            MessageBoxButton.YesNo => new[] { (MessageBoxResult.Yes, "Yes"), (MessageBoxResult.No, "No") },
            MessageBoxButton.YesNoCancel => new[] { (MessageBoxResult.Yes, "Yes"), (MessageBoxResult.No, "No"), (MessageBoxResult.Cancel, "Cancel") },
            _ => new[] { (MessageBoxResult.OK, "OK") }
        };
        var defaultChoice = specs.Any(s => s.Item1 == defaultResult) ? defaultResult : specs[0].Item1;

        var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        Button? defaultButton = null;
        for (int i = 0; i < specs.Length; i++)
        {
            var (choice, label) = specs[i];
            var button = new Button
            {
                Content = label,
                MinWidth = 88,
                Margin = new Thickness(i == 0 ? 0 : 8, 0, 0, 0),
                IsDefault = choice == defaultChoice
            };
            // the affirmative action (OK / Yes) is the primary button, the others are quiet
            if (Application.Current?.TryFindResource(i == 0 ? "PrimaryButton" : "GhostButton") is Style style) button.Style = style;
            button.Click += (_, _) => { _result = choice; Close(); };
            if (button.IsDefault) defaultButton = button;
            row.Children.Add(button);
        }
        Grid.SetRow(row, 1);
        Grid.SetColumnSpan(row, 2);
        root.Children.Add(row);

        Content = root;
        PreviewKeyDown += OnPreviewKeyDown;
        Loaded += (_, _) => defaultButton?.Focus();
    }

    /// <summary>Esc closes with the safe choice; Ctrl+C copies the message (like the system message box).</summary>
    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            _result = _closeResult;
            Close();
            e.Handled = true;
        }
        else if (e.Key == Key.C && Keyboard.Modifiers == ModifierKeys.Control)
        {
            try { Clipboard.SetText(Title + Environment.NewLine + Environment.NewLine + _text); }
            catch (ExternalException) { /* another app holds the clipboard – ignore */ }
            e.Handled = true;
        }
    }

    /// <summary>Round coloured badge with a symbol for the icon type, or null for <see cref="MessageBoxImage.None"/>.</summary>
    private static Border? IconBadge(MessageBoxImage icon)
    {
        (Color color, string symbol)? look = icon switch
        {
            MessageBoxImage.Error => (ErrorColor, "✕"),
            MessageBoxImage.Warning => (WarningColor, "!"),
            MessageBoxImage.Question => (AccentColor, "?"),
            MessageBoxImage.Information => (AccentColor, "i"),
            _ => null
        };
        if (look is not { } l) return null;
        return new Border
        {
            Width = 36,
            Height = 36,
            CornerRadius = new CornerRadius(18),
            Background = new SolidColorBrush(l.color),
            VerticalAlignment = VerticalAlignment.Top,
            Child = new TextBlock
            {
                Text = l.symbol,
                Foreground = Brushes.White,
                FontFamily = new FontFamily("Segoe UI"),
                FontWeight = FontWeights.Bold,
                FontSize = 18,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            }
        };
    }

    /// <summary>Plays the system sound that belongs to the icon type.</summary>
    private static void PlaySound(MessageBoxImage icon)
    {
        switch (icon)
        {
            case MessageBoxImage.Error: SystemSounds.Hand.Play(); break;
            case MessageBoxImage.Warning: SystemSounds.Exclamation.Play(); break;
            case MessageBoxImage.Question: SystemSounds.Question.Play(); break;
            case MessageBoxImage.Information: SystemSounds.Asterisk.Play(); break;
        }
    }

    /// <summary>An app brush by key, or the given colour when the resource is not available.</summary>
    private static Brush Res(string key, Color fallback) =>
        Application.Current?.TryFindResource(key) as Brush ?? new SolidColorBrush(fallback);
}
