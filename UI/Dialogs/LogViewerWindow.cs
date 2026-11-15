using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>
/// Built-in log viewer. Logs are encrypted on disk (DPAPI) and unreadable in an editor; here they are
/// decrypted and shown read-only. They never contain passwords or vault content.
/// </summary>
internal sealed class LogViewerWindow : Window
{
    /// <summary>Builds the window and loads the decrypted recent log lines into a read-only box.</summary>
    public LogViewerWindow(Window owner)
    {
        Owner = owner;
        Title = "Phrasia – logs (decrypted view)";
        Width = 760;
        Height = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)owner.FindResource("WindowBrush");
        Foreground = (Brush)owner.FindResource("TextBrush");

        var root = new DockPanel { Margin = new Thickness(16) };

        var note = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10),
            Opacity = 0.8,
            FontSize = 12,
            Text = "These logs are stored encrypted on disk (Windows DPAPI) and are readable only here, " +
                   "by your Windows account. They stay on this computer and contain no passwords or vault content."
        };
        DockPanel.SetDock(note, Dock.Top);
        root.Children.Add(note);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 10, 0, 0)
        };
        DockPanel.SetDock(buttons, Dock.Bottom);
        var close = new Button { Content = "Close", IsCancel = true, MinWidth = 90, Style = (Style)Application.Current.Resources["GhostButton"] };
        close.Click += (_, _) => Close();
        buttons.Children.Add(close);
        root.Children.Add(buttons);

        var lines = Logging.ReadDecrypted();
        var text = lines.Count == 0 ? "(no log entries yet)" : string.Join(Environment.NewLine, lines);

        var box = new TextBox
        {
            Text = text,
            IsReadOnly = true,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
            FontSize = 12,
            Background = (Brush)owner.FindResource("SurfaceBrush"),
            Foreground = (Brush)owner.FindResource("TextBrush"),
            BorderThickness = new Thickness(1),
            BorderBrush = (Brush)owner.FindResource("LineBrush"),
            Padding = new Thickness(8)
        };
        box.CaretIndex = box.Text.Length;
        root.Children.Add(box);

        Content = root;
        Loaded += (_, _) => box.ScrollToEnd();
    }
}
