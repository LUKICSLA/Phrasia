using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Phrasia;

/// <summary>
/// Shows how long it would take, on average, to crack a password of the given strength in several attack scenarios
/// (from a rate-limited website login to an offline GPU farm), with a short explanation of the assumptions.
/// </summary>
internal sealed class CrackTimeDialog : Window
{
    /// <summary>Builds the dialog for a password of <paramref name="bits"/> estimated strength.</summary>
    public CrackTimeDialog(Window owner, double bits)
    {
        Owner = owner;
        Title = "Time to crack";
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = Res("WindowBrush");
        Foreground = Res("TextBrush");
        var iconFont = (FontFamily)Application.Current.Resources["IconFont"];

        var root = new StackPanel { Margin = new Thickness(24, 22, 24, 20), Width = 660 };

        // ---- header ----
        var header = new DockPanel();
        var badge = new Border
        {
            Width = 44, Height = 44, CornerRadius = new CornerRadius(12), Background = Res("HeroBrush"),
            Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Top,
            Child = new TextBlock
            {
                Text = "", FontFamily = iconFont, FontSize = 20, Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center
            }
        };
        DockPanel.SetDock(badge, Dock.Left);
        header.Children.Add(badge);
        var titles = new StackPanel();
        titles.Children.Add(new TextBlock { Text = "How long would it take to crack?", FontSize = 17, FontWeight = FontWeights.SemiBold });
        titles.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0), Foreground = Res("MutedBrush"),
            Text = $"Estimated strength ≈ {bits:F0} bits, i.e. about 2^{bits:F0} possible passwords. " +
                   "Average time = trying half of them."
        });
        header.Children.Add(titles);
        root.Children.Add(header);

        // ---- table of scenarios ----
        var table = new Grid { Margin = new Thickness(0, 18, 0, 0) };
        table.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        table.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(130) });
        table.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(250) });

        AddCell(table, 0, 0, new TextBlock { Text = "ATTACK", Style = Sec() });
        AddCell(table, 0, 1, new TextBlock { Text = "GUESSES", Style = Sec() });
        AddCell(table, 0, 2, new TextBlock { Text = "AVERAGE TIME", Style = Sec(), HorizontalAlignment = HorizontalAlignment.Right });

        var estimates = CrackTimeEstimator.EstimateAll(bits);
        for (int i = 0; i < estimates.Count; i++)
        {
            var est = estimates[i];
            int row = i + 1;
            table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var stripe = new Border
            {
                Background = i % 2 == 0 ? Res("SurfaceBrush") : Brushes.Transparent,
                CornerRadius = new CornerRadius(8)
            };
            Grid.SetRow(stripe, row);
            Grid.SetColumnSpan(stripe, 3);
            table.Children.Add(stripe);

            var name = new StackPanel { Margin = new Thickness(12, 9, 8, 9) };
            name.Children.Add(new TextBlock { Text = est.Scenario.Name, FontWeight = FontWeights.SemiBold });
            name.Children.Add(new TextBlock
            {
                Text = est.Scenario.Description, FontSize = 12, Foreground = Res("MutedBrush"), TextWrapping = TextWrapping.Wrap
            });
            AddCell(table, row, 0, name);
            AddCell(table, row, 1, new TextBlock
            {
                Text = CrackTimeEstimator.FormatRate(est.Scenario.GuessesPerSecond),
                FontFamily = (FontFamily)Application.Current.Resources["MonoFont"], FontSize = 12,
                Foreground = Res("MutedBrush"), VerticalAlignment = VerticalAlignment.Center
            });
            var time = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) };
            time.Children.Add(new TextBlock
            {
                Text = CrackTimeEstimator.FormatDuration(est.Seconds), FontWeight = FontWeights.Bold,
                Foreground = SeverityBrush(CrackTimeEstimator.Severity(est.Seconds)),
                HorizontalAlignment = HorizontalAlignment.Right, TextAlignment = TextAlignment.Right,
                TextWrapping = TextWrapping.Wrap
            });
            if (est.Seconds / (365.25 * 86400) > CrackTimeEstimator.UniverseAgeYears)
                time.Children.Add(new TextBlock
                {
                    Text = "longer than the universe exists", FontSize = 11, Foreground = Res("SubtleBrush"),
                    HorizontalAlignment = HorizontalAlignment.Right
                });
            AddCell(table, row, 2, time);
        }
        table.RowDefinitions.Insert(0, new RowDefinition { Height = GridLength.Auto });
        root.Children.Add(table);

        // ---- assumptions ----
        var note = new DockPanel { Margin = new Thickness(0, 16, 0, 0) };
        var info = new TextBlock
        {
            Text = "", FontFamily = iconFont, FontSize = 12, Foreground = Res("SubtleBrush"),
            Margin = new Thickness(0, 2, 8, 0), VerticalAlignment = VerticalAlignment.Top
        };
        DockPanel.SetDock(info, Dock.Left);
        note.Children.Add(info);
        note.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = Res("SubtleBrush"),
            Text = "Rough estimates. They assume the attacker knows exactly how Phrasia built the password (word list " +
                   "and settings) – the cautious case. Hardware gets faster every year, and a lucky guess can come " +
                   "earlier than the average. Reusing a password, phishing or malware make these numbers irrelevant. " +
                   "Your Phrasia vault is protected far better than the “slow hash” row: Argon2id tuned to your PC, a secret " +
                   "PIM and a device key that never leaves this computer."
        });
        root.Children.Add(note);

        var close = new Button
        {
            Content = "Close", IsDefault = true, IsCancel = true, MinWidth = 100, Margin = new Thickness(0, 18, 0, 0),
            HorizontalAlignment = HorizontalAlignment.Right,
            Style = (Style)Application.Current.Resources["PrimaryButton"]
        };
        root.Children.Add(close);

        Content = root;
    }

    /// <summary>Places an element into a grid cell.</summary>
    private static void AddCell(Grid grid, int row, int column, UIElement element)
    {
        Grid.SetRow(element, row);
        Grid.SetColumn(element, column);
        grid.Children.Add(element);
    }

    /// <summary>Red (under a day), orange (under a year), green (under 1000 years), dark green (longer).</summary>
    private static Brush SeverityBrush(int severity) => severity switch
    {
        0 => Res("Strength1Brush"),
        1 => Res("Strength2Brush"),
        2 => Res("Strength3Brush"),
        _ => Res("Strength4Brush")
    };


    private static Style Sec() => (Style)Application.Current.Resources["SectionLabel"];

    /// <summary>App brush by key.</summary>
    private static Brush Res(string key) => (Brush)Application.Current.Resources[key];
}
