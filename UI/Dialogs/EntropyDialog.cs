using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace Phrasia;

/// <summary>
/// VeraCrypt-style "move the mouse" dialog: collects user entropy into <see cref="EntropyPool"/> before a critical
/// operation (new vault, master-password change, re-tuning, device-key export, suggested master password).
/// The pad draws a fading trail of the pointer; a gradient bar shows progress towards <see cref="EntropyPool.TargetBits"/>.
/// The movement is mixed with the Windows random generator – it never replaces it. Pool content is never displayed.
/// </summary>
internal sealed class EntropyDialog : Window
{
    private const int TrailLength = 90;            // line segments kept in the trail
    private const double PadHeight = 210;

    private readonly Canvas _pad = new() { ClipToBounds = true, Background = Brushes.Transparent, Cursor = Cursors.Cross };
    private readonly Queue<Line> _trail = new();
    private readonly FrameworkElement _hint;
    private readonly ScaleTransform _fillScale = new(0, 1);
    private readonly TextBlock _percent = new() { FontSize = 26, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _stats = new() { FontSize = 12 };
    private readonly TextBlock _doneIcon = new() { Text = "", Visibility = Visibility.Collapsed, Margin = new Thickness(0, 0, 6, 0) };
    private readonly Button _continue;
    private readonly Brush _accent, _done;
    private Point? _last;
    private int _samples;
    private bool _hintHidden, _completed;

    /// <summary>Makes sure fresh user entropy has been collected; shows the dialog only when it has not. Returns false if the user cancelled.</summary>
    public static bool EnsureFresh(Window owner, string purpose)
    {
        if (EntropyPool.IsFresh) return true;
        return new EntropyDialog(owner, purpose).ShowDialog() == true;
    }

    /// <summary>Builds the dialog: header, drawing pad with trail, progress, statistics, privacy note and buttons.</summary>
    private EntropyDialog(Window owner, string purpose)
    {
        Owner = owner;
        Title = "Generate randomness";
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = Res("WindowBrush");
        Foreground = Res("TextBrush");
        _accent = Res("AccentBrush");
        _done = Res("PrivacyIconBrush");
        var iconFont = (FontFamily)Application.Current.Resources["IconFont"];
        _doneIcon.FontFamily = iconFont;
        _doneIcon.Foreground = _done;

        var root = new StackPanel { Margin = new Thickness(24, 22, 24, 20), Width = 500 };

        // ---- header: gradient badge + title + purpose ----
        var header = new DockPanel();
        var badge = new Border
        {
            Width = 44, Height = 44, CornerRadius = new CornerRadius(12), Background = Res("HeroBrush"),
            Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Top,
            Child = new TextBlock
            {
                Text = "", FontFamily = iconFont, FontSize = 20, Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center
            }
        };
        DockPanel.SetDock(badge, Dock.Left);
        header.Children.Add(badge);
        var titles = new StackPanel();
        titles.Children.Add(new TextBlock { Text = "Generate randomness", FontSize = 17, FontWeight = FontWeights.SemiBold });
        titles.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0), Foreground = Res("MutedBrush"),
            Text = $"Your mouse movement is mixed with the Windows random generator to create {purpose}."
        });
        header.Children.Add(titles);
        root.Children.Add(header);

        // ---- drawing pad: dotted surface, fading trail, pulsing hint ----
        _hint = BuildHint(iconFont);
        var padGrid = new Grid();
        padGrid.Children.Add(_pad);
        padGrid.Children.Add(_hint);
        root.Children.Add(new Border
        {
            Height = PadHeight, Margin = new Thickness(0, 18, 0, 0), CornerRadius = new CornerRadius(12),
            BorderThickness = new Thickness(1), BorderBrush = Res("LineBrush"), Background = Res("SurfaceBrush"),
            Child = new Border { CornerRadius = new CornerRadius(11), Background = DotGrid(), Child = padGrid }
        });

        // ---- progress: percent + gradient bar ----
        var progressRow = new DockPanel { Margin = new Thickness(0, 16, 0, 0) };
        _percent.Margin = new Thickness(14, 0, 0, 0);
        _percent.MinWidth = 64;
        _percent.TextAlignment = TextAlignment.Right;
        DockPanel.SetDock(_percent, Dock.Right);
        progressRow.Children.Add(_percent);
        var fill = new Border
        {
            CornerRadius = new CornerRadius(5), Background = Res("HeroBrush"),
            RenderTransform = _fillScale, RenderTransformOrigin = new Point(0, 0.5)
        };
        progressRow.Children.Add(new Border
        {
            Height = 10, CornerRadius = new CornerRadius(5), Background = Res("LineBrush"),
            VerticalAlignment = VerticalAlignment.Center, ClipToBounds = true, Child = fill
        });
        root.Children.Add(progressRow);

        var statsRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };
        statsRow.Children.Add(_doneIcon);
        statsRow.Children.Add(_stats);
        root.Children.Add(statsRow);

        // ---- privacy note ----
        var note = new DockPanel { Margin = new Thickness(0, 14, 0, 0) };
        var lockIcon = new TextBlock
        {
            Text = "", FontFamily = iconFont, FontSize = 12, Foreground = Res("SubtleBrush"),
            Margin = new Thickness(0, 2, 8, 0), VerticalAlignment = VerticalAlignment.Top
        };
        DockPanel.SetDock(lockIcon, Dock.Left);
        note.Children.Add(lockIcon);
        note.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = Res("SubtleBrush"),
            Text = "Only position and precise timing are used, mixed into memory and never stored or sent. " +
                   "It adds to the Windows generator – it never replaces it."
        });
        root.Children.Add(note);

        // ---- buttons ----
        _continue = new Button
        {
            Content = "Continue", IsDefault = true, IsEnabled = false, MinWidth = 110, Margin = new Thickness(0, 18, 8, 0),
            Style = (Style)Application.Current.Resources["PrimaryButton"]
        };
        _continue.Click += (_, _) => DialogResult = true;
        var cancel = new Button
        {
            Content = "Cancel", IsCancel = true, MinWidth = 90, Margin = new Thickness(0, 18, 0, 0),
            Style = (Style)Application.Current.Resources["GhostButton"]
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(_continue);
        buttons.Children.Add(cancel);
        root.Children.Add(buttons);

        Content = root;
        PreviewMouseMove += OnMouseMove;
        _pad.MouseLeave += (_, _) => _last = null; // no long jump line when re-entering the pad
        Update(animate: false);
    }

    /// <summary>Centered hint over the pad: pulsing mouse icon and instructions; fades out on the first movement.</summary>
    private FrameworkElement BuildHint(FontFamily iconFont)
    {
        var icon = new TextBlock
        {
            Text = "", FontFamily = iconFont, FontSize = 30, Foreground = _accent,
            HorizontalAlignment = HorizontalAlignment.Center
        };
        icon.BeginAnimation(OpacityProperty, new DoubleAnimation(0.35, 1, TimeSpan.FromSeconds(0.9))
        {
            AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        });
        var panel = new StackPanel
        {
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false
        };
        panel.Children.Add(icon);
        panel.Children.Add(new TextBlock
        {
            Text = "Move the mouse around inside this area", FontSize = 14, FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 10, 0, 0), HorizontalAlignment = HorizontalAlignment.Center
        });
        panel.Children.Add(new TextBlock
        {
            Text = "Draw large, irregular loops and zig-zags – avoid straight lines.",
            Foreground = Res("MutedBrush"), Margin = new Thickness(0, 4, 0, 0), HorizontalAlignment = HorizontalAlignment.Center
        });
        return panel;
    }

    /// <summary>Feeds the pointer position (screen pixels) into the pool, extends the trail and refreshes the progress.</summary>
    private void OnMouseMove(object sender, MouseEventArgs e)
    {
        var screen = PointToScreen(e.GetPosition(this));
        EntropyPool.AddMouseSample((long)Math.Round(screen.X), (long)Math.Round(screen.Y));
        _samples++;

        var p = e.GetPosition(_pad);
        bool inside = p.X >= 0 && p.Y >= 0 && p.X <= _pad.ActualWidth && p.Y <= _pad.ActualHeight;
        if (inside)
        {
            if (!_hintHidden)
            {
                _hintHidden = true;
                _hint.BeginAnimation(OpacityProperty, new DoubleAnimation(0, TimeSpan.FromMilliseconds(350)));
            }
            if (_last is { } last && (last - p).Length >= 1) AddSegment(last, p);
            _last = p;
        }
        else _last = null;
        Update(animate: true);
    }

    /// <summary>Adds one trail segment; older segments fade out and get thinner, the oldest is removed.</summary>
    private void AddSegment(Point from, Point to)
    {
        var line = new Line
        {
            X1 = from.X, Y1 = from.Y, X2 = to.X, Y2 = to.Y,
            Stroke = _completed ? _done : _accent,
            StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round,
            IsHitTestVisible = false
        };
        _pad.Children.Add(line);
        _trail.Enqueue(line);
        if (_trail.Count > TrailLength) _pad.Children.Remove(_trail.Dequeue());

        int i = 0, n = _trail.Count;
        foreach (var seg in _trail)
        {
            double age = (double)++i / n;            // 0 = oldest, 1 = newest
            seg.Opacity = age * age;
            seg.StrokeThickness = 1 + 3.5 * age;
        }
    }

    /// <summary>Updates the bar, percentage and statistics; enables Continue once enough entropy is collected.</summary>
    private void Update(bool animate)
    {
        int bits = EntropyPool.CreditedBits;
        double fraction = (double)bits / EntropyPool.TargetBits;
        bool done = bits >= EntropyPool.TargetBits;

        if (animate)
            _fillScale.BeginAnimation(ScaleTransform.ScaleXProperty,
                new DoubleAnimation(fraction, TimeSpan.FromMilliseconds(140)) { EasingFunction = new QuadraticEase() });
        else
            _fillScale.ScaleX = fraction;

        _percent.Text = $"{(int)(fraction * 100)} %";
        _percent.Foreground = done ? _done : Res("TextBrush");
        _stats.Text = done
            ? $"Enough randomness collected – {EntropyPool.TargetBits} bits from {_samples} samples"
            : $"{bits} / {EntropyPool.TargetBits} bits  ·  {_samples} samples  ·  keep moving";
        _stats.Foreground = done ? Res("PrivacyTextBrush") : Res("MutedBrush");
        _doneIcon.Visibility = done ? Visibility.Visible : Visibility.Collapsed;
        _continue.IsEnabled = done;

        if (done && !_completed)
        {
            _completed = true;
            foreach (var seg in _trail) seg.Stroke = _done;
            _continue.Focus();
        }
    }

    /// <summary>Subtle dotted background for the pad.</summary>
    private static Brush DotGrid()
    {
        var dot = new GeometryDrawing(Res("LineBrush"), null, new EllipseGeometry(new Point(2, 2), 1.2, 1.2));
        return new DrawingBrush(dot)
        {
            TileMode = TileMode.Tile, Stretch = Stretch.None,
            Viewport = new Rect(0, 0, 18, 18), ViewportUnits = BrushMappingMode.Absolute,
            Viewbox = new Rect(0, 0, 18, 18), ViewboxUnits = BrushMappingMode.Absolute
        };
    }

    /// <summary>App brush by key.</summary>
    private static Brush Res(string key) => (Brush)Application.Current.Resources[key];
}
