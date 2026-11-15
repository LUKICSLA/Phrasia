using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

namespace Phrasia;

/// <summary>
/// "About &amp; licenses" window: copyright, the GPL-3.0 notice (no warranty), where to get the source code,
/// and the full texts of the GPL and of all third-party notices. The texts are embedded in the .exe,
/// so they ship with the single-file build.
/// </summary>
internal sealed class AboutWindow : Window
{
    /// <summary>Where the source code is published (GPL-3.0 requires telling users where to get it).</summary>
    internal const string SourceUrl = "https://github.com/LUKICSLA";

    /// <summary>Builds the window: notice header, tabs with the license texts and a Close button.</summary>
    public AboutWindow(Window owner, Action<string> openUrl)
    {
        Owner = owner;
        Title = "About Phrasia";
        Width = 760;
        Height = 620;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = owner.FontFamily;
        FontSize = 13;
        Background = (Brush)owner.FindResource("WindowBrush");
        Foreground = (Brush)owner.FindResource("TextBrush");

        var root = new DockPanel { Margin = new Thickness(16) };

        var header = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
        header.Children.Add(new TextBlock
        {
            Text = $"{MainWindow.AppName} {MainWindow.AppVersion}",
            FontSize = 18,
            FontWeight = FontWeights.Bold
        });
        header.Children.Add(new TextBlock
        {
            Text = "Offline passphrase generator and encrypted password vault",
            Opacity = 0.8,
            Margin = new Thickness(0, 2, 0, 10)
        });
        header.Children.Add(new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Text = "Copyright (C) 2026 Lukáš \"LUKI\" Maár\n\n" +
                   "This program is free software: you can redistribute it and/or modify it under the terms of " +
                   "the GNU General Public License, version 3, as published by the Free Software Foundation.\n" +
                   "This program comes with ABSOLUTELY NO WARRANTY; see the license below for details."
        });
        var source = new TextBlock { Margin = new Thickness(0, 8, 0, 0) };
        source.Inlines.Add("Source code: ");
        var link = new Hyperlink(new Run(SourceUrl));
        link.Click += (_, _) => openUrl(SourceUrl);
        source.Inlines.Add(link);
        header.Children.Add(source);
        DockPanel.SetDock(header, Dock.Top);
        root.Children.Add(header);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 10, 0, 0)
        };
        DockPanel.SetDock(buttons, Dock.Bottom);
        var close = new Button { Content = "Close", IsCancel = true, IsDefault = true, MinWidth = 90, Style = (Style)Application.Current.Resources["GhostButton"] };
        close.Click += (_, _) => Close();
        buttons.Children.Add(close);
        root.Children.Add(buttons);

        var tabs = new TabControl();
        tabs.Items.Add(new TabItem { Header = "License (GPL-3.0)", Content = TextView(owner, LoadText("Phrasia.LICENSE")) });
        tabs.Items.Add(new TabItem { Header = "Third-party notices", Content = TextView(owner, LoadText("Phrasia.THIRD-PARTY-NOTICES")) });
        root.Children.Add(tabs);

        Content = root;
    }

    /// <summary>Reads an embedded UTF-8 text resource; returns a short note if it is missing.</summary>
    private static string LoadText(string resourceName)
    {
        using var stream = typeof(AboutWindow).Assembly.GetManifestResourceStream(resourceName);
        if (stream is null) return $"(embedded resource '{resourceName}' was not found)";
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>Read-only, scrollable monospace view of a license text, styled like the log viewer.</summary>
    private static TextBox TextView(Window owner, string text) => new()
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
}
