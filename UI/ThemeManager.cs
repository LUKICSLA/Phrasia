using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

namespace Phrasia;

/// <summary>Color theme choice: follow Windows, or always light / dark.</summary>
internal enum ThemeMode { System, Light, Dark }

/// <summary>
/// Light / dark theme. All colors are application resources (looked up with DynamicResource), so switching replaces
/// the brushes in <see cref="Application.Resources"/> and every open window updates immediately. In "System" mode the
/// app follows the Windows setting "Choose your app mode" and reacts when it changes. Title bars are switched to dark
/// through DWM (Windows 10 2004+ / Windows 11).
/// </summary>
internal static class ThemeManager
{
    /// <summary>Every themed brush: key → (light, dark).</summary>
    private static readonly (string Key, string Light, string Dark)[] Palette =
    [
        ("AccentBrush",          "#6D4AFF", "#8B70FF"),
        ("AccentDarkBrush",      "#4B2FD6", "#C4B5FF"),
        ("AccentSoftBrush",      "#F1EDFF", "#2B2445"),
        ("AccentHoverBrush",     "#E6DFFF", "#372D5E"),
        ("AccentLineBrush",      "#E0D8FF", "#3A3162"),
        ("WindowBrush",          "#F5F6FA", "#121219"),
        ("SurfaceBrush",         "#FFFFFF", "#1C1C26"),
        ("LineBrush",            "#E4E6EE", "#2F2F3D"),
        ("LineHoverBrush",       "#C4B6FF", "#5B4AA8"),
        ("TextBrush",            "#1E1F2B", "#E7E7EF"),
        ("MutedBrush",           "#6B7080", "#A4A8B8"),
        ("SubtleBrush",          "#9A9EAD", "#767A8C"),
        ("PrivacyBrush",         "#EAF8F0", "#12281C"),
        ("PrivacyLineBrush",     "#BFE6D0", "#1E4A32"),
        ("PrivacyTextBrush",     "#176B45", "#7ED8A6"),
        ("PrivacyIconBrush",     "#1E9E63", "#3DC985"),
        ("ToggleTrackBrush",     "#D9DBE4", "#3A3A4B"),
        ("ToggleTrackHoverBrush","#C9CBD6", "#4A4A5E"),
        ("KnobBrush",            "#FFFFFF", "#F2F2F7"),
        ("SliderTrackBrush",     "#E4E2F0", "#2F2F3D"),
        ("ListHoverBrush",       "#F6F4FF", "#24203A"),
        ("ProgressTrackBrush",   "#ECEDF3", "#2A2A36"),
        ("TabStripBrush",        "#EAE8F4", "#20202B"),
        ("TabTextBrush",         "#5A5F70", "#A4A8B8"),
        ("TabSelectedBrush",     "#FFFFFF", "#2F2A4A"),
        ("ToolTipBrush",         "#1E1F2B", "#2F2F3D"),
        ("ScrollThumbBrush",     "#C9CBD6", "#3E3E50"),
        ("ScrollThumbHoverBrush","#A9ACBA", "#56566C"),
        ("PasswordBgBrush",      "#FAF9FF", "#191624"),
        ("PasswordLineBrush",    "#E4DEFF", "#3A3162"),
        ("DangerBrush",          "#C62828", "#FF7070"),
        ("DangerStrongBrush",    "#E53935", "#E53935"),
        ("DangerSoftBrush",      "#FDECEC", "#3B1E22"),
        ("DangerLineBrush",      "#F3C7C7", "#5C2B30"),
        ("WarningBrush",         "#E65100", "#FFA24D"),
        ("WarningSoftBrush",     "#FFF1E0", "#3A2914"),
        ("CautionBrush",         "#9A6A00", "#E5BE55"),
        ("CautionSoftBrush",     "#FFF8DC", "#33301A"),
        ("SuccessBrush",         "#2E7D32", "#6FCF7F"),
        ("Strength0Brush",       "#B71C1C", "#FF6B6B"),
        ("Strength1Brush",       "#D32F2F", "#FF8A80"),
        ("Strength2Brush",       "#F57C00", "#FFB74D"),
        ("Strength3Brush",       "#388E3C", "#81C784"),
        ("Strength4Brush",       "#1B5E20", "#4CC26B"),
        ("Strength5Brush",       "#6D4AFF", "#A08BFF"),
        ("DigitBrush",           "#2563EB", "#6EA8FF"),
        ("SymbolBrush",          "#E11D48", "#FF6B8A")
    ];

    /// <summary>The chosen mode (System follows Windows).</summary>
    public static ThemeMode Mode { get; private set; } = ThemeMode.System;

    /// <summary>True when the dark palette is active.</summary>
    public static bool IsDark { get; private set; }

    /// <summary>Raised after the palette changed, for colors set from code.</summary>
    public static event Action? Changed;

    private static bool _hooked;

    /// <summary>Parses the stored setting ("system", "light", "dark").</summary>
    public static ThemeMode Parse(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "light" => ThemeMode.Light,
        "dark" => ThemeMode.Dark,
        _ => ThemeMode.System
    };

    /// <summary>The value stored in the settings file.</summary>
    public static string ToSetting(ThemeMode mode) => mode.ToString().ToLowerInvariant();

    /// <summary>Themed brush by key (falls back to the light palette value if the key is missing).</summary>
    public static Brush Brush(string key) =>
        Application.Current?.Resources[key] as Brush ?? Create(Palette.First(p => p.Key == key).Light);

    /// <summary>Applies a mode: replaces the brushes, switches title bars, notifies listeners.</summary>
    public static void Apply(ThemeMode mode)
    {
        Mode = mode;
        bool dark = mode == ThemeMode.Dark || (mode == ThemeMode.System && WindowsUsesDarkApps());
        var resources = Application.Current.Resources;
        foreach (var (key, light, darkColor) in Palette)
            resources[key] = Create(dark ? darkColor : light);
        IsDark = dark;
        MapSystemColors(resources);

        if (!_hooked)
        {
            _hooked = true;
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent,
                new RoutedEventHandler((sender, _) =>
                {
                    var window = (Window)sender;
                    // every window (also dialogs built in code) follows the theme, even after a switch
                    window.SetResourceReference(Window.BackgroundProperty, "WindowBrush");
                    window.SetResourceReference(Control.ForegroundProperty, "TextBrush");
                    ApplyTitleBar(window);
                }));
        }
        foreach (Window window in Application.Current.Windows) ApplyTitleBar(window);
        Changed?.Invoke();
    }

    /// <summary>
    /// WPF's built-in control styles (TabControl, ListBox, Label, menus, hyperlinks…) take their colors from the
    /// SystemColors keys, not from inherited values – which is why some text stayed black in dark mode. Redirecting
    /// those keys to the theme makes every control follow it, including ones without a custom style.
    /// </summary>
    private static void MapSystemColors(ResourceDictionary r)
    {
        var text = (Brush)r["TextBrush"];
        var surface = (Brush)r["SurfaceBrush"];
        r[SystemColors.ControlTextBrushKey] = text;
        r[SystemColors.WindowTextBrushKey] = text;
        r[SystemColors.MenuTextBrushKey] = text;
        r[SystemColors.InfoTextBrushKey] = text;
        r[SystemColors.HighlightTextBrushKey] = Create("#FFFFFF");
        r[SystemColors.InactiveSelectionHighlightTextBrushKey] = text;
        r[SystemColors.GrayTextBrushKey] = (Brush)r["SubtleBrush"];
        r[SystemColors.HotTrackBrushKey] = (Brush)r["AccentBrush"];   // default hyperlink color
        r[SystemColors.HighlightBrushKey] = (Brush)r["AccentBrush"];
        r[SystemColors.InactiveSelectionHighlightBrushKey] = (Brush)r["AccentSoftBrush"];
        r[SystemColors.WindowBrushKey] = surface;
        r[SystemColors.ControlBrushKey] = surface;
        r[SystemColors.MenuBrushKey] = surface;
        r[SystemColors.InfoBrushKey] = (Brush)r["ToolTipBrush"];
        r[SystemColors.ControlLightBrushKey] = (Brush)r["LineBrush"];
        r[SystemColors.ControlDarkBrushKey] = (Brush)r["LineHoverBrush"];
    }

    /// <summary>Windows "Choose your app mode": AppsUseLightTheme = 0 means dark.</summary>
    private static bool WindowsUsesDarkApps()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
            return false;
        }
    }

    /// <summary>In System mode, follows a change of the Windows app mode.</summary>
    private static void OnUserPreferenceChanged(object? sender, UserPreferenceChangedEventArgs e)
    {
        if (Mode != ThemeMode.System || e.Category is not (UserPreferenceCategory.General or UserPreferenceCategory.Color)) return;
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            if (Mode == ThemeMode.System && WindowsUsesDarkApps() != IsDark) Apply(ThemeMode.System);
        });
    }

    /// <summary>Dark or light title bar (DWMWA_USE_IMMERSIVE_DARK_MODE; attribute 19 on early Windows 10 builds).</summary>
    private static void ApplyTitleBar(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;
        int on = IsDark ? 1 : 0;
        if (DwmSetWindowAttribute(hwnd, 20, ref on, sizeof(int)) != 0)
            DwmSetWindowAttribute(hwnd, 19, ref on, sizeof(int));
    }

    /// <summary>Frozen brush from a #RRGGBB string.</summary>
    private static SolidColorBrush Create(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
