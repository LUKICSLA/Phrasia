using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace Phrasia;

public partial class MainWindow : Window
{
    private static Brush DigitBrush  => ThemeManager.Brush("DigitBrush");  // digits – blue
    private static Brush SymbolBrush => ThemeManager.Brush("SymbolBrush"); // separators/symbols – pink-red
    private static Brush LetterBrush => ThemeManager.Brush("TextBrush");

    private readonly Dictionary<string, string[]> _wordCache = new();
    private string _current = "";
    private readonly DispatcherTimer _statusTimer = new() { Interval = TimeSpan.FromSeconds(2) };

    /// <summary>Initializes the window and its generator, privacy and vault subsystems.</summary>
    public MainWindow()
    {
        InitializeComponent();
        InitAbout();
        InitGeneratorPrivacy();
        InitVault();
        _statusTimer.Tick += (_, _) => { StatusText.Text = ""; _statusTimer.Stop(); };
        ThemeManager.Changed += OnThemeChanged;
        Closed += (_, _) => ThemeManager.Changed -= OnThemeChanged;
    }

    /// <summary>Re-applies colors that are set from code (password digits/symbols, strength, vault health).</summary>
    private void OnThemeChanged()
    {
        UpdateMainPasswordDisplay();
        if (_lastBits > 0)
        {
            var (_, _, brush) = Rate(_lastBits);
            EntropyBar.Foreground = brush;
            RatingText.Foreground = brush;
        }
        if (_vault is not null && !IsVaultBusy)
        {
            UpdateVaultHealth();
            UpdateEntryPasswordInfo();
        }
    }

    /// <summary>UI logger – NEVER write passwords, entry titles or usernames to it (see Logging.cs).</summary>
    private static readonly NLog.Logger Log = NLog.LogManager.GetLogger("Phrasia.UI");

    public const string AppName = "Phrasia";
    public const string GitHubUrl = "https://github.com/LUKICSLA";
    public const string Author = "Lukáš \"LUKI\" Maár";

    /// <summary>App version, read from the assembly (&lt;Version&gt; in .csproj) so it lives in one place.</summary>
    public static string AppVersion =>
        "v" + (typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "1.0.0");

    /// <summary>Fills in the title, author and version labels.</summary>
    private void InitAbout()
    {
        Title = $"{AppName} {AppVersion}";
        AuthorText.Text = $"{AppName}  ·  © {DateTime.Now.Year} {Author}";
        VersionText.Text = AppVersion;
        HeaderVersionText.Text = AppVersion;
    }

    public const string KoFiUrl = "https://ko-fi.com/lukicsla";

    /// <summary>Opens the GitHub page.</summary>
    private void GitHub_Click(object sender, RoutedEventArgs e) => OpenUrl(GitHubUrl);
    /// <summary>Opens the Ko-fi support page.</summary>
    private void KoFi_Click(object sender, RoutedEventArgs e) => OpenUrl(KoFiUrl);

    /// <summary>Opens the built-in decrypted log viewer.</summary>
    private void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            new LogViewerWindow(this).ShowDialog();
        }
        catch (Exception ex)
        {
            Log.Warn(ex, "Could not open the log viewer");
            AppMessageBox.Show(this, "Could not open the log viewer.", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    /// <summary>Opens the About window (version, GPL-3.0 notice, source link, third-party notices).</summary>
    private void OpenAbout_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            new AboutWindow(this, OpenUrl).ShowDialog();
        }
        catch (Exception ex)
        {
            Log.Warn(ex, "Could not open the About window");
            AppMessageBox.Show(this, "Could not open the About window.", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    /// <summary>Opens a hyperlink target in the default browser.</summary>
    private void GitHub_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        OpenUrl(e.Uri.AbsoluteUri);
        e.Handled = true;
    }

    /// <summary>Opens a URL in the default browser, showing a message on failure.</summary>
    private void OpenUrl(string url)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Log.Warn(ex, "Could not open a link");
            AppMessageBox.Show(this, $"Could not open the link:\n{url}", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    /// <summary>On load: populates word-list choices, restores last settings, and generates a first password.</summary>
    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        // automatically add all lists from the Wordlists folder next to the .exe
        var dir = System.IO.Path.Combine(AppContext.BaseDirectory, "Wordlists");
        ComboBoxItem? first = null;
        if (Directory.Exists(dir))
        {
            foreach (var file in Directory.EnumerateFiles(dir)
                         .Where(f => f.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                                  || f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                         .OrderBy(f => f))
            {
                var item = AddWordlistItem(file);
                first ??= item;
            }
        }

        Log.Info("Main window loaded");

        // the last settings (if any) take precedence over the automatic file choice
        bool restored = InitPresets();
        InitUpdateCheck();
        if (restored) return;

        if (first is not null)
            LangCombo.SelectedItem = first; // triggers Regenerate
        else
            Regenerate();
    }

    /// <summary>Adds (or reuses) a combo item for a word-list file path.</summary>
    private ComboBoxItem AddWordlistItem(string path)
    {
        var existing = LangCombo.Items.OfType<ComboBoxItem>()
            .FirstOrDefault(i => (i.Tag as string) == "path:" + path);
        if (existing is not null) return existing;

        var item = new ComboBoxItem
        {
            Content = "File: " + System.IO.Path.GetFileName(path),
            Tag = "path:" + path,
            ToolTip = path
        };
        LangCombo.Items.Add(item);
        return item;
    }

    // Shared handler for all sliders, combo boxes, text boxes and check boxes.
    /// <summary>Handles any generator option change: regenerates and persists the last settings.</summary>
    private void Option_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return; // during InitializeComponent not all controls exist yet
        if (_applyingPreset) return; // Recommended mode is changing settings – it regenerates once at the end
        if (sender != VariantsSlider) ClearPresetSelectionAfterManualChange();

        // in Recommended mode, changing the word list recomputes the word count
        if (sender == LangCombo && RecommendedCheck.IsChecked == true)
        {
            ApplyRecommended();
            return;
        }

        // keep min <= max for the word length
        if (sender == MinLenSlider && MinLenSlider.Value > MaxLenSlider.Value)
            MaxLenSlider.Value = MinLenSlider.Value;
        else if (sender == MaxLenSlider && MaxLenSlider.Value < MinLenSlider.Value)
            MinLenSlider.Value = MaxLenSlider.Value;

        Regenerate();
    }

    /// <summary>Regenerates the password on demand.</summary>
    private void Generate_Click(object sender, RoutedEventArgs e) => Regenerate();

    // ---------------- recommended mode ----------------

    /// <summary>Target password strength in Recommended mode (bits, conservative estimate).</summary>
    private const double RecommendedBits = 100;
    private const int RecommendedMinWords = 5;
    /// <summary>The largest word list (~226k words after filtering, ~17.8 bits per word).</summary>
    private const string RecommendedWordList = "all-large";
    private bool _applyingPreset;
    private SettingsSnapshot? _beforeRecommended;

    /// <summary>Snapshot of the user settings before Recommended mode was turned on – restored when it is turned off.</summary>
    private sealed record SettingsSnapshot(
        string Lang, string Case, string Separator, string Numbers,
        double Words, double Digits, double MinLen, double MaxLen, bool? Strip, bool? Unique,
        bool? Extra, string Symbols);

    /// <summary>Captures the current generator UI settings into a snapshot.</summary>
    private SettingsSnapshot TakeSnapshot() => new(
        SelTag(LangCombo), SelTag(CaseCombo), SelTag(SeparatorCombo), SelTag(NumbersCombo),
        WordsSlider.Value, DigitsSlider.Value, MinLenSlider.Value, MaxLenSlider.Value,
        NoDiacriticsCheck.IsChecked, UniqueCheck.IsChecked,
        ExtraRandomCheck.IsChecked, SymbolsBox.Text);

    /// <summary>Restores generator UI settings from a snapshot.</summary>
    private void RestoreSnapshot(SettingsSnapshot s)
    {
        _applyingPreset = true;
        try
        {
            SelectByTag(LangCombo, s.Lang);
            SelectByTag(CaseCombo, s.Case);
            SelectByTag(SeparatorCombo, s.Separator);
            SelectByTag(NumbersCombo, s.Numbers);
            MinLenSlider.Value = Math.Min(s.MinLen, MaxLenSlider.Maximum);
            MaxLenSlider.Value = s.MaxLen;
            MinLenSlider.Value = s.MinLen;
            WordsSlider.Value = s.Words;
            DigitsSlider.Value = s.Digits;
            NoDiacriticsCheck.IsChecked = s.Strip;
            UniqueCheck.IsChecked = s.Unique;
            ExtraRandomCheck.IsChecked = s.Extra;
            SymbolsBox.Text = s.Symbols;
        }
        finally
        {
            _applyingPreset = false;
        }
    }

    /// <summary>Toggles Recommended mode: applies strong locked settings, or restores the previous ones.</summary>
    private void Recommended_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        bool on = RecommendedCheck.IsChecked == true;

        foreach (var c in new FrameworkElement[]
                 {
                     LangCombo, LoadWordlistButton, WordsSlider, MinLenSlider, MaxLenSlider, DigitsSlider,
                     NoDiacriticsCheck, UniqueCheck, CaseCombo, SeparatorCombo, NumbersCombo,
                     CustomSeparatorBox, SymbolsBox, ExtraRandomCheck
                 })
            c.IsEnabled = !on;

        ClearPresetSelectionAfterManualChange();
        UpdatePresetButtons();

        Log.Info("Recommended mode {State}", on ? "on" : "off");

        if (on)
        {
            _beforeRecommended = TakeSnapshot();
            ApplyRecommended();
        }
        else
        {
            if (_beforeRecommended is not null) RestoreSnapshot(_beforeRecommended);
            _beforeRecommended = null;
            RecommendedHint.Text = RecommendedOffHint;
            Regenerate();
        }
    }

    /// <summary>Applies vetted safe options and picks the fewest words (at least 5) that reach the target bits for the chosen list.</summary>
    private void ApplyRecommended()
    {
        _applyingPreset = true;
        try
        {
            SelectByTag(LangCombo, RecommendedWordList);
            SelectByTag(CaseCombo, "random");
            SelectByTag(SeparatorCombo, "period");
            SelectByTag(NumbersCombo, "one");
            DigitsSlider.Value = 2;
            NoDiacriticsCheck.IsChecked = true;
            UniqueCheck.IsChecked = true;
            ExtraRandomCheck.IsChecked = true;
            SymbolsBox.Text = RecommendedSymbols;
            MinLenSlider.Value = 3;
            MaxLenSlider.Value = 10;

            int words = RecommendedMinWords;
            double bits = 0;
            for (; words <= (int)WordsSlider.Maximum; words++)
            {
                WordsSlider.Value = words;
                bits = TryEstimateBits();
                if (bits >= RecommendedBits) break;
            }
            words = Math.Min(words, (int)WordsSlider.Maximum);
            WordsSlider.Value = words;
            bits = TryEstimateBits();

            RecommendedHint.Text =
                $"On: SK + CZ + EN pool (~226,000 words) · {words} words · random case · extra randomness · 2 digits · ≈ {bits:F0} bits. " +
                "All settings are locked – turn it off to restore yours.";
        }
        finally
        {
            _applyingPreset = false;
        }
        Regenerate();
    }

    /// <summary>Symbols accepted by virtually every site and typable on SK/CZ/EN keyboards.</summary>
    private const string RecommendedSymbols = "!#$%*-_=+?";

    private const string RecommendedOffHint =
        "Strongest settings with one click: the largest word list, enough words for 100+ bits, everything locked.";

    /// <summary>Estimates the current configurations entropy in bits, or 0 on failure.</summary>
    private double TryEstimateBits()
    {
        try { return CreateGenerator().EstimateEntropyBits(); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException) { return 0; }
    }

    /// <summary>Selects the combo item whose Tag matches the given value.</summary>
    private static void SelectByTag(ComboBox combo, string tag)
    {
        var item = combo.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (i.Tag as string) == tag);
        if (item is not null) combo.SelectedItem = item;
    }

    /// <summary>Copies the current password to the clipboard.</summary>
    private void Copy_Click(object sender, RoutedEventArgs e) => CopyToClipboard(_current);

    /// <summary>Copies a variant password when its row is double-clicked.</summary>
    private void Variant_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (VariantsList.SelectedItem is VariantItem v && v.Value.Length > 0) CopyToClipboard(v.Value);
    }

    /// <summary>Lets the user pick a custom .txt/.zip word list and adds it to the choices.</summary>
    private void LoadWordlist_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Choose a word list",
            Filter = "Word lists (*.txt;*.zip)|*.txt;*.zip|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;

        LangCombo.SelectedItem = AddWordlistItem(dlg.FileName); // triggers Regenerate
    }

    // ---------------- main logic ----------------

    /// <summary>Builds options, generates the main password plus variants, and updates the UI.</summary>
    private void Regenerate()
    {
        string sep = SelTag(SeparatorCombo);
        bool extra = ExtraRandomCheck.IsChecked == true;
        bool locked = RecommendedCheck.IsChecked == true;
        SeparatorCombo.IsEnabled = !extra && !locked;   // with Extra randomness the generator picks the separator
        CustomSeparatorBox.Visibility = !extra && sep == "custom" ? Visibility.Visible : Visibility.Collapsed;
        SymbolsPanel.Visibility = extra || sep is "symbol" or "mixed" ? Visibility.Visible : Visibility.Collapsed;
        DigitsPanel.IsEnabled = SelTag(NumbersCombo) != "none";

        try
        {
            var gen = CreateGenerator();

            ShowGeneratedPasswords(gen.Generate(), gen.Generate((int)VariantsSlider.Value).ToList());

            double bits = gen.EstimateEntropyBits();
            var (label, quip, brush) = Rate(bits);
            EntropyBar.Value = Math.Min(bits, EntropyBar.Maximum);
            EntropyBar.Foreground = brush;
            RatingText.Text = label;
            RatingText.Foreground = brush;
            RatingQuipText.Text = quip;
            _lastBits = bits;
            var worst = CrackTimeEstimator.WorstCase;
            CrackTimeText.Text = "Worst case (GPU farm, fast hash): ≈ " +
                CrackTimeEstimator.FormatDuration(CrackTimeEstimator.AverageSeconds(bits, worst.GuessesPerSecond)) + " on average";
            CrackTimeButton.IsEnabled = true;
            EntropyText.Text = gen.IsMultiList
                ? $"Entropy ≈ {bits:F0} bits (conservative)  ·  every language in each password"
                : $"Entropy ≈ {bits:F0} bits  ·  list: {gen.WordListSize:N0} words";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
                                      or IOException or UnauthorizedAccessException)
        {
            Log.Warn("Generator could not create a password: {Reason}", ex.Message);
            _current = "";
            ForgetVariants();
            PasswordText.Inlines.Clear();
            VariantsList.ItemsSource = null;
            EntropyBar.Value = 0;
            RatingText.Text = "";
            RatingQuipText.Text = "";
            _lastBits = 0;
            CrackTimeText.Text = "";
            CrackTimeButton.IsEnabled = false;
            EntropyText.Text = "⚠ " + ex.Message;
        }
    }

    /// <summary>Translates the UI controls into a GeneratorOptions instance.</summary>
    private GeneratorOptions BuildOptions()
    {
        var o = new GeneratorOptions
        {
            WordCount     = (int)WordsSlider.Value,
            DigitCount    = (int)DigitsSlider.Value,
            MinWordLength = (int)MinLenSlider.Value,
            MaxWordLength = (int)MaxLenSlider.Value,
            UniqueWords   = UniqueCheck.IsChecked == true,
            SymbolSet     = SymbolsBox.Text,

            Case = SelTag(CaseCombo) switch
            {
                "lower"      => CaseMode.Lower,
                "upper"      => CaseMode.Upper,
                "capitalize" => CaseMode.Capitalize,
                "alternate"  => CaseMode.Alternate,
                _            => CaseMode.Random
            },

            Numbers = SelTag(NumbersCombo) switch
            {
                "none" => NumberMode.None,
                "each" => NumberMode.EachWord,
                "end"  => NumberMode.End,
                _      => NumberMode.OneWord
            }
        };

        (o.SeparatorMode, o.Separator) = SelTag(SeparatorCombo) switch
        {
            "hyphen"     => (SeparatorMode.Fixed, "-"),
            "underscore" => (SeparatorMode.Fixed, "_"),
            "comma"      => (SeparatorMode.Fixed, ","),
            "space"      => (SeparatorMode.Fixed, " "),
            "none"       => (SeparatorMode.Fixed, ""),
            "digit"      => (SeparatorMode.RandomDigit, ""),
            "symbol"     => (SeparatorMode.RandomSymbol, ""),
            "mixed"      => (SeparatorMode.RandomDigitOrSymbol, ""),
            "custom"     => (SeparatorMode.Fixed, CustomSeparatorBox.Text),
            _            => (SeparatorMode.Fixed, ".")
        };

        // Extra randomness: a random symbol in each gap (no digits – so they don't mix with numbers),
        // a number on a random side of the word, and one random character inserted into a word
        if (ExtraRandomCheck.IsChecked == true)
        {
            o.SeparatorMode = SeparatorMode.RandomSymbol;
            o.NumberRandomSide = true;
            o.InsertRandomChar = true;
        }

        return o;
    }

    /// <summary>Language combos where the passphrase must contain a word from each list.</summary>
    private static readonly Dictionary<string, string[]> EachLanguageModes = new()
    {
        ["each-sk-cs-en"] = new[] { "sk-large", "cs-all", "en-large" }
    };

    /// <summary>Creates a generator from the current settings (single list, or "one word per language").</summary>
    private PassphraseGenerator CreateGenerator()
    {
        string tag = SelTag(LangCombo);
        if (EachLanguageModes.TryGetValue(tag, out var parts))
            return new PassphraseGenerator(parts.Select(GetWordsFor).ToArray(), BuildOptions());
        return new PassphraseGenerator(GetWordsFor(tag), BuildOptions());
    }

    private IEnumerable<string> GetWords() => GetWordsFor(SelTag(LangCombo));

    /// <summary>Returns the word list for a language tag (cached), loading embedded lists as needed.</summary>
    private string[] GetWordsFor(string tag)
    {
        bool strip = NoDiacriticsCheck.IsChecked == true;
        string key = tag + "|" + strip;
        if (_wordCache.TryGetValue(key, out var cached)) return cached;

        IEnumerable<string> words = tag switch
        {
            "en" => WordLists.English,
            "sk" => WordLists.Slovak,
            "sk-large" => WordLists.SlovakLarge,
            "en-large" => WordLists.EnglishLarge,
            "mix-large" => WordLists.SlovakLarge.Concat(WordLists.EnglishLarge),
            "cs-common" => WordLists.CzechCommon,
            "cs-all" => WordLists.CzechAll,
            "all-large" => WordLists.SlovakLarge.Concat(WordLists.CzechAll).Concat(WordLists.EnglishLarge),
            _ when tag.StartsWith("path:") => WordLists.LoadFromFile(tag["path:".Length..]),
            _ => WordLists.English.Concat(WordLists.Slovak)
        };
        if (strip) words = words.Select(WordLists.RemoveDiacritics);

        var result = words.ToArray();
        _wordCache[key] = result;
        if (tag.StartsWith("path:"))
            Log.Info("Custom word list loaded: {File}, {Count} lines", System.IO.Path.GetFileName(tag["path:".Length..]), result.Length);
        WordlistLabel.Text = tag.StartsWith("path:") ? $"{result.Length:N0} lines loaded" : ".txt or .zip";
        return result;
    }

    /// <summary>Renders the password with letters, digits and symbols colored (Proton-Pass style).</summary>
    /// <summary>Renders the given password string into the colored display.</summary>
    private void RenderPassword(string pwd)
    {
        PasswordText.Inlines.Clear();
        int i = 0;
        while (i < pwd.Length)
        {
            int kind = Kind(pwd[i]);
            int start = i;
            while (i < pwd.Length && Kind(pwd[i]) == kind) i++;

            PasswordText.Inlines.Add(new Run(pwd[start..i])
            {
                Foreground = kind switch { 0 => LetterBrush, 1 => DigitBrush, _ => SymbolBrush }
            });
        }

        static int Kind(char c) => char.IsLetter(c) ? 0 : char.IsDigit(c) ? 1 : 2;
    }

    /// <summary>Copies text to the clipboard, excluding it from clipboard history, and schedules a clear.</summary>
    private void CopyToClipboard(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        ShowStatus(CopySecure(text)
            ? $"Copied ✓ (cleared from clipboard in {ClipboardClearSeconds} s)"
            : "Clipboard is busy, please try again");
    }

    /// <summary>Shows a transient status message that auto-clears.</summary>
    private void ShowStatus(string msg)
    {
        StatusText.Text = msg;
        _statusTimer.Stop();
        _statusTimer.Start();
    }

    /// <summary>Strength (bits) of the currently shown password settings – used by the crack-time dialog.</summary>
    private double _lastBits;

    /// <summary>Opens the crack-time breakdown for the current settings.</summary>
    private void CrackTime_Click(object sender, RoutedEventArgs e)
    {
        if (_lastBits <= 0) return;
        new CrackTimeDialog(this, _lastBits).ShowDialog();
    }

    private static string SelTag(ComboBox cb) => (cb.SelectedItem as ComboBoxItem)?.Tag as string ?? "";

    /// <summary>Strength tier: a short label, a witty (but accurate) quip and a (theme) color. Times assume an offline attack of ~10^12 guesses/s against a fast hash (worst case).</summary>
    private static (string Label, string Quip, Brush Color) Rate(double bits) => bits switch
    {
        < 28  => ("Paper lock",    "Cracked before you finish typing it. Add more words!",                     ThemeManager.Brush("Strength0Brush")),
        < 40  => ("Hacker snack",  "A GPU chews through this in under a second. Crunchy.",                     ThemeManager.Brush("Strength1Brush")),
        < 60  => ("Sibling-proof", "Keeps your little brother out. A cracking rig needs days at most.",            ThemeManager.Brush("Strength2Brush")),
        < 80  => ("Strong",        "Good for everyday accounts. Offline cracking: weeks to millennia.",       ThemeManager.Brush("Strength3Brush")),
        < 100 => ("Fort Knox",     "Very strong. Even a GPU farm would need tens of thousands of years or more.", ThemeManager.Brush("Strength4Brush")),
        _     => ("Cosmic",        "The Sun burns out before anyone cracks this. Overkill – in the best way.", ThemeManager.Brush("Strength5Brush"))
    };

}
