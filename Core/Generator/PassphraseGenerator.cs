using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Phrasia;

/// <summary>How upper/lower case is applied to words.</summary>
public enum CaseMode
{
    Lower,       // macka
    Upper,       // MACKA
    Capitalize,  // Macka
    Random,      // random per word: macka / MACKA / Macka
    Alternate    // striedavo: macka.PES.macka.PES
}

/// <summary>Type of separator placed between words.</summary>
public enum SeparatorMode
{
    Fixed,          // fixed string (e.g. ".", "-", " ", "" ...)
    RandomDigit,    // a random digit between each two words (Proton: "Numbers")
    RandomSymbol,   // a random symbol from SymbolSet
    RandomDigitOrSymbol // Proton: "Numbers and symbols"
}

/// <summary>Where digits are added.</summary>
public enum NumberMode
{
    None,       // no numbers
    OneWord,    // digits after one random word (Proton style)
    EachWord,   // digits after every word
    End         // digits at the very end of the password
}

/// <summary>Configurable options for the passphrase generator (word count, case, separators, numbers, extra randomness).</summary>
public sealed class GeneratorOptions
{
    public int WordCount { get; set; } = 4;
    public CaseMode Case { get; set; } = CaseMode.Random;

    public SeparatorMode SeparatorMode { get; set; } = SeparatorMode.Fixed;
    public string Separator { get; set; } = ".";
    public string SymbolSet { get; set; } = "!@#$%^&*-_=+?";

    public NumberMode Numbers { get; set; } = NumberMode.OneWord;
    public int DigitCount { get; set; } = 2;

    /// <summary>Optional source of uniform random integers in [0, n); null = the OS CSPRNG. Used to mix user entropy (mouse) into suggested master passwords.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public Func<int, int>? RandomSource { get; set; }

    public int MinWordLength { get; set; } = 3;
    public int MaxWordLength { get; set; } = 10;

    /// <summary>Prevents the same word repeating within one passphrase.</summary>
    public bool UniqueWords { get; set; } = true;

    /// <summary>Places the number randomly before or after the word (+1 bit per number).</summary>
    public bool NumberRandomSide { get; set; }

    /// <summary>Inserts one random digit or symbol at a random inner position of a random word.</summary>
    public bool InsertRandomChar { get; set; }
}

/// <summary>Generates Proton-Pass-style passphrases from word lists using a CSPRNG (no modulo bias).</summary>
public sealed class PassphraseGenerator
{
    /// <summary>Uniform random integer in [0, n) from the configured source, or the OS CSPRNG.</summary>
    private int Rand(int toExclusive) =>
        _o.RandomSource is { } source ? source(toExclusive) : RandomNumberGenerator.GetInt32(toExclusive);

    private readonly GeneratorOptions _o;
    private readonly string[] _words;          // all words (the union when there are multiple lists)
    private readonly string[][]? _pools;       // "at least one word from each list" mode

    /// <summary>Builds a single-list generator, filtering the words to the configured length range.</summary>
    public PassphraseGenerator(IEnumerable<string> wordList, GeneratorOptions options)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        Validate(_o);

        _words = GetFiltered(wordList, _o.MinWordLength, _o.MaxWordLength);

        if (_words.Length < 2)
            throw new InvalidOperationException(
                $"After filtering (length {_o.MinWordLength}–{_o.MaxWordLength}) only {_words.Length} words remain.");
        if (_o.UniqueWords && _words.Length < _o.WordCount)
            throw new InvalidOperationException(
                $"The list has only {_words.Length} words, but {_o.WordCount} unique words were requested.");
    }

    /// <summary>
    /// Multi-list mode (e.g. SK + CZ + EN): each passphrase contains at least one word from every list
    /// (when there are at least as many words as lists), in random language order. With fewer words than
    /// lists, each word comes from a different list.
    /// </summary>
    public PassphraseGenerator(IReadOnlyList<IEnumerable<string>> pools, GeneratorOptions options)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        Validate(_o);
        if (pools is null || pools.Count < 2)
            throw new ArgumentException("At least two word lists are required.");

        var filtered = pools.Select(p => GetFiltered(p, _o.MinWordLength, _o.MaxWordLength)).ToArray();

        // The lists must be disjoint: a word present in several languages (e.g. SK and CZ "roku") would
        // otherwise be picked more often and the "one word per language" rule would not truly hold.
        // Only words unique to a given list are therefore kept.
        _pools = GetExclusivePools(filtered);

        foreach (var pool in _pools)
            if (pool.Length < 2)
                throw new InvalidOperationException(
                    $"After filtering (length {_o.MinWordLength}–{_o.MaxWordLength}) one of the lists has only {pool.Length} words unique to it.");

        _words = _pools.SelectMany(p => p).Distinct().ToArray();
        if (_o.UniqueWords && _words.Length < _o.WordCount)
            throw new InvalidOperationException(
                $"The lists have only {_words.Length} words, but {_o.WordCount} unique words were requested.");
    }

    /// <summary>True when the generator draws from multiple disjoint language pools.</summary>
    public bool IsMultiList => _pools is not null;

    /// <summary>List sizes after filtering (in multi-language mode, with shared words already removed).</summary>
    public IReadOnlyList<int> PoolSizes => _pools?.Select(p => p.Length).ToArray() ?? new[] { _words.Length };

    /// <summary>Test-only: the words of each individual pool.</summary>
    internal IReadOnlyList<string[]> PoolsForTests => _pools ?? new[] { _words };

    // The filtered list is cached per word array and length range – for large lists (hundreds of
    // thousands of words) it would otherwise be filtered on every slider move.
    private static readonly ConditionalWeakTable<string[], Dictionary<(int, int), string[]>> FilterCache = new();

    /// <summary>Returns the length-filtered word array, cached per source array and length range.</summary>
    private static string[] GetFiltered(IEnumerable<string> source, int min, int max)
    {
        if (source is not string[] array) return Filter(source, min, max);

        var perList = FilterCache.GetOrCreateValue(array);
        lock (perList)
        {
            if (!perList.TryGetValue((min, max), out var filtered))
            {
                filtered = Filter(array, min, max);
                perList[(min, max)] = filtered;
            }
            return filtered;
        }
    }

    // last computed disjoint pools (filtered arrays come from the cache, so reference equality suffices)
    private static readonly object ExclusiveLock = new();
    private static string[][]? _lastExclusiveKey, _lastExclusiveValue;

    /// <summary>Reduces pools to words unique to a single pool (so cross-language duplicates are not favored).</summary>
    private static string[][] GetExclusivePools(string[][] filtered)
    {
        lock (ExclusiveLock)
        {
            if (_lastExclusiveKey is not null && _lastExclusiveKey.Length == filtered.Length
                && _lastExclusiveKey.Zip(filtered).All(t => ReferenceEquals(t.First, t.Second)))
                return _lastExclusiveValue!;

            var occurrences = new Dictionary<string, int>();
            foreach (var pool in filtered)
                foreach (var w in pool)
                    occurrences[w] = occurrences.GetValueOrDefault(w) + 1;
            var result = filtered.Select(pool => pool.Where(w => occurrences[w] == 1).ToArray()).ToArray();

            _lastExclusiveKey = filtered;
            _lastExclusiveValue = result;
            return result;
        }
    }

    /// <summary>Normalizes, length-filters, letter-filters, lower-cases and de-duplicates a word source.</summary>
    private static string[] Filter(IEnumerable<string> source, int min, int max) => source
        .Select(w => w.Trim().Normalize(NormalizationForm.FormC)) // the same word in different Unicode forms = one word
        .Where(w => w.Length >= min && w.Length <= max)
        .Where(w => w.All(char.IsLetter))
        .Select(w => w.ToLowerInvariant())
        .Distinct()
        .ToArray();

    /// <summary>Total number of distinct usable words after filtering.</summary>
    public int WordListSize => _words.Length;

    /// <summary>Generates one passphrase according to the current options.</summary>
    public string Generate()
    {
        var chosen = PickWords();
        var parts = new string[chosen.Length];

        for (int i = 0; i < chosen.Length; i++)
            parts[i] = ApplyCase(chosen[i], i);

        // a random character inside a random word (not at the start or end – the word stays readable)
        if (_o.InsertRandomChar)
        {
            int wi = Rand(parts.Length);
            string w = parts[wi];
            if (w.Length >= 2)
            {
                int pos = 1 + Rand(w.Length - 1);
                string set = InsertCharSet();
                parts[wi] = w[..pos] + set[Rand(set.Length)] + w[pos..];
            }
        }

        // numbers
        switch (_o.Numbers)
        {
            case NumberMode.OneWord:
                int idx = Rand(parts.Length);
                parts[idx] = AttachNumber(parts[idx]);
                break;
            case NumberMode.EachWord:
                for (int i = 0; i < parts.Length; i++)
                    parts[i] = AttachNumber(parts[i]);
                break;
        }

        // join with separators
        var sb = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.Length; i++)
        {
            sb.Append(NextSeparator());
            sb.Append(parts[i]);
        }

        if (_o.Numbers == NumberMode.End)
            sb.Append(RandomDigits(_o.DigitCount));

        return sb.ToString();
    }

    /// <summary>Lazily generates <paramref name="count"/> independent passphrases.</summary>
    public IEnumerable<string> Generate(int count)
    {
        for (int i = 0; i < count; i++)
            yield return Generate();
    }

    /// <summary>Estimates entropy in bits assuming the attacker knows the settings and the word list (conservative).</summary>
    public double EstimateEntropyBits()
    {
        int n = _o.WordCount;
        double bits = 0;

        // words
        if (_pools is not null)
        {
            // conservative: count each word as if from the smallest pool,
            // and do not credit the random language order
            int smallest = _pools.Min(p => p.Length);
            for (int i = 0; i < n; i++) bits += Math.Log2(smallest - (_o.UniqueWords ? i : 0));
        }
        else if (_o.UniqueWords)
            for (int i = 0; i < n; i++) bits += Math.Log2(_words.Length - i);
        else
            bits += n * Math.Log2(_words.Length);

        // case
        if (_o.Case == CaseMode.Random) bits += n * Math.Log2(3);
        if (_o.Case == CaseMode.Alternate) bits += 1; // starts lower or upper

        // separators
        int seps = n - 1;
        bits += _o.SeparatorMode switch
        {
            SeparatorMode.RandomDigit => seps * Math.Log2(10),
            SeparatorMode.RandomSymbol => seps * Math.Log2(DistinctSymbols().Length),
            SeparatorMode.RandomDigitOrSymbol => seps * Math.Log2(10 + DistinctSymbols().Length),
            _ => 0
        };

        // numbers
        double digitBits = _o.DigitCount * Math.Log2(10);
        bits += _o.Numbers switch
        {
            NumberMode.OneWord => digitBits + Math.Log2(n),
            NumberMode.EachWord => n * digitBits,
            NumberMode.End => digitBits,
            _ => 0
        };

        // number side – only counted when the separator can be neither a digit nor empty
        // (otherwise "word12.3x" and "word1.23x" could merge and the bit would be fictitious)
        if (_o.NumberRandomSide && SeparatorIsUnambiguous())
            bits += _o.Numbers switch { NumberMode.OneWord => 1, NumberMode.EachWord => n, _ => 0 };

        // inserted character: word choice × (conservative) fewest inner positions × character
        if (_o.InsertRandomChar && _o.MinWordLength >= 2)
            bits += Math.Log2(n) + Math.Log2(_o.MinWordLength - 1) + Math.Log2(InsertCharSet().Length);

        return bits;
    }

    // ---------- internal ----------

    /// <summary>Picks the words for one passphrase (unique if requested) from the single list.</summary>
    private string[] PickWords()
    {
        if (_pools is not null) return PickWordsFromPools(_pools);

        var result = new string[_o.WordCount];
        var used = new HashSet<int>();
        for (int i = 0; i < result.Length; i++)
        {
            int k;
            do k = Rand(_words.Length);
            while (_o.UniqueWords && !used.Add(k));
            result[i] = _words[k];
        }
        return result;
    }

    /// <summary>Picks words so every pool is used at least once, in random order (multi-list mode).</summary>
    private string[] PickWordsFromPools(string[][] pools)
    {
        int n = _o.WordCount;

        // each pool at least once, remaining positions a random pool; then shuffle
        var assignment = new List<int>(Enumerable.Range(0, pools.Length));
        while (assignment.Count < n) assignment.Add(Rand(pools.Length));
        Shuffle(assignment);
        if (assignment.Count > n) assignment.RemoveRange(n, assignment.Count - n); // fewer words than pools

        var result = new string[n];
        var used = new HashSet<string>();
        for (int i = 0; i < n; i++)
        {
            var pool = pools[assignment[i]];
            string w;
            do w = pool[Rand(pool.Length)];
            while (_o.UniqueWords && !used.Add(w));
            result[i] = w;
        }
        return result;
    }

    /// <summary>In-place Fisher–Yates shuffle using the CSPRNG.</summary>
    private void Shuffle<T>(IList<T> list)
    {
        for (int i = list.Count - 1; i > 0; i--)
        {
            int j = Rand(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }

    private bool? _alternateStartUpper;

    /// <summary>Applies the configured case mode to a word at the given position.</summary>
    private string ApplyCase(string w, int index) => _o.Case switch
    {
        CaseMode.Lower => w,
        CaseMode.Upper => w.ToUpperInvariant(),
        CaseMode.Capitalize => Capitalize(w),
        CaseMode.Random => Rand(3) switch
        {
            0 => w,
            1 => w.ToUpperInvariant(),
            _ => Capitalize(w)
        },
        CaseMode.Alternate => AlternateCase(w, index),
        _ => w
    };

    /// <summary>Alternates upper/lower case per word, with a random starting case.</summary>
    private string AlternateCase(string w, int index)
    {
        if (index == 0) _alternateStartUpper = Rand(2) == 1;
        bool upper = (index % 2 == 0) == _alternateStartUpper;
        return upper ? w.ToUpperInvariant() : w;
    }

    /// <summary>Upper-cases the first letter of a word.</summary>
    private static string Capitalize(string w) =>
        w.Length == 0 ? w : char.ToUpperInvariant(w[0]) + w[1..];

    /// <summary>Returns the next separator (fixed, random digit, random symbol, or either).</summary>
    private string NextSeparator() => _o.SeparatorMode switch
    {
        SeparatorMode.Fixed => _o.Separator,
        SeparatorMode.RandomDigit => Rand(10).ToString(),
        SeparatorMode.RandomSymbol => PickChar(DistinctSymbols()),
        SeparatorMode.RandomDigitOrSymbol => PickChar("0123456789" + DistinctSymbols()),
        _ => _o.Separator
    };

    /// <summary>Appends (or, with NumberRandomSide, prepends) random digits to a word.</summary>
    private string AttachNumber(string word)
    {
        string digits = RandomDigits(_o.DigitCount);
        bool before = _o.NumberRandomSide && Rand(2) == 0;
        return before ? digits + word : word + digits;
    }

    /// <summary>Characters eligible for insertion into a word: digits + allowed symbols.</summary>
    private string InsertCharSet() => "0123456789" + DistinctSymbols();

    /// <summary>True if the separator can never be a digit or empty (so number-side adds real entropy).</summary>
    private bool SeparatorIsUnambiguous() => _o.SeparatorMode switch
    {
        SeparatorMode.RandomSymbol => true,
        SeparatorMode.Fixed => _o.Separator.Length > 0 && !_o.Separator.Any(char.IsDigit),
        _ => false // digits as the separator
    };

    /// <summary>Returns the configured symbol set with duplicates removed.</summary>
    private string DistinctSymbols() => new(_o.SymbolSet.Distinct().ToArray());

    /// <summary>Picks one random character from a set via the CSPRNG.</summary>
    private string PickChar(string set) =>
        set[Rand(set.Length)].ToString();

    /// <summary>Returns a string of <paramref name="count"/> CSPRNG digits.</summary>
    private string RandomDigits(int count)
    {
        var sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) sb.Append(Rand(10));
        return sb.ToString();
    }

    /// <summary>Validates option ranges and throws on invalid combinations.</summary>
    private static void Validate(GeneratorOptions o)
    {
        if (o.WordCount is < 1 or > 20) throw new ArgumentException("Number of words must be 1–20.");
        if (o.DigitCount is < 1 or > 10) throw new ArgumentException("Number of digits must be 1–10.");
        if (o.MinWordLength < 1 || o.MaxWordLength < o.MinWordLength)
            throw new ArgumentException("Invalid word length range.");
        if (o.SeparatorMode is SeparatorMode.RandomSymbol && string.IsNullOrEmpty(o.SymbolSet))
            throw new ArgumentException("The symbol set must not be empty.");
    }
}
