using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Phrasia;

/// <summary>
/// Built-in word lists. For more security load your own large list via "Load wordlist"
/// (e.g. the EFF large wordlist). Slovak words are diacritic-free so they are easy to type on any keyboard.
/// </summary>
public static class WordLists
{
    /// <summary>Small built-in English word list (space/newline separated).</summary>
    public static readonly string[] English =
    """
    apple anchor angle animal answer arrow autumn badge baker balloon bamboo banana
    basket battery beach beacon bear beaver bicycle bird blanket blossom border bottle
    bread breeze brick bridge bronze bubble bucket butter cabin cactus camera candle
    canyon carbon carpet castle cedar cherry chess circle cloud clover coffee comet
    copper coral cotton cousin crayon cricket crystal curtain dancer desert diamond
    dinner dolphin donkey dragon dream drum eagle echo engine falcon feather fence
    field finger flame flower forest fossil fountain fox frost galaxy garden giant
    ginger glacier glass globe goat gold grape gravel guitar hammer harbor harvest
    hawk helmet hero hill honey horizon horse island ivory jacket jaguar jelly jungle
    kettle kitten ladder lagoon lake lantern lemon lettuce library lizard lobster
    magnet mango maple marble meadow melon meteor mirror monkey moon mountain muffin
    needle nest noodle ocean olive onion orange orbit otter owl paddle panda paper
    parrot peach pebble pencil pepper piano pillow pilot planet plum pocket pony
    potato puzzle quartz rabbit radar rain raven ribbon river robot rocket saddle
    salmon sand saturn scarf shadow shark shell silver sketch sky snow socket spider
    spring squirrel star stone storm sugar summer sunset swan table tiger timber
    toast tomato tower tractor trumpet tulip tunnel turtle umbrella valley velvet
    violin volcano wagon walnut water weather whale whisper willow window winter
    wizard wolf yellow zebra zipper
    """.Split((char[])[' ', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries);

    /// <summary>Small built-in Slovak word list, diacritic-free.</summary>
    public static readonly string[] Slovak =
    """
    macka pes kon krava ovca koza zajac liska vlk medved jelen srna sova orol
    holub vrabec kacica hus labut ryba kapor pstruh zaba had jasterica motyl
    vcela osa mravec pavuk slimak jez veverica myska potkan kohut sliepka
    strom dub buk javor lipa breza smrek jedla borovica vrba gastan orech jablko
    hruska slivka marhula broskyna ceresna malina jahoda hrozno citron pomaranc
    banan melon mrkva zemiak cibula cesnak paprika rajcina uhorka kapusta tekvica
    chlieb rozok maslo syr mlieko vajce med cukor sol kava caj polievka kolac
    dom chata hrad zamok veza most cesta ulica mesto dedina pole luka les hora
    kopec dolina rieka potok jazero more ostrov pustatina jaskyna skala kamen
    piesok hlina blato sneh dazd vietor hmla mraz slnko mesiac hviezda oblak
    duha blesk hrom jar leto jesen zima rano vecer noc obed tyzden rok
    stol stolicka postel skrina okno dvere stena strecha komin schody lampa
    hodiny zrkadlo obraz kniha zosit pero ceruzka papier taska kufor kluc zamka
    lyzica vidlicka noz tanier hrnec panvica pohar flasa kanva vedro metla
    auto vlak lietadlo lod bicykel motorka autobus elektricka traktor raketa
    gitara husle bubon klavir pistalka zvon spev tanec hra lopta kocka
    cervena modra zelena zlta biela cierna siva ruzova fialova oranzova
    zlato striebro med zelezo olovo cin drevo sklo hodvab vlna bavlna koza
    kral kralovna princ rytier drak obor trpaslik carodej vila skriatok
    lekar ucitel kuchar pekar kovac mlynar rybar pastier zahradnik pilot
    """.Split((char[])[' ', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries);

    private static string[]? _slovakLarge;

    /// <summary>Large Slovak list (~36k common words) embedded (encrypted) in the .exe; loaded lazily.</summary>
    public static string[] SlovakLarge => _slovakLarge ??= LoadEmbedded("r_sk", gzip: false);

    private static string[]? _englishLarge;

    /// <summary>EFF Large Wordlist (7,772 words) chosen for passphrases. © EFF, CC BY 3.0 US. Loaded lazily.</summary>
    public static string[] EnglishLarge => _englishLarge ??= LoadEmbedded("r_en", gzip: false);

    /// <summary>Count of "common" Czech words at the start of the list (corpus frequency ≥ 50).</summary>
    public const int CzechCommonCount = 89_905;
    private static string[]? _czechAll, _czechCommon;

    /// <summary>Czech list (~253k word forms) by frequency; OpenSubtitles FrequencyWords (CC BY-SA 4.0), spell-checked. Loaded lazily.</summary>
    public static string[] CzechAll => _czechAll ??= LoadEmbedded("r_cs", gzip: true);

    /// <summary>The ~90k most frequent Czech words (easier to remember).</summary>
    public static string[] CzechCommon => _czechCommon ??= CzechAll.Take(CzechCommonCount).ToArray();

    /// <summary>Loads an embedded word list: the resource is AES-256-GCM encrypted, decrypted in memory, optionally gunzipped, then split into words. Plaintext stays in RAM only.</summary>
    private static string[] LoadEmbedded(string name, bool gzip)
    {
        using var stream = typeof(WordLists).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded word list '{name}' was not found.");
        using var raw = new MemoryStream();
        stream.CopyTo(raw);

        var decrypted = ResourceProtection.Decrypt(name, raw.ToArray());
        try
        {
            if (!gzip) return ParseText(Decode(decrypted)).ToArray();

            using var src = new MemoryStream(decrypted);
            using var gz = new GZipStream(src, CompressionMode.Decompress);
            using var ms = new MemoryStream();
            gz.CopyTo(ms);
            return ParseText(Decode(ms.ToArray())).ToArray();
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(decrypted);
        }
    }

    /// <summary>Loads words from a .txt or .zip file (all entries). Supports one-word-per-line, EFF "11111&lt;TAB&gt;word" and "word count". Encoding: UTF-8, falling back to Windows-1250.</summary>
    public static string[] LoadFromFile(string path)
    {
        if (Path.GetExtension(path).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            var words = new List<string>();
            using var zip = ZipFile.OpenRead(path);
            foreach (var entry in zip.Entries)
            {
                if (entry.Length == 0 || entry.FullName.EndsWith('/')) continue;
                using var stream = entry.Open();
                using var ms = new MemoryStream();
                stream.CopyTo(ms);
                words.AddRange(ParseText(Decode(ms.ToArray())));
            }
            return words.ToArray();
        }

        return ParseText(Decode(File.ReadAllBytes(path))).ToArray();
    }

    /// <summary>Strips diacritics: "mačka" → "macka".</summary>
    public static string RemoveDiacritics(string s)
    {
        var decomposed = s.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(decomposed.Length);
        foreach (char c in decomposed)
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
                sb.Append(c);
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }

    /// <summary>Decodes bytes as UTF-8 (stripping BOM), falling back to Windows-1250 on invalid UTF-8.</summary>
    private static string Decode(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes).TrimStart('\uFEFF');
        }
        catch (DecoderFallbackException)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(1250).GetString(bytes);
        }
    }

    /// <summary>Parses text into words: skips blanks/comments and takes the first all-letter token per line.</summary>
    private static IEnumerable<string> ParseText(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            // take the first all-letter token from the line (ignores numbers, frequencies, etc.)
            var word = line
                .Split((char[])['\t', ' ', ',', ';', '/'], StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault(t => t.All(char.IsLetter));
            if (word is not null) yield return word;
        }
    }
}
