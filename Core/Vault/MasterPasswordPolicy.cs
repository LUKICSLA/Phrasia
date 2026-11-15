using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Phrasia;
/// <summary>Master-password strength policy: entropy estimation and validation rules.</summary>
public static class MasterPasswordPolicy
{
    // ----- the suggested master password ("Suggest a strong password") -----
    private const int SuggestionWords = 5;
    private const int SuggestionMinWordLength = 3;
    private const int SuggestionMaxWordLength = 10;
    private const string SuggestionSeparator = ".";
    private const int SuggestionDigits = 2;

    /// <summary>Minimum master-password length: as long as the shortest password the suggestion can produce
    /// (5 words × 3 letters + 4 separators + 2 digits = 21), so a typed password is never shorter than a generated one.
    /// Suggestions are typically ~41 characters long.</summary>
    public static readonly int MinLength =
        SuggestionWords * SuggestionMinWordLength + (SuggestionWords - 1) * SuggestionSeparator.Length + SuggestionDigits;

    /// <summary>Minimum estimated strength (bits) of a master password.</summary>
    public const double MinBits = 70;

    /// <summary>Generates a strong master password: 5 random words from the large Slovak list (without diacritics,
    /// so it can be typed on any keyboard), random case, "." separators and 2 digits after one word (≈ 90 bits).
    /// Randomness: OS CSPRNG mixed with the user's mouse entropy (<see cref="EntropyPool"/>). The result always satisfies <see cref="Validate"/>.</summary>
    public static string Suggest()
    {
        var generator = new PassphraseGenerator(
            WordLists.SlovakLarge.Select(WordLists.RemoveDiacritics),
            new GeneratorOptions
            {
                WordCount = SuggestionWords,
                MinWordLength = SuggestionMinWordLength,
                MaxWordLength = SuggestionMaxWordLength,
                Case = CaseMode.Random,
                SeparatorMode = SeparatorMode.Fixed,
                Separator = SuggestionSeparator,
                Numbers = NumberMode.OneWord,
                DigitCount = SuggestionDigits,
                RandomSource = EntropyPool.GetInt32 // OS CSPRNG mixed with the user's mouse entropy
            });
        string pw = generator.Generate();
        for (int i = 0; i < 100 && Validate(pw) is not null; i++) pw = generator.Generate(); // safety net – passes by construction
        return pw;
    }

    /// <summary>Rough password-strength estimate (length × log2 of the alphabet size) with a penalty for repeated characters. Not perfect, but reliably filters out "Password12345" and the like.</summary>
    public static double EstimateBits(string pw)
    {
        if (string.IsNullOrEmpty(pw)) return 0;
        int pool = 0;
        if (pw.Any(char.IsAsciiLetterLower)) pool += 26;
        if (pw.Any(char.IsAsciiLetterUpper)) pool += 26;
        if (pw.Any(char.IsAsciiDigit)) pool += 10;
        if (pw.Any(c => c < 128 && !char.IsAsciiLetterOrDigit(c))) pool += 33;
        if (pw.Any(c => c >= 128)) pool += 50;

        int distinct = pw.Distinct().Count();
        double effectiveLength = Math.Min(pw.Length, distinct * 2.0); // "aaaaaaaaaaaa" is not strong
        return effectiveLength * Math.Log2(pool);
    }

    /// <summary>Returns an error message if the password fails the policy (length/strength), or null if it passes.</summary>
    public static string? Validate(string pw)
    {
        if (pw.Length < MinLength) return $"The master password must be at least {MinLength} characters long.";
        if (EstimateBits(pw) < MinBits) return "The master password is too weak – add more words or characters.";
        return null;
    }
}
