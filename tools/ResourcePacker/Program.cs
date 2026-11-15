// Phrasia ResourcePacker – Copyright (C) 2026 Lukáš "LUKI" Maár – GPL-3.0
// Encrypts the plain word lists in Resources/ into the r_*.bin files embedded in Phrasia.exe
// (AES-256-GCM, see Core/Crypto/ResourceProtection.cs), or verifies existing ones.
using Phrasia;

var map = new (string Resource, string Source)[]
{
    ("r_sk", "sk_common.txt"),
    ("r_en", "en_eff.txt"),
    ("r_cs", "cs_words.txt.gz"), // kept gzipped; the app gunzips it after decryption
};

if (args.Length < 1 || args.Contains("-h") || args.Contains("--help"))
{
    Console.WriteLine("usage: ResourcePacker <Resources folder> [--verify]");
    Console.WriteLine("  (default)  encrypt each plain list into its r_*.bin");
    Console.WriteLine("  --verify   check that every existing r_*.bin decrypts to its plain list");
    return 2;
}

string dir = args[0];
bool verify = args.Contains("--verify");
int errors = 0;

foreach (var (resource, source) in map)
{
    var sourcePath = Path.Combine(dir, source);
    var binPath = Path.Combine(dir, resource + ".bin");
    if (!File.Exists(sourcePath))
    {
        Console.Error.WriteLine($"missing source: {sourcePath}");
        errors++;
        continue;
    }
    var plain = File.ReadAllBytes(sourcePath);

    if (!verify)
    {
        File.WriteAllBytes(binPath, ResourceProtection.Encrypt(resource, plain));
        Console.WriteLine($"packed   {source} -> {resource}.bin ({plain.Length:N0} bytes)");
        continue;
    }

    if (!File.Exists(binPath))
    {
        Console.Error.WriteLine($"missing: {binPath}");
        errors++;
        continue;
    }
    try
    {
        var decrypted = ResourceProtection.Decrypt(resource, File.ReadAllBytes(binPath));
        bool same = decrypted.AsSpan().SequenceEqual(plain);
        Console.WriteLine($"{(same ? "OK     " : "DIFFERS")}  {resource}.bin <-> {source}");
        if (!same) errors++;
    }
    catch (Exception e)
    {
        Console.Error.WriteLine($"FAILED   {resource}.bin: {e.Message}");
        errors++;
    }
}

return errors == 0 ? 0 : 1;
