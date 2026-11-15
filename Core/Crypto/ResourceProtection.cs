using System.IO;
using System.Security.Cryptography;

namespace Phrasia;

/// <summary>
/// Decrypts the embedded resources (word lists) stored in the .exe as AES-256-GCM.
///
/// IMPORTANT – HONEST ABOUT STRENGTH: this is obfuscation, not vault-grade protection.
/// The vault is protected by the user's password, which is NOT in the app. The word lists, however,
/// must load without any password (at startup, for the generator), so the key must be derivable from
/// the app itself. Therefore: in a hex editor (HxD) the resources look like random bytes and cannot be
/// read or guessed; but anyone who disassembles the .exe and runs its own code can reconstruct the key.
/// The goal is "make it as hard as possible", not impossible – which is unachievable for data the app
/// reads itself without a password.
///
/// The key is not stored as a single block: at runtime it is assembled from several scattered parts, and
/// HKDF derives a distinct key per resource. Resource format: [nonce 12][ciphertext][tag 16],
/// AAD = resource name (swapping files is detected).
/// </summary>
internal static class ResourceProtection
{
    private const int NonceSize = 12, TagSize = 16, KeySize = 32;

    // scattered parts – individually they reveal nothing; order and combination are decided only in Assemble()
    private static readonly byte[] P1 = { 0x8F, 0x2C, 0xA7, 0x4E, 0xB1, 0x05, 0xD3, 0x6A, 0x19, 0xF8, 0x7B, 0x2D };
    private static readonly byte[] P2 = { 0x44, 0xE0, 0x93, 0x1C, 0xAF, 0x58, 0x72, 0xBE, 0x06, 0xD1, 0x3F, 0x9A };
    private static readonly byte[] P3 = { 0x21, 0x6D, 0xC4, 0x88, 0x0B, 0xF3, 0x5E, 0x97, 0xA2, 0x4C, 0xE9, 0x30 };
    private static readonly byte[] P4 = { 0xDA, 0x17, 0x6F, 0xB5, 0x92, 0x28, 0x4A, 0xC1, 0x7E, 0x03, 0x8D, 0x56 };
    private static readonly byte[] Pepper = "Phrasia embedded resource vault | do not treat as real key"u8.ToArray();
    private static readonly byte[] HkdfSalt = { 0x63, 0x1A, 0xBF, 0x04, 0x7D, 0x2E, 0x95, 0xC8, 0x50, 0x3B, 0xE7, 0x16, 0x8C, 0x41, 0xA9, 0xD2 };

    /// <summary>Assembles the 32-byte "master" from all parts (at runtime only, never stored).</summary>
    private static byte[] Assemble()
    {
        var buf = new byte[P1.Length + P2.Length + P3.Length + P4.Length + Pepper.Length];
        int o = 0;
        // interleaved order, not plain concatenation
        P3.CopyTo(buf, o); o += P3.Length;
        P1.CopyTo(buf, o); o += P1.Length;
        P4.CopyTo(buf, o); o += P4.Length;
        Pepper.CopyTo(buf, o); o += Pepper.Length;
        P2.CopyTo(buf, o);
        var master = SHA256.HashData(buf);
        CryptographicOperations.ZeroMemory(buf);
        return master;
    }

    /// <summary>Key for a specific resource – distinct per name (HKDF-SHA256).</summary>
    private static byte[] KeyFor(string resourceName)
    {
        var master = Assemble();
        try
        {
            var key = new byte[KeySize];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, master, key, HkdfSalt,
                System.Text.Encoding.UTF8.GetBytes(resourceName));
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
        }
    }

    /// <summary>Decrypts an embedded [nonce][ct][tag] resource. AAD = resource name.</summary>
    public static byte[] Decrypt(string resourceName, byte[] blob)
    {
        if (blob.Length < NonceSize + TagSize)
            throw new InvalidDataException($"Protected resource '{resourceName}' is too short.");
        var key = KeyFor(resourceName);
        try
        {
            var nonce = blob.AsSpan(0, NonceSize);
            var tag = blob.AsSpan(blob.Length - TagSize, TagSize);
            var cipher = blob.AsSpan(NonceSize, blob.Length - NonceSize - TagSize);
            var plain = new byte[cipher.Length];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain,
                System.Text.Encoding.UTF8.GetBytes(resourceName));
            return plain;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Encrypts a resource as [nonce 12][ciphertext][tag 16], AAD = resource name. Used by tools/ResourcePacker to regenerate Resources/r_*.bin from the plain word lists.</summary>
    public static byte[] Encrypt(string resourceName, byte[] plain)
    {
        var key = KeyFor(resourceName);
        try
        {
            var blob = new byte[NonceSize + plain.Length + TagSize];
            var nonce = blob.AsSpan(0, NonceSize);
            RandomNumberGenerator.Fill(nonce);
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plain,
                blob.AsSpan(NonceSize, plain.Length),
                blob.AsSpan(NonceSize + plain.Length, TagSize),
                System.Text.Encoding.UTF8.GetBytes(resourceName));
            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
