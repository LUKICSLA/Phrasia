using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Phrasia;

/// <summary>
/// ChaCha20-Poly1305 AEAD (RFC 8439): 256-bit key, 96-bit nonce, 128-bit tag.
/// Uses the operating-system implementation when available (Windows 11 / Server 2022, Linux, macOS) and an
/// equivalent managed implementation otherwise – Windows 10 does not provide ChaCha20-Poly1305. Both produce
/// byte-identical output, so a vault written on one computer opens on the other.
/// </summary>
internal static class ChaCha20Poly1305Aead
{
    private const int KeySize = 32, NonceSize = 12, TagSize = 16;

    /// <summary>Test switch: always use the managed implementation.</summary>
    internal static bool ForceManaged;

    /// <summary>True when the operating-system implementation is used.</summary>
    public static bool UsesNative => !ForceManaged && ChaCha20Poly1305.IsSupported;

    /// <summary>Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> (same length) and writes the 16-byte tag.</summary>
    public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData)
    {
        CheckSizes(key, nonce, tag.Length);
        if (ciphertext.Length != plaintext.Length)
            throw new ArgumentException("Plaintext and ciphertext must have the same length.", nameof(ciphertext));

        if (UsesNative)
        {
            using var native = new ChaCha20Poly1305(key);
            native.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return;
        }
        ChaCha20Xor(key, nonce, 1, plaintext, ciphertext);
        ComputeTag(key, nonce, associatedData, ciphertext, tag);
    }

    /// <summary>Verifies the tag and decrypts. On a wrong key, nonce, tag or data throws
    /// <see cref="AuthenticationTagMismatchException"/> and leaves <paramref name="plaintext"/> zeroed.</summary>
    public static void Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        CheckSizes(key, nonce, tag.Length);
        if (plaintext.Length != ciphertext.Length)
            throw new ArgumentException("Plaintext and ciphertext must have the same length.", nameof(plaintext));

        if (UsesNative)
        {
            using var native = new ChaCha20Poly1305(key);
            native.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return;
        }

        // authenticate first, decrypt only data that passed
        Span<byte> expected = stackalloc byte[TagSize];
        ComputeTag(key, nonce, associatedData, ciphertext, expected);
        bool valid = CryptographicOperations.FixedTimeEquals(expected, tag);
        CryptographicOperations.ZeroMemory(expected);
        if (!valid)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new AuthenticationTagMismatchException();
        }
        ChaCha20Xor(key, nonce, 1, ciphertext, plaintext);
    }

    /// <summary>Validates the fixed key, nonce and tag sizes.</summary>
    private static void CheckSizes(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int tagLength)
    {
        if (key.Length != KeySize) throw new ArgumentException("ChaCha20-Poly1305 needs a 256-bit key.", nameof(key));
        if (nonce.Length != NonceSize) throw new ArgumentException("ChaCha20-Poly1305 needs a 96-bit nonce.", nameof(nonce));
        if (tagLength != TagSize) throw new ArgumentException("ChaCha20-Poly1305 uses a 128-bit tag.", "tag");
    }

    // ---------------- ChaCha20 (RFC 8439, section 2.3 – 2.4) ----------------

    /// <summary>XORs <paramref name="input"/> with the ChaCha20 keystream starting at block <paramref name="counter"/>.</summary>
    private static void ChaCha20Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter,
        ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<uint> state = stackalloc uint[16];
        Span<uint> work = stackalloc uint[16];
        Span<byte> keystream = stackalloc byte[64];
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4 * i));
        state[12] = counter;
        for (int i = 0; i < 3; i++) state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4 * i));
        try
        {
            for (int offset = 0; offset < input.Length; offset += 64)
            {
                Block(state, work, keystream);
                int n = Math.Min(64, input.Length - offset);
                for (int i = 0; i < n; i++) output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
                if (++state[12] == 0 && offset + 64 < input.Length)
                    throw new CryptographicException("ChaCha20 block counter overflow.");
            }
        }
        finally
        {
            state.Clear();
            work.Clear();
            keystream.Clear();
        }
    }

    /// <summary>The ChaCha20 block function: 20 rounds over a copy of the state, then added to it (little-endian output).</summary>
    private static void Block(ReadOnlySpan<uint> state, Span<uint> x, Span<byte> output)
    {
        state.CopyTo(x);
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14);
            QuarterRound(x, 3, 7, 11, 15);
            QuarterRound(x, 0, 5, 10, 15);
            QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13);
            QuarterRound(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4 * i), x[i] + state[i]);
    }

    /// <summary>The ChaCha quarter round.</summary>
    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }

    // ---------------- AEAD construction (RFC 8439, section 2.8) ----------------

    /// <summary>Poly1305 over aad ‖ pad16 ‖ ciphertext ‖ pad16 ‖ len(aad) ‖ len(ciphertext), keyed by ChaCha20 block 0.</summary>
    private static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ciphertext, Span<byte> tag)
    {
        Span<byte> zeros = stackalloc byte[64];
        Span<byte> block0 = stackalloc byte[64];
        zeros.Clear();
        ChaCha20Xor(key, nonce, 0, zeros, block0);
        try
        {
            var mac = new Poly1305(block0[..32]);
            mac.UpdatePadded(aad);
            mac.UpdatePadded(ciphertext);
            Span<byte> lengths = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(lengths, (ulong)aad.Length);
            BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertext.Length);
            mac.UpdatePadded(lengths);
            mac.Finish(tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block0);
        }
    }

    // ---------------- Poly1305 (RFC 8439, section 2.5) – 26-bit limbs, constant time ----------------

    /// <summary>Poly1305 one-time authenticator over full 16-byte blocks (the AEAD construction pads every part to 16 bytes).</summary>
    private struct Poly1305
    {
        private const uint Mask26 = 0x3ffffff;
        private uint _r0, _r1, _r2, _r3, _r4, _s1, _s2, _s3, _s4;
        private uint _h0, _h1, _h2, _h3, _h4;
        private uint _pad0, _pad1, _pad2, _pad3;

        /// <summary>Loads the 32-byte one-time key: clamped r (first half) and s (second half).</summary>
        public Poly1305(ReadOnlySpan<byte> key)
        {
            uint t0 = LE(key, 0), t1 = LE(key, 4), t2 = LE(key, 8), t3 = LE(key, 12);
            _r0 = t0 & 0x3ffffff;
            _r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
            _r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
            _r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
            _r4 = (t3 >> 8) & 0x00fffff;
            _s1 = _r1 * 5; _s2 = _r2 * 5; _s3 = _r3 * 5; _s4 = _r4 * 5;
            _h0 = _h1 = _h2 = _h3 = _h4 = 0;
            _pad0 = LE(key, 16); _pad1 = LE(key, 20); _pad2 = LE(key, 24); _pad3 = LE(key, 28);
        }

        /// <summary>Absorbs data as full 16-byte blocks, zero-padding the last one (AEAD "pad16").</summary>
        public void UpdatePadded(ReadOnlySpan<byte> data)
        {
            int full = data.Length & ~15;
            for (int i = 0; i < full; i += 16) Block(data.Slice(i, 16));
            if (full == data.Length) return;
            Span<byte> last = stackalloc byte[16];
            last.Clear();
            data[full..].CopyTo(last);
            Block(last);
            CryptographicOperations.ZeroMemory(last);
        }

        /// <summary>h = (h + block + 2^128) · r mod 2^130 − 5.</summary>
        private void Block(ReadOnlySpan<byte> m)
        {
            _h0 += LE(m, 0) & Mask26;
            _h1 += (LE(m, 3) >> 2) & Mask26;
            _h2 += (LE(m, 6) >> 4) & Mask26;
            _h3 += (LE(m, 9) >> 6) & Mask26;
            _h4 += (LE(m, 12) >> 8) | (1u << 24);

            ulong d0 = (ulong)_h0 * _r0 + (ulong)_h1 * _s4 + (ulong)_h2 * _s3 + (ulong)_h3 * _s2 + (ulong)_h4 * _s1;
            ulong d1 = (ulong)_h0 * _r1 + (ulong)_h1 * _r0 + (ulong)_h2 * _s4 + (ulong)_h3 * _s3 + (ulong)_h4 * _s2;
            ulong d2 = (ulong)_h0 * _r2 + (ulong)_h1 * _r1 + (ulong)_h2 * _r0 + (ulong)_h3 * _s4 + (ulong)_h4 * _s3;
            ulong d3 = (ulong)_h0 * _r3 + (ulong)_h1 * _r2 + (ulong)_h2 * _r1 + (ulong)_h3 * _r0 + (ulong)_h4 * _s4;
            ulong d4 = (ulong)_h0 * _r4 + (ulong)_h1 * _r3 + (ulong)_h2 * _r2 + (ulong)_h3 * _r1 + (ulong)_h4 * _r0;

            ulong c = d0 >> 26; _h0 = (uint)d0 & Mask26;
            d1 += c; c = d1 >> 26; _h1 = (uint)d1 & Mask26;
            d2 += c; c = d2 >> 26; _h2 = (uint)d2 & Mask26;
            d3 += c; c = d3 >> 26; _h3 = (uint)d3 & Mask26;
            d4 += c; c = d4 >> 26; _h4 = (uint)d4 & Mask26;
            _h0 += (uint)c * 5;
            _h1 += _h0 >> 26;
            _h0 &= Mask26;
        }

        /// <summary>Fully reduces h, adds s and writes the 16-byte tag; then wipes the state.</summary>
        public void Finish(Span<byte> tag)
        {
            uint c = _h1 >> 26; _h1 &= Mask26; _h2 += c;
            c = _h2 >> 26; _h2 &= Mask26; _h3 += c;
            c = _h3 >> 26; _h3 &= Mask26; _h4 += c;
            c = _h4 >> 26; _h4 &= Mask26; _h0 += c * 5;
            c = _h0 >> 26; _h0 &= Mask26; _h1 += c;

            // g = h + 5 − 2^130; use it if it did not underflow (i.e. h ≥ p) – selected without branching
            uint g0 = _h0 + 5; c = g0 >> 26; g0 &= Mask26;
            uint g1 = _h1 + c; c = g1 >> 26; g1 &= Mask26;
            uint g2 = _h2 + c; c = g2 >> 26; g2 &= Mask26;
            uint g3 = _h3 + c; c = g3 >> 26; g3 &= Mask26;
            uint g4 = _h4 + c - (1u << 26);
            uint mask = (g4 >> 31) - 1;
            g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
            mask = ~mask;
            _h0 = (_h0 & mask) | g0;
            _h1 = (_h1 & mask) | g1;
            _h2 = (_h2 & mask) | g2;
            _h3 = (_h3 & mask) | g3;
            _h4 = (_h4 & mask) | g4;

            // h mod 2^128, then + s
            uint w0 = _h0 | (_h1 << 26);
            uint w1 = (_h1 >> 6) | (_h2 << 20);
            uint w2 = (_h2 >> 12) | (_h3 << 14);
            uint w3 = (_h3 >> 18) | (_h4 << 8);
            ulong f = (ulong)w0 + _pad0; w0 = (uint)f;
            f = (ulong)w1 + _pad1 + (f >> 32); w1 = (uint)f;
            f = (ulong)w2 + _pad2 + (f >> 32); w2 = (uint)f;
            f = (ulong)w3 + _pad3 + (f >> 32); w3 = (uint)f;

            BinaryPrimitives.WriteUInt32LittleEndian(tag, w0);
            BinaryPrimitives.WriteUInt32LittleEndian(tag[4..], w1);
            BinaryPrimitives.WriteUInt32LittleEndian(tag[8..], w2);
            BinaryPrimitives.WriteUInt32LittleEndian(tag[12..], w3);
            this = default; // wipe key material and state
        }

        /// <summary>Reads a little-endian 32-bit word.</summary>
        private static uint LE(ReadOnlySpan<byte> b, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(b.Slice(offset));
    }
}
