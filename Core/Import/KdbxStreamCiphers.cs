using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Phrasia;

/// <summary>A keystream that is XORed over data in order (used for KeePass inner-stream protection and the ChaCha20 body cipher).</summary>
internal interface IKdbxKeyStream : IDisposable
{
    /// <summary>XORs the next <c>data.Length</c> keystream bytes into <paramref name="data"/> in place.</summary>
    void Xor(Span<byte> data);
}

/// <summary>ChaCha20 (RFC 8439: 256-bit key, 96-bit nonce, 32-bit block counter) as a continuous keystream.</summary>
internal sealed class KdbxChaCha20 : IKdbxKeyStream
{
    private readonly uint[] _state = new uint[16];
    private readonly uint[] _work = new uint[16];
    private readonly byte[] _block = new byte[64];
    private int _used = 64; // no keystream buffered yet

    /// <summary>Creates the keystream; the block counter starts at <paramref name="counter"/> (0 for KeePass).</summary>
    public KdbxChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter = 0)
    {
        if (key.Length != 32) throw new ArgumentException("ChaCha20 needs a 32-byte key.", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("ChaCha20 needs a 12-byte nonce.", nameof(nonce));
        _state[0] = 0x61707865; _state[1] = 0x3320646e; _state[2] = 0x79622d32; _state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) _state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        _state[12] = counter;
        for (int i = 0; i < 3; i++) _state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(4 * i)..]);
    }

    public void Xor(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (_used == 64) NextBlock();
            data[i] ^= _block[_used++];
        }
    }

    /// <summary>Computes the next 64-byte keystream block and advances the counter.</summary>
    private void NextBlock()
    {
        Array.Copy(_state, _work, 16);
        for (int i = 0; i < 10; i++)
        {
            Qr(_work, 0, 4, 8, 12); Qr(_work, 1, 5, 9, 13); Qr(_work, 2, 6, 10, 14); Qr(_work, 3, 7, 11, 15);
            Qr(_work, 0, 5, 10, 15); Qr(_work, 1, 6, 11, 12); Qr(_work, 2, 7, 8, 13); Qr(_work, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(_block.AsSpan(4 * i), _work[i] + _state[i]);
        if (++_state[12] == 0) throw new CryptographicException("ChaCha20 block counter overflow.");
        _used = 0;
    }

    private static void Qr(uint[] x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }

    public void Dispose()
    {
        Array.Clear(_state);
        Array.Clear(_work);
        CryptographicOperations.ZeroMemory(_block);
    }
}

/// <summary>Salsa20/20 (256-bit key, 64-bit nonce, 64-bit counter) – the inner-stream cipher of KDBX 3.x files.</summary>
internal sealed class KdbxSalsa20 : IKdbxKeyStream
{
    private readonly uint[] _state = new uint[16];
    private readonly uint[] _work = new uint[16];
    private readonly byte[] _block = new byte[64];
    private int _used = 64;

    public KdbxSalsa20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != 32) throw new ArgumentException("Salsa20 needs a 32-byte key.", nameof(key));
        if (nonce.Length != 8) throw new ArgumentException("Salsa20 needs an 8-byte nonce.", nameof(nonce));
        Span<uint> k = stackalloc uint[8];
        for (int i = 0; i < 8; i++) k[i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        _state[0] = 0x61707865;
        _state[1] = k[0]; _state[2] = k[1]; _state[3] = k[2]; _state[4] = k[3];
        _state[5] = 0x3320646e;
        _state[6] = BinaryPrimitives.ReadUInt32LittleEndian(nonce);
        _state[7] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[4..]);
        _state[8] = 0; _state[9] = 0; // 64-bit block counter
        _state[10] = 0x79622d32;
        _state[11] = k[4]; _state[12] = k[5]; _state[13] = k[6]; _state[14] = k[7];
        k.Clear();
        _state[15] = 0x6b206574;
    }

    public void Xor(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (_used == 64) NextBlock();
            data[i] ^= _block[_used++];
        }
    }

    private void NextBlock()
    {
        var x = _work;
        Array.Copy(_state, x, 16);
        for (int i = 0; i < 10; i++)
        {
            // column round
            x[4] ^= BitOperations.RotateLeft(x[0] + x[12], 7);  x[8] ^= BitOperations.RotateLeft(x[4] + x[0], 9);
            x[12] ^= BitOperations.RotateLeft(x[8] + x[4], 13); x[0] ^= BitOperations.RotateLeft(x[12] + x[8], 18);
            x[9] ^= BitOperations.RotateLeft(x[5] + x[1], 7);   x[13] ^= BitOperations.RotateLeft(x[9] + x[5], 9);
            x[1] ^= BitOperations.RotateLeft(x[13] + x[9], 13); x[5] ^= BitOperations.RotateLeft(x[1] + x[13], 18);
            x[14] ^= BitOperations.RotateLeft(x[10] + x[6], 7); x[2] ^= BitOperations.RotateLeft(x[14] + x[10], 9);
            x[6] ^= BitOperations.RotateLeft(x[2] + x[14], 13); x[10] ^= BitOperations.RotateLeft(x[6] + x[2], 18);
            x[3] ^= BitOperations.RotateLeft(x[15] + x[11], 7); x[7] ^= BitOperations.RotateLeft(x[3] + x[15], 9);
            x[11] ^= BitOperations.RotateLeft(x[7] + x[3], 13); x[15] ^= BitOperations.RotateLeft(x[11] + x[7], 18);
            // row round
            x[1] ^= BitOperations.RotateLeft(x[0] + x[3], 7);   x[2] ^= BitOperations.RotateLeft(x[1] + x[0], 9);
            x[3] ^= BitOperations.RotateLeft(x[2] + x[1], 13);  x[0] ^= BitOperations.RotateLeft(x[3] + x[2], 18);
            x[6] ^= BitOperations.RotateLeft(x[5] + x[4], 7);   x[7] ^= BitOperations.RotateLeft(x[6] + x[5], 9);
            x[4] ^= BitOperations.RotateLeft(x[7] + x[6], 13);  x[5] ^= BitOperations.RotateLeft(x[4] + x[7], 18);
            x[11] ^= BitOperations.RotateLeft(x[10] + x[9], 7); x[8] ^= BitOperations.RotateLeft(x[11] + x[10], 9);
            x[9] ^= BitOperations.RotateLeft(x[8] + x[11], 13); x[10] ^= BitOperations.RotateLeft(x[9] + x[8], 18);
            x[12] ^= BitOperations.RotateLeft(x[15] + x[14], 7); x[13] ^= BitOperations.RotateLeft(x[12] + x[15], 9);
            x[14] ^= BitOperations.RotateLeft(x[13] + x[12], 13); x[15] ^= BitOperations.RotateLeft(x[14] + x[13], 18);
        }
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(_block.AsSpan(4 * i), x[i] + _state[i]);
        if (++_state[8] == 0) _state[9]++;
        _used = 0;
    }

    public void Dispose()
    {
        Array.Clear(_state);
        Array.Clear(_work);
        CryptographicOperations.ZeroMemory(_block);
    }
}
