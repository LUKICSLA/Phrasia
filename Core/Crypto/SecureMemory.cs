using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Phrasia;

/// <summary>
/// Protection of sensitive data (keys) in memory at runtime.
///
/// What it can and cannot do – HONESTLY: this makes reading keys from memory harder, but is not 100% reliable.
///  - Keys live in a pinned array (the GC does not move them) and are zeroed after use.
///  - VirtualLock prevents the key's page from being paged to the swap file (pagefile.sys) on disk.
///  - A long-lived key is kept protected in memory (ProtectedKey) and decrypted only for one operation;
///    a memory dump of the idle process does not reveal it.
/// LIMITATION: passwords typed into WPF fields are .NET strings (immutable, GC-managed) – their copies may
/// linger in memory until the GC frees them; in a managed GUI app this cannot be fully eliminated.
/// </summary>
internal static class SecureMemory
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualLock(IntPtr addr, UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualUnlock(IntPtr addr, UIntPtr size);

    private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    /// <summary>Pinned array that is not paged to disk (VirtualLock). Best-effort – failure is harmless.</summary>
    public static byte[] AllocLocked(int size)
    {
        var buffer = GC.AllocateArray<byte>(size, pinned: true);
        TryLock(buffer);
        return buffer;
    }

    /// <summary>Best-effort VirtualLock of a pinned buffer so it is not paged to disk (Windows only).</summary>
    public static void TryLock(byte[] pinned)
    {
        if (!IsWindows) return;
        try
        {
            var addr = Marshal.UnsafeAddrOfPinnedArrayElement(pinned, 0);
            VirtualLock(addr, (UIntPtr)pinned.Length);
        }
        catch { /* best effort */ }
    }

    /// <summary>Zeroes the array and releases the page lock.</summary>
    public static void Wipe(byte[]? buffer)
    {
        if (buffer is null) return;
        CryptographicOperations.ZeroMemory(buffer);
        if (!IsWindows) return;
        try
        {
            var addr = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);
            VirtualUnlock(addr, (UIntPtr)buffer.Length);
        }
        catch { }
    }
}

/// <summary>
/// A long-lived key kept protected in memory: on Windows encrypted via DPAPI (ProtectedData, account key,
/// not in the process); otherwise masked with a one-time random mask held in a separate (locked) block.
/// It is decrypted only for one operation via <see cref="Use"/>; the copy is zeroed immediately after.
/// </summary>
internal sealed class ProtectedKey : IDisposable
{
    private readonly int _length;
    private readonly bool _dpapi;
    private byte[]? _blob;     // DPAPI blob, or (fallback) key XOR mask
    private byte[]? _mask;     // only in the fallback, otherwise null
    private readonly object _gate = new(); // serializes Use() with Dispose()
    private readonly byte[] _entropy;
    private bool _disposed;

    private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    public int Length => _length;

    /// <summary>Takes <paramref name="key"/> (zeroing it) and holds its protected form.</summary>
    public ProtectedKey(byte[] key)
    {
        _length = key.Length;
        _entropy = RandomNumberGenerator.GetBytes(16);

        byte[]? blob = null;
        bool ok = false;
        if (IsWindows)
        {
            try { blob = ProtectedData.Protect(key, _entropy, DataProtectionScope.CurrentUser); ok = true; }
            catch { ok = false; }
        }

        if (ok)
        {
            _dpapi = true;
            _blob = blob;
        }
        else
        {
            _dpapi = false;
            _mask = SecureMemory.AllocLocked(_length);
            RandomNumberGenerator.Fill(_mask);
            _blob = SecureMemory.AllocLocked(_length);
            for (int i = 0; i < _length; i++) _blob[i] = (byte)(key[i] ^ _mask[i]);
        }
        CryptographicOperations.ZeroMemory(key);
    }

    /// <summary>Temporarily restores the key, passes it to the action, and zeroes it immediately after. Serialized with <see cref="Dispose"/>, so the key cannot be wiped while it is in use (a disposed key throws <see cref="ObjectDisposedException"/>).</summary>
    public void Use(Action<byte[]> action)
    {
        lock (_gate) UseCore(action);
    }

    /// <summary>Use() implementation; the caller must hold <see cref="_gate"/>.</summary>
    private void UseCore(Action<byte[]> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var copy = SecureMemory.AllocLocked(_length);
        try
        {
            if (_dpapi)
            {
                var plain = ProtectedData.Unprotect(_blob!, _entropy, DataProtectionScope.CurrentUser);
                try { Array.Copy(plain, copy, _length); }
                finally { CryptographicOperations.ZeroMemory(plain); }
            }
            else
            {
                for (int i = 0; i < _length; i++) copy[i] = (byte)(_blob![i] ^ _mask![i]);
            }
            action(copy);
        }
        finally
        {
            SecureMemory.Wipe(copy);
        }
    }

    /// <summary>Constant-time comparison with another key (of the same length).</summary>
    public bool Equals(byte[] other)
    {
        bool eq = false;
        Use(k => eq = CryptographicOperations.FixedTimeEquals(k, other));
        return eq;
    }

    /// <summary>Wipes the protected key material (blob, mask, entropy) from memory.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            SecureMemory.Wipe(_blob);
            SecureMemory.Wipe(_mask);
            CryptographicOperations.ZeroMemory(_entropy);
        }
    }
}
