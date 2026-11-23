using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace Phrasia;

/// <summary>
/// File writes that survive a crash or power loss. A plain File.WriteAllBytes + File.Move can leave an empty or
/// partly written file after a power cut, because Windows may persist the rename before the data. Here the data
/// is flushed to the disk first and the rename itself is done write-through.
/// </summary>
internal static class DurableFile
{
    /// <summary>Writes <paramref name="data"/> to <paramref name="path"/> and flushes it to the disk before returning.</summary>
    public static void WriteAllBytes(string path, ReadOnlySpan<byte> data)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        fs.Write(data);
        fs.Flush(flushToDisk: true);
    }

    /// <summary>Atomically replaces <paramref name="path"/> with <paramref name="data"/>: writes and flushes a temp file
    /// (<paramref name="path"/>.tmp), then renames it over the target write-through.</summary>
    public static void ReplaceAtomically(string path, ReadOnlySpan<byte> data)
    {
        var tmp = path + ".tmp";
        WriteAllBytes(tmp, data);
        Move(tmp, path);
    }

    /// <summary>Renames <paramref name="source"/> over <paramref name="destination"/> and waits until the rename is on the disk.</summary>
    public static void Move(string source, string destination)
    {
        if (!MoveFileEx(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            int error = Marshal.GetLastWin32Error();
            throw new IOException($"Could not replace '{Path.GetFileName(destination)}': {new Win32Exception(error).Message}",
                error);
        }
    }

    private const uint MOVEFILE_REPLACE_EXISTING = 0x1, MOVEFILE_WRITE_THROUGH = 0x8;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "MoveFileExW")]
    private static extern bool MoveFileEx(string existingFileName, string newFileName, uint flags);
}
