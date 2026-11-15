using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Phrasia;
/// <summary>Thrown when the master password (or PIM, or device binding) does not unlock the vault.</summary>
public sealed class WrongPasswordException : Exception
{
    /// <summary>Creates the exception with a generic "wrong master password" message.</summary>
    public WrongPasswordException() : base("Wrong master password.") { }
}
