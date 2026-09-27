using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Runtime;

/// <summary>Windows current-user DPAPI only. Never silently switches to LocalMachine or plaintext.</summary>
public sealed class CurrentUserDpapiTaskProtector : ITaskPayloadProtector
{
    public CurrentUserDpapiTaskProtector()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Current-user Windows DPAPI is required.");
    }
    public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> purpose)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var copy = plaintext.ToArray();
        try { return ProtectedData.Protect(copy, purpose.ToArray(), DataProtectionScope.CurrentUser); }
        finally { CryptographicOperations.ZeroMemory(copy); }
    }
    public byte[] Unprotect(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> purpose)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return ProtectedData.Unprotect(ciphertext.ToArray(), purpose.ToArray(), DataProtectionScope.CurrentUser);
    }
}
