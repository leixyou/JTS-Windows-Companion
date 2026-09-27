using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.WorkerIpc;

/// <summary>Trusted local launch evidence. Never construct it from a message claimed by the pipe peer.</summary>
public sealed record WindowsProcessIdentity(uint ProcessId, long StartedFileTime, string AccountSid, string ImagePath, string ImageSha256);

[SupportedOSPlatform("windows")]
internal sealed class VerifiedWindowsProcess : IDisposable
{
    internal SafeFileHandle Handle { get; }
    internal WindowsProcessIdentity Identity { get; }
    private readonly FileStream _image;
    internal VerifiedWindowsProcess(uint pid, uint access, WindowsProcessIdentity? expected = null)
    {
        Handle = WindowsIpcNative.OpenProcess(access | 0x00101000, false, pid);
        FileStream? image = null;
        try
        {
            WindowsIpcNative.Require(!Handle.IsInvalid && WindowsIpcNative.WaitForSingleObject(Handle, 0) == 258);
            WindowsIpcNative.Require(WindowsIpcNative.GetProcessTimes(Handle, out var started, out _, out _, out _));
            var path = new StringBuilder(32768); var length = path.Capacity;
            WindowsIpcNative.Require(WindowsIpcNative.QueryImage(Handle, 0, path, ref length));
            var sid = ReadAccount(Handle);
            image = new FileStream(path.ToString(), FileMode.Open, FileAccess.Read, FileShare.Read);
            var hash = Convert.ToHexString(SHA256.HashData(image)).ToLowerInvariant();
            Identity = new WindowsProcessIdentity(pid, started, sid, path.ToString(), hash);
            if (expected is not null && (Identity.ProcessId != expected.ProcessId || Identity.StartedFileTime != expected.StartedFileTime
                || Identity.AccountSid != expected.AccountSid || Identity.ImageSha256 != expected.ImageSha256
                || !string.Equals(Path.GetFullPath(Identity.ImagePath), Path.GetFullPath(expected.ImagePath), StringComparison.OrdinalIgnoreCase)))
                throw new WorkerIpcException();
            _image = image;
        }
        catch { image?.Dispose(); Handle.Dispose(); throw; }
    }
    internal void RequireAlive() => WindowsIpcNative.Require(WindowsIpcNative.WaitForSingleObject(Handle, 0) == 258);
    internal static void ValidateSid(string sid)
    {
        if (new SecurityIdentifier(sid).Value != sid || sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") throw new WorkerIpcException();
        if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)) throw new WorkerIpcException();
    }
    private static string ReadAccount(SafeFileHandle process)
    {
        WindowsIpcNative.Require(WindowsIpcNative.OpenProcessToken(process, 8, out var token));
        using (token)
        {
            WindowsIpcNative.GetTokenInformation(token, 1, IntPtr.Zero, 0, out var length);
            if (length is < 8 or > 65536) throw new WorkerIpcException();
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                WindowsIpcNative.Require(WindowsIpcNative.GetTokenInformation(token, 1, buffer, length, out _));
                var sid = new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
                ValidateSid(sid);
                WindowsIpcNative.Require(WindowsIpcNative.GetTokenInformation(token, 20, buffer, length, out _));
                WindowsIpcNative.Require(Marshal.ReadInt32(buffer) == 0); // No elevated authority/Worker process.
                return sid;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
    public void Dispose() { _image.Dispose(); Handle.Dispose(); }
}
