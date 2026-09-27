using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.Windows.Managed;

public static class SecureManagedServicePipe
{
    public static NamedPipeServerStream CreateServer(string pipeName, string allowedClientSid)
    {
        Validate(pipeName, allowedClientSid);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Managed service pipes are available only on Windows.");
        }

        return CreateServerWindows(pipeName, allowedClientSid);
    }

    public static bool IsExpectedClient(
        NamedPipeServerStream pipe,
        string allowedClientSid)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        Validate("validation", allowedClientSid);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Managed service client validation is available only on Windows.");
        }

        return IsExpectedClientWindows(pipe, allowedClientSid);
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateServerWindows(string pipeName, string allowedClientSid)
    {
        // Protected DACL: LocalSystem has full access; the configured interactive user has read/write.
        // No Administrators or Everyone ACE is inherited, and remote named-pipe clients are rejected.
        var sddl = $"D:P(A;;GA;;;SY)(A;;GRGW;;;{allowedClientSid})";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl,
                1,
                out var securityDescriptor,
                out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = securityDescriptor,
                InheritHandle = false,
            };
            var handle = CreateNamedPipe(
                $"\\\\.\\pipe\\{pipeName}",
                0x00000003 | 0x00080000 | 0x40000000,
                0x00000008,
                1,
                64 * 1024,
                64 * 1024,
                0,
                ref attributes);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }

            try
            {
                return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsExpectedClientWindows(NamedPipeServerStream pipe, string allowedClientSid)
    {
        string? actualSid = null;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            actualSid = identity.User?.Value;
        });
        return string.Equals(actualSid, allowedClientSid, StringComparison.OrdinalIgnoreCase);
    }

    private static void Validate(string pipeName, string sid)
    {
        if (string.IsNullOrWhiteSpace(pipeName)
            || pipeName.Length > 128
            || !pipeName.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_')
            || string.IsNullOrWhiteSpace(sid)
            || sid.Length > 184
            || !sid.StartsWith("S-1-", StringComparison.Ordinal)
            || sid.Any(character => !char.IsAsciiDigit(character) && character != '-'))
        {
            throw new ArgumentException("The managed service pipe name or client SID is invalid.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSDRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maximumInstances,
        uint outputBufferSize,
        uint inputBufferSize,
        uint defaultTimeout,
        ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
