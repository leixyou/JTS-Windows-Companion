using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.Windows.Elevation;

public static class NamedPipePeerProcess
{
    public static int GetClientProcessId(NamedPipeServerStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Named-pipe peer process discovery is available only on Windows.");
        }

        return GetClientProcessIdWindows(stream);
    }

    public static int GetServerProcessId(NamedPipeClientStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Named-pipe peer process discovery is available only on Windows.");
        }

        return GetServerProcessIdWindows(stream);
    }

    [SupportedOSPlatform("windows")]
    private static int GetClientProcessIdWindows(NamedPipeServerStream stream)
    {
        if (!GetNamedPipeClientProcessId(stream.SafePipeHandle, out var processId))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return checked((int)processId);
    }

    [SupportedOSPlatform("windows")]
    private static int GetServerProcessIdWindows(NamedPipeClientStream stream)
    {
        if (!GetNamedPipeServerProcessId(stream.SafePipeHandle, out var processId))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return checked((int)processId);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        Microsoft.Win32.SafeHandles.SafePipeHandle pipe,
        out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        Microsoft.Win32.SafeHandles.SafePipeHandle pipe,
        out uint serverProcessId);
}
