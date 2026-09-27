using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using JTS.WindowsCompanion.Elevation;

namespace JTS.WindowsCompanion.Windows.Security;

public sealed class WindowsProcessElevationVerifier : IProcessElevationVerifier
{
    public bool IsElevated
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            return IsElevatedWindows();
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsElevatedWindows()
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (token)
        {
            var elevation = new TokenElevation();
            if (!GetTokenInformation(
                    token,
                    20,
                    ref elevation,
                    Marshal.SizeOf<TokenElevation>(),
                    out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return elevation.TokenIsElevated != 0;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenElevation
    {
        public int TokenIsElevated;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        ref TokenElevation tokenInformation,
        int tokenInformationLength,
        out int returnLength);
}
