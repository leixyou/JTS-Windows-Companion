using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal static class InstallationScmNative
{
    internal const uint AllAccess = 0x000F01FF;
    [StructLayout(LayoutKind.Sequential)] internal struct Configuration
    {
        internal uint Type, StartType, ErrorControl;
        internal IntPtr BinaryPath, LoadGroup;
        internal uint Tag;
        internal IntPtr Dependencies, Account, DisplayName;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Status
    { internal uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint, Pid, Flags; }
    [StructLayout(LayoutKind.Sequential)] internal struct FailureActions
    { internal uint Reset; internal IntPtr Reboot, Command; internal uint Count; internal IntPtr Actions; }
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern InstallationServiceHandle OpenManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern InstallationServiceHandle OpenService(InstallationServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", EntryPoint = "CreateServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern InstallationServiceHandle CreateService(InstallationServiceHandle manager, string name,
        string displayName, uint access, uint type, uint start, uint errorControl, string command,
        string? group, IntPtr tag, string? dependencies, string account, IntPtr password);
    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeConfiguration(InstallationServiceHandle service, uint type, uint start, uint errorControl,
        string? command, string? group, IntPtr tag, string? dependencies, string? account, IntPtr password, string? displayName);
    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ChangeOptional(InstallationServiceHandle service, int kind, IntPtr value);
    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryConfiguration(InstallationServiceHandle service, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryOptional(InstallationServiceHandle service, int kind, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceObjectSecurity(InstallationServiceHandle service, uint parts, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceStatusEx(InstallationServiceHandle service, int kind, out Status status, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartService(InstallationServiceHandle service, int count, IntPtr arguments);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteService(InstallationServiceHandle service);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll")]
    internal static extern uint SetSecurityInfo(InstallationServiceHandle service, int type, uint parts,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    internal static void Require(bool success, string code = "INSTALL_SERVICE_NATIVE_FAILED")
    { if (!success) throw new UnattendedInstallationException(code); }
}

[SupportedOSPlatform("windows")]
internal sealed class InstallationServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private InstallationServiceHandle() : base(true) { }
    protected override bool ReleaseHandle() => InstallationScmNative.CloseServiceHandle(handle);
}

internal sealed class InstallationScmBuffer(int length) : IDisposable
{
    internal int Length { get; } = length;
    internal IntPtr Pointer { get; } = Marshal.AllocHGlobal(length);
    internal T Read<T>() where T : struct
    {
        if (Marshal.SizeOf<T>() > Length) throw new UnattendedInstallationException("INSTALL_SERVICE_DATA_INVALID");
        return Marshal.PtrToStructure<T>(Pointer);
    }
    internal string String(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return string.Empty;
        var offset = pointer.ToInt64() - Pointer.ToInt64();
        if (offset < 0 || offset > Length - 2 || offset % 2 != 0)
            throw new UnattendedInstallationException("INSTALL_SERVICE_DATA_INVALID");
        var chars = new List<char>();
        for (var i = (int)offset; i <= Length - 2; i += 2)
        {
            var character = (char)Marshal.ReadInt16(Pointer, i);
            if (character == '\0') return new string(chars.ToArray());
            chars.Add(character);
        }
        throw new UnattendedInstallationException("INSTALL_SERVICE_DATA_INVALID");
    }
    internal string[] MultiString(IntPtr pointer)
    {
        var values = new List<string>();
        while (pointer != IntPtr.Zero)
        {
            var value = String(pointer);
            if (value.Length == 0) return values.ToArray();
            if (values.Count == 32) throw new UnattendedInstallationException("INSTALL_SERVICE_DATA_INVALID");
            values.Add(value); pointer += checked((value.Length + 1) * 2);
        }
        return values.ToArray();
    }
    public void Dispose() => Marshal.FreeHGlobal(Pointer);
}
