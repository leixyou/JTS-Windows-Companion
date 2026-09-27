using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.WorkerService;

[SupportedOSPlatform("windows")]
internal static class ScmNative
{
    [StructLayout(LayoutKind.Sequential)] internal struct Configuration
    {
        internal uint Type, StartType, ErrorControl;
        internal IntPtr BinaryPath, LoadGroup; internal uint Tag;
        internal IntPtr Dependencies, Account, DisplayName;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Status
    { internal uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint, Pid, Flags; }
    [StructLayout(LayoutKind.Sequential)] internal struct Recovery
    { internal uint Reset; internal IntPtr Reboot, Command; internal uint Count; internal IntPtr Actions; }
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern ServiceHandle OpenManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryConfig(ServiceHandle service, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryConfig2(ServiceHandle service, int kind, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceStatusEx(ServiceHandle service, int kind, out Status status, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceObjectSecurity(ServiceHandle service, uint info, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartService(ServiceHandle service, int count, IntPtr args);
    [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
    internal static extern uint GetNamedSecurityInfo(string path, int type, uint info, out IntPtr owner,
        out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] internal static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr pointer);
    internal static void Require(bool ok) { if (!ok) throw new WorkerServiceException("WORKER_SCM_QUERY_FAILED"); }
}

[SupportedOSPlatform("windows")]
internal sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private ServiceHandle() : base(true) { }
    protected override bool ReleaseHandle() => ScmNative.CloseServiceHandle(handle);
}

internal sealed class ScmBuffer(int size) : IDisposable
{
    internal IntPtr Pointer { get; } = Marshal.AllocHGlobal(size);
    internal int Size { get; } = size;
    internal T Structure<T>() where T : struct
    {
        if (Marshal.SizeOf<T>() > Size) throw new WorkerServiceException("WORKER_SCM_DATA_INVALID");
        return Marshal.PtrToStructure<T>(Pointer);
    }
    internal string String(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return string.Empty;
        var offset = pointer.ToInt64() - Pointer.ToInt64();
        if (offset < 0 || offset > Size - 2 || offset % 2 != 0) throw new WorkerServiceException("WORKER_SCM_DATA_INVALID");
        var chars = new List<char>();
        for (var i = (int)offset; i <= Size - 2; i += 2)
        {
            var c = (char)Marshal.ReadInt16(Pointer, i); if (c == '\0') return new string(chars.ToArray()); chars.Add(c);
        }
        throw new WorkerServiceException("WORKER_SCM_DATA_INVALID");
    }
    internal string[] MultiString(IntPtr pointer)
    {
        var values = new List<string>();
        while (pointer != IntPtr.Zero)
        {
            var value = String(pointer); if (value.Length == 0) return values.ToArray();
            if (values.Count >= 32) throw new WorkerServiceException("WORKER_SCM_DATA_INVALID");
            values.Add(value); pointer += (value.Length + 1) * 2;
        }
        return [];
    }
    public void Dispose() => Marshal.FreeHGlobal(Pointer);
}
