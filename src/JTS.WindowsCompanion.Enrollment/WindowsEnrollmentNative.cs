using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using JTS.WindowsCompanion.WorkerService;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.Enrollment;

[SupportedOSPlatform("windows")]
internal static class WindowsEnrollmentNative
{
    internal const uint ClientAccess = 0x0012019B; // Deliberately excludes FILE_CREATE_PIPE_INSTANCE and ownership rights.
    internal static NamedPipeServerStream CreateServer(string authoritySid)
    {
        if (new SecurityIdentifier(authoritySid).Value != authoritySid) throw Denied();
        Require(ConvertSecurity($"D:P(A;;GA;;;{authoritySid})(A;;0x0012019B;;;BA)", 1, out var descriptor, out _));
        try
        {
            var attrs = new Attributes { Length = Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            var handle = CreateNamedPipe(@"\\.\pipe\" + EnrollmentManagementWire.PipeName, 3 | 0x40000000 | 0x00080000,
                8, 1, 8192, 8192, 0, ref attrs); // first instance, asynchronous, remote pipe clients rejected.
            if (handle.IsInvalid) { handle.Dispose(); throw Denied(); }
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        finally { LocalFree(descriptor); }
    }
    internal static void VerifyClient(NamedPipeServerStream pipe)
    {
        Require(GetClientProcessId(pipe.SafePipeHandle, out var pid)); Require(ProcessIdToSessionId(pid, out var processSession));
        // Identification-only impersonation is used solely to inspect the actual client token, never for authority work.
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent();
            var session = TokenInteger(identity.AccessToken, 12); var elevated = TokenInteger(identity.AccessToken, 20) != 0;
            EnrollmentCallerPolicy.Require(identity.User?.Value, identity.IsSystem,
                new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), elevated, session, checked((int)processSession));
        });
    }
    internal static async Task<NamedPipeClientStream> ConnectAsync(CancellationToken token)
    {
        // Identification SQOS prevents the local server from using the caller's elevated credentials.
        for (var n = 0; n < 40; n++)
        {
            token.ThrowIfCancellationRequested();
            var handle = OpenPipe(@"\\.\pipe\" + EnrollmentManagementWire.PipeName, ClientAccess, 0, IntPtr.Zero, 3,
                0x40000000 | 0x00110000, IntPtr.Zero);
            if (!handle.IsInvalid)
            {
                try { VerifyServer(handle); return new NamedPipeClientStream(PipeDirection.InOut, true, true, handle); }
                catch { handle.Dispose(); throw; }
            }
            var error = Marshal.GetLastWin32Error(); handle.Dispose();
            if (error is not (2 or 231)) throw Denied();
            await Task.Delay(100, token).ConfigureAwait(false);
        }
        throw new EnrollmentException("ENROLLMENT_SERVICE_UNAVAILABLE");
    }
    private static void VerifyServer(SafePipeHandle pipe)
    {
        Require(GetServerProcessId(pipe, out var pid));
        using var manager = OpenManager(null, null, 1); Require(!manager.IsInvalid);
        using var service = OpenService(manager, "JTSCompanionAuthority25", 4); Require(!service.IsInvalid);
        Require(QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _) && status.State == 4 && status.Pid == pid);
        using var process = OpenProcess(0x00101000, false, pid); Require(!process.IsInvalid && WaitForSingleObject(process, 0) == 258);
        var path = new StringBuilder(32768); var length = path.Capacity;
        Require(QueryImage(process, 0, path, ref length));
        using var image = WindowsServiceProgramTrust.Open(path.ToString(), CompanionServiceProgram.Authority);
        Require(QueryServiceStatusEx(service, 0, out var after, Marshal.SizeOf<ServiceStatus>(), out _) && after.State == 4 && after.Pid == pid
            && WaitForSingleObject(process, 0) == 258);
    }
    private static int TokenInteger(SafeAccessTokenHandle token, int type)
    { Require(GetTokenInformation(token, type, out var value, sizeof(int), out _)); return value; }
    private static EnrollmentException Denied() => new("ENROLLMENT_ACCESS_DENIED");
    private static void Require(bool result) { if (!result) throw Denied(); }
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { internal int Length; internal IntPtr Descriptor; internal int Inherit; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { internal uint Type, State, Controls, Exit, SpecificExit, Checkpoint, Hint, Pid, Flags; }
    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertSecurity(string text, uint revision, out IntPtr descriptor, out uint length);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint mode, uint instances, uint outputSize, uint inputSize, uint timeout, ref Attributes attributes);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle OpenPipe(string name, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetNamedPipeClientProcessId", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetClientProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", EntryPoint = "GetNamedPipeServerProcessId", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint pid, out uint session);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int type, out int value, int size, out int needed);
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int kind, out ServiceStatus status, int size, out int needed);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint timeout);
    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryImage(SafeProcessHandle process, uint flags, StringBuilder path, ref int size);
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    { private ServiceHandle() : base(true) { } protected override bool ReleaseHandle() => CloseServiceHandle(handle); }
}
