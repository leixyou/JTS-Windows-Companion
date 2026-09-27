using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.WorkerIpc;

[SupportedOSPlatform("windows")]
internal static class WindowsWorkerPipe
{
    // Specific rights, deliberately without FILE_CREATE_PIPE_INSTANCE (4) or WRITE_DAC/OWNER.
    internal const uint ClientAccess = 0x0012019B;
    internal static string Name(Guid session)
        => session != Guid.Empty ? @"\\.\pipe\JTS25Worker-" + session.ToString("N") : throw new WorkerIpcException();
    internal static NamedPipeServerStream Create(Guid session, string authoritySid, string workerSid)
    {
        VerifiedWindowsProcess.ValidateSid(authoritySid); VerifiedWindowsProcess.ValidateSid(workerSid);
        if (authoritySid == workerSid) throw new WorkerIpcException();
        var sddl = $"D:P(A;;GA;;;{authoritySid})(A;;0x0012019B;;;{workerSid})";
        WindowsIpcNative.Require(WindowsIpcNative.ConvertSecurity(sddl, 1, out var descriptor, out _));
        try
        {
            var security = new WindowsIpcNative.SecurityAttributes { Length = Marshal.SizeOf<WindowsIpcNative.SecurityAttributes>(), Descriptor = descriptor };
            var pipe = WindowsIpcNative.CreateNamedPipe(Name(session), 3 | 0x40000000 | 0x00080000,
                8, 1, 8192, 8192, 0, ref security); // duplex, overlapped, first instance, reject remote clients
            try { WindowsIpcNative.Require(!pipe.IsInvalid); return new NamedPipeServerStream(PipeDirection.InOut, true, false, pipe); }
            catch { pipe.Dispose(); throw; }
        }
        finally { WindowsIpcNative.LocalFree(descriptor); }
    }
    internal static NamedPipeClientStream Connect(Guid session, VerifiedWindowsProcess authority)
    {
        authority.RequireAlive();
        // Identification SQOS prevents a compromised server from impersonating the client account.
        var handle = WindowsIpcNative.OpenPipe(Name(session), ClientAccess, 0, IntPtr.Zero, 3, 0x40000000 | 0x00110000, IntPtr.Zero);
        try
        {
            WindowsIpcNative.Require(!handle.IsInvalid);
            WindowsIpcNative.Require(WindowsIpcNative.GetNamedPipeServerProcessId(handle, out var pid) && pid == authority.Identity.ProcessId);
            authority.RequireAlive();
            return new NamedPipeClientStream(PipeDirection.InOut, true, true, handle);
        }
        catch { handle.Dispose(); throw; }
    }
    internal static void VerifyClient(NamedPipeServerStream pipe, VerifiedWindowsProcess worker)
    {
        worker.RequireAlive();
        WindowsIpcNative.Require(WindowsIpcNative.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid) && pid == worker.Identity.ProcessId);
        worker.RequireAlive(); // Held process handle/start identity prevents PID reuse from becoming trust.
    }
}
