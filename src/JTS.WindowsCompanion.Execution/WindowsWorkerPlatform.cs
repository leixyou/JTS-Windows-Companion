using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Execution;

[SupportedOSPlatform("windows")]
internal sealed class WindowsWorkerPlatform(string expectedSid) : IWorkerExecutionPlatform
{
    public IWorkerProcess Start(string workingDirectory)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess) throw new PlatformNotSupportedException();
        WindowsWorkerToken.Verify(WindowsNative.GetCurrentProcess(), expectedSid);
        workingDirectory = WorkerWorkingDirectory.Resolve(workingDirectory, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        if (!PowerShellRequest.IsLocalDirectory(workingDirectory) || !Directory.Exists(workingDirectory))
            throw new InvalidOperationException("WORKER_DIRECTORY_REJECTED");
        var system = Environment.SystemDirectory;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var application = Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(application)) throw new InvalidOperationException("WORKER_POWERSHELL_UNAVAILABLE");
        var environment = PowerShellLaunchPlan.EnvironmentBlock(system, windows,
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        var process = new WindowsWorkerProcess();
        try
        {
            process.Create(application, environment, workingDirectory, expectedSid);
            return process;
        }
        catch
        {
            try { process.TerminateAndDrainAsync().GetAwaiter().GetResult(); }
            finally { process.Dispose(); }
            throw;
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsWorkerProcess : IWorkerProcess
{
    private readonly SafeFileHandle _job = WindowsNative.CreateJobObject(IntPtr.Zero, IntPtr.Zero);
    private SafeFileHandle? _process, _thread;
    private WindowsWorkerPipe? _input, _output, _error;
    private bool _drained, _resumed;
    public Stream Input => _input!.Parent;
    public Stream Output => _output!.Parent;
    public Stream Error => _error!.Parent;

    internal void Create(string application, string environment, string directory, string expectedSid)
    {
        WindowsNative.Require(!_job.IsInvalid);
        var limits = new WindowsNative.ExtendedLimit { Basic = new WindowsNative.BasicLimit { Flags = 0x2000 } };
        WindowsNative.Require(WindowsNative.SetInformationJobObject(_job, 9, ref limits, (uint)Marshal.SizeOf<WindowsNative.ExtendedLimit>()));
        _input = new WindowsWorkerPipe(PipeDirection.Out);
        _output = new WindowsWorkerPipe(PipeDirection.In);
        _error = new WindowsWorkerPipe(PipeDirection.In);
        var input = _input.Child.SafePipeHandle.DangerousGetHandle();
        var output = _output.Child.SafePipeHandle.DangerousGetHandle();
        var error = _error.Child.SafePipeHandle.DangerousGetHandle();
        using var attributes = new WindowsStartupAttributes(_job.DangerousGetHandle(), input, output, error);
        var startup = new WindowsNative.StartupInfoEx
        {
            Info = new WindowsNative.StartupInfo
            {
                Size = (uint)Marshal.SizeOf<WindowsNative.StartupInfoEx>(), Flags = 0x100,
                Input = input, Output = output, Error = error,
            },
            Attributes = attributes.Pointer,
        };
        var environmentPointer = Marshal.StringToHGlobalUni(environment);
        try
        {
            WindowsNative.Require(WindowsNative.CreateProcess(application,
                new StringBuilder('"' + application + "\" " + PowerShellLaunchPlan.Arguments),
                IntPtr.Zero, IntPtr.Zero, true, 0x00000004 | 0x00000400 | 0x00080000 | 0x08000000,
                environmentPointer, directory, ref startup, out var info));
            _process = new SafeFileHandle(info.Process, true); _thread = new SafeFileHandle(info.Thread, true);
        }
        finally
        {
            Marshal.FreeHGlobal(environmentPointer);
            // Only the child's inherited copies remain. EOF now reflects the actual process tree.
            _input.Child.Dispose(); _output.Child.Dispose(); _error.Child.Dispose();
        }
        WindowsWorkerToken.Verify(_process.DangerousGetHandle(), expectedSid);
    }
    public void Resume()
    {
        if (_resumed || _drained || _thread is null) throw new InvalidOperationException("WORKER_STATE_INVALID");
        if (WindowsNative.ResumeThread(_thread) != 1) throw new InvalidOperationException("WORKER_RESUME_FAILED");
        _resumed = true;
    }
    public async Task<uint> WaitForExitAsync(CancellationToken cancellationToken)
    {
        if (_process is null) throw new InvalidOperationException("WORKER_STATE_INVALID");
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var wait = WindowsNative.WaitForSingleObject(_process, 0);
            if (wait == 0) break;
            WindowsNative.Require(wait == 258);
            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
        }
        WindowsNative.Require(WindowsNative.GetExitCodeProcess(_process, out var code));
        return code;
    }
    public async Task TerminateAndDrainAsync()
    {
        if (_drained) return;
        if (_process is null) { _drained = true; return; }
        try
        {
            WindowsNative.Require(WindowsNative.TerminateJobObject(_job, 1));
            var timeout = Stopwatch.StartNew();
            while (true)
            {
                WindowsNative.Require(WindowsNative.QueryInformationJobObject(_job, 1, out var accounting,
                    (uint)Marshal.SizeOf<WindowsNative.JobAccounting>(), IntPtr.Zero));
                if (accounting.ActiveProcesses == 0) { _drained = true; return; }
                if (timeout.Elapsed >= TimeSpan.FromSeconds(3)) throw new JobExecutionStateUnknownException();
                await Task.Delay(25).ConfigureAwait(false);
            }
        }
        catch (Exception) { throw new JobExecutionStateUnknownException(); }
    }
    public void Dispose()
    {
        // Last-resort kernel kill remains in place even when explicit drain could not be attested.
        _job.Dispose(); _thread?.Dispose(); _process?.Dispose();
        _input?.Dispose(); _output?.Dispose(); _error?.Dispose();
    }
}
