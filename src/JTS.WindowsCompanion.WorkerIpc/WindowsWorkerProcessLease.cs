using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.WorkerIpc;

/// <summary>Authority-owned kernel job. The launcher must supply trusted start evidence for its waiting, one-shot Worker.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsWorkerProcessLease : IDisposable, IWorkerSupervisor
{
    internal VerifiedWindowsProcess Worker { get; }
    private readonly SafeFileHandle _job;
    private bool _stopped;
    private WindowsWorkerProcessLease(VerifiedWindowsProcess worker, SafeFileHandle job) => (Worker, _job) = (worker, job);

    /// <summary>SCM supplies the PID; image/SID come from a verified install, and a held process supplies creation time.</summary>
    public static WindowsWorkerProcessLease AttachNewServiceProcess(uint scmPid, long startedNotBefore,
        string expectedSid, string expectedImage, string expectedSha256)
    {
        using var observed = new VerifiedWindowsProcess(scmPid, 0x101);
        if (observed.Identity.StartedFileTime < startedNotBefore || observed.Identity.AccountSid != expectedSid
            || observed.Identity.ImageSha256 != expectedSha256
            || !string.Equals(Path.GetFullPath(observed.Identity.ImagePath), Path.GetFullPath(expectedImage), StringComparison.OrdinalIgnoreCase))
            throw new JobExecutionStateUnknownException();
        return Attach(observed.Identity);
    }

    public static WindowsWorkerProcessLease Attach(WindowsProcessIdentity trustedLaunchIdentity)
    {
        var worker = new VerifiedWindowsProcess(trustedLaunchIdentity.ProcessId, 0x101, trustedLaunchIdentity);
        var job = WindowsIpcNative.CreateJobObject(IntPtr.Zero, IntPtr.Zero);
        try
        {
            WindowsIpcNative.Require(!job.IsInvalid);
            var limits = new WindowsIpcNative.ExtendedLimit { Basic = new WindowsIpcNative.BasicLimit { Flags = 0x2000 } };
            WindowsIpcNative.Require(WindowsIpcNative.SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<WindowsIpcNative.ExtendedLimit>()));
            WindowsIpcNative.Require(WindowsIpcNative.AssignProcessToJobObject(job, worker.Handle));
            // Only now may the authority send the first Execute frame. No script is provided to the launcher.
            return new WindowsWorkerProcessLease(worker, job);
        }
        catch
        {
            job.Dispose(); worker.Dispose();
            // Caller must independently clean up a failed launch; never infer that attachment failure stopped it.
            throw new JobExecutionStateUnknownException();
        }
    }
    public async Task StopAndConfirmAsync()
    {
        if (_stopped) return;
        try
        {
            WindowsIpcNative.Require(WindowsIpcNative.TerminateJobObject(_job, 1));
            var deadline = Stopwatch.StartNew();
            while (true)
            {
                WindowsIpcNative.Require(WindowsIpcNative.QueryInformationJobObject(_job, 1, out var state,
                    (uint)Marshal.SizeOf<WindowsIpcNative.Accounting>(), IntPtr.Zero));
                if (state.ActiveProcesses == 0) { _stopped = true; return; }
                if (deadline.Elapsed >= TimeSpan.FromSeconds(3)) throw new JobExecutionStateUnknownException();
                await Task.Delay(25).ConfigureAwait(false);
            }
        }
        catch { throw new JobExecutionStateUnknownException(); }
    }
    public void Dispose() { _job.Dispose(); Worker.Dispose(); }
}
