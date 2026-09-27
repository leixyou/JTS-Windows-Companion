using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal sealed class ProvisioningProcess : IDisposable
{
    private readonly SafeFileHandle _job = ProvisioningNative.CreateJobObject(IntPtr.Zero, IntPtr.Zero);
    private SafeFileHandle? _process, _thread;
    private bool _contained;

    internal void Start(SafeAccessTokenHandle token, string sid, string executable,
        string command, string environment, string desktop)
    {
        ProvisioningNative.Require(!_job.IsInvalid);
        var limits = new ProvisioningNative.ExtendedLimit
        { Basic = new ProvisioningNative.BasicLimit { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE; no breakaway.
        ProvisioningNative.Require(ProvisioningNative.SetInformationJobObject(_job, 9, ref limits,
            (uint)Marshal.SizeOf<ProvisioningNative.ExtendedLimit>()));
        using var attributes = new ProvisioningJobAttribute(_job.DangerousGetHandle());
        var desktopPointer = Marshal.StringToHGlobalUni(desktop);
        var environmentPointer = Marshal.StringToHGlobalUni(environment);
        try
        {
            var startup = new ProvisioningNative.StartupInfoEx
            {
                Info = new ProvisioningNative.StartupInfo
                { Size = (uint)Marshal.SizeOf<ProvisioningNative.StartupInfoEx>(), Desktop = desktopPointer },
                Attributes = attributes.Pointer,
            };
            // No LOGON_NETCREDENTIALS_ONLY, automatic profile unload, inherited handles or ambient cwd/env.
            // JOB_LIST associates the process inside creation, before any application code can execute.
            var info = ProvisioningPrivileges.Run(() =>
            {
                ProvisioningNative.Require(ProvisioningNative.CreateProcessWithToken(token, 0, executable,
                    new StringBuilder(command), 0x4 | 0x400 | 0x80000 | 0x08000000,
                    environmentPointer, Path.GetDirectoryName(executable)!, ref startup, out var created),
                    "PROVISION_PROCESS_CREATE_FAILED");
                return created;
            }, "SeImpersonatePrivilege");
            _process = new SafeFileHandle(info.Process, true); _thread = new SafeFileHandle(info.Thread, true);
            ProvisioningNative.Require(ProvisioningNative.IsProcessInJob(_process, _job, out _contained)
                && _contained, "PROVISION_PROCESS_CONTAINMENT_FAILED");
            ProvisioningToken.VerifyProcess(_process, sid);
            ProvisioningNative.Require(ProvisioningNative.ResumeThread(_thread) == 1, "PROVISION_PROCESS_RESUME_FAILED");
        }
        finally { Marshal.FreeHGlobal(environmentPointer); Marshal.FreeHGlobal(desktopPointer); }
    }

    internal async Task WaitAsync(CancellationToken cancellationToken)
    {
        if (_process is null) throw new UnattendedInstallationException("PROVISION_PROCESS_NOT_STARTED");
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = ProvisioningNative.WaitForSingleObject(_process, 0);
            if (result == 0) break;
            ProvisioningNative.Require(result == 258);
            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
        }
        ProvisioningNative.Require(ProvisioningNative.GetExitCodeProcess(_process, out var code));
        if (code != 0) throw new UnattendedInstallationException("PROVISION_PROCESS_FAILED");
        // The initializer is not an execution agent and is not allowed to leave detached children behind.
        if (ActiveCount() != 0) throw new UnattendedInstallationException("PROVISION_UNEXPECTED_CHILD_PROCESS");
    }

    internal async Task DrainAsync()
    {
        if (_process is null) return;
        try
        {
            if (!_contained)
            {
                // The initial thread has never been resumed if atomic containment verification failed.
                // Terminate that exact suspended process directly; it cannot have created descendants.
                ProvisioningNative.Require(ProvisioningNative.TerminateProcess(_process, 1));
                var unassigned = Stopwatch.StartNew();
                while (unassigned.Elapsed < ProvisioningLaunchPlan.DrainLimit)
                {
                    if (ProvisioningNative.WaitForSingleObject(_process, 0) == 0) return;
                    await Task.Delay(25).ConfigureAwait(false);
                }
                throw new UnattendedInstallationException("PROVISION_PROCESS_STOP_UNCONFIRMED");
            }
            if (ActiveCount() != 0)
                ProvisioningNative.Require(ProvisioningNative.TerminateJobObject(_job, 1));
            var elapsed = Stopwatch.StartNew();
            while (true)
            {
                if (ActiveCount() == 0 && ProvisioningNative.WaitForSingleObject(_process, 0) == 0) return;
                if (elapsed.Elapsed >= ProvisioningLaunchPlan.DrainLimit) break;
                await Task.Delay(25).ConfigureAwait(false);
            }
        }
        catch (Exception) { /* Every stop failure becomes the single non-rollbackable result below. */ }
        throw new UnattendedInstallationException("PROVISION_PROCESS_STOP_UNCONFIRMED");
    }

    private uint ActiveCount()
    {
        ProvisioningNative.Require(ProvisioningNative.QueryInformationJobObject(_job, 1, out var accounting,
            (uint)Marshal.SizeOf<ProvisioningNative.JobAccounting>(), IntPtr.Zero));
        return accounting.ActiveProcesses;
    }
    public void Dispose() { _job.Dispose(); _thread?.Dispose(); _process?.Dispose(); }
}

[SupportedOSPlatform("windows")]
internal sealed class ProvisioningJobAttribute : IDisposable
{
    internal IntPtr Pointer { get; private set; }
    private IntPtr _value;
    private bool _initialized;
    internal ProvisioningJobAttribute(IntPtr job)
    {
        nuint size = 0; ProvisioningNative.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
        ProvisioningNative.Require(size is > 0 and <= 1_048_576);
        Pointer = Marshal.AllocHGlobal(checked((nint)size));
        try
        {
            _value = Marshal.AllocHGlobal(IntPtr.Size);
            ProvisioningNative.Require(ProvisioningNative.InitializeProcThreadAttributeList(Pointer, 1, 0, ref size));
            _initialized = true; Marshal.WriteIntPtr(_value, job);
            ProvisioningNative.Require(ProvisioningNative.UpdateProcThreadAttribute(Pointer, 0, 0x0002000D,
                _value, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero));
        }
        catch { Dispose(); throw; }
    }
    public void Dispose()
    {
        if (_initialized) { ProvisioningNative.DeleteProcThreadAttributeList(Pointer); _initialized = false; }
        if (_value != IntPtr.Zero) { Marshal.FreeHGlobal(_value); _value = IntPtr.Zero; }
        if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; }
    }
}
