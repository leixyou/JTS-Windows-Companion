using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using JTS.WindowsCompanion.WorkerIpc;

namespace JTS.WindowsCompanion.WorkerService;

/// <summary>Starts only the fixed, explicitly installed on-demand Worker service. No credentials or elevated process launcher.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsScmWorkerLauncher(WorkerServiceInstallation installation) : IWorkerProcessLauncher
{
    public async ValueTask<WindowsWorkerProcessLease> LaunchAsync(WorkerLaunchDescriptor descriptor, CancellationToken token)
    {
        if (descriptor.Authority.ProcessId != Environment.ProcessId || descriptor.WorkerSid != installation.AccountSid)
            throw new WorkerServiceException("WORKER_SERVICE_BINDING_REJECTED");
        token.ThrowIfCancellationRequested();
        // Existing project release trust is mandatory; Authenticode is not substituted or required here.
        using var executable = WindowsServiceProgramTrust.Open(installation.ExecutablePath, CompanionServiceProgram.Worker);
        var hash = Convert.ToHexString(SHA256.HashData(executable)).ToLowerInvariant();
        using var scm = new WindowsServiceInspection();
        WorkerServicePolicy.Validate(installation, descriptor.Authority.AccountSid, scm.ReadFacts(installation));
        var operations = new NativeOperations(scm, installation, hash);
        var lease = await ServiceLaunchEngine.LaunchAsync(operations, descriptor, token).ConfigureAwait(false);
        return lease.Native;
    }
    private sealed class NativeLease(WindowsWorkerProcessLease lease) : IServiceProcessLease
    {
        internal WindowsWorkerProcessLease Native { get; } = lease;
        public Task StopAndConfirmAsync() => Native.StopAndConfirmAsync();
        public void Dispose() => Native.Dispose();
    }
    private sealed class NativeOperations(WindowsServiceInspection scm, WorkerServiceInstallation installation, string imageHash)
        : IServiceLaunchOperations<NativeLease>
    {
        public ServiceState ReadState() => scm.ReadState();
        public Task<StartOutcome> StartAsync(string[] arguments) => Task.Run(() =>
        {
            var pointers = new List<IntPtr>(); var array = IntPtr.Zero;
            try
            {
                foreach (var value in arguments) pointers.Add(Marshal.StringToHGlobalUni(value));
                array = Marshal.AllocHGlobal(IntPtr.Size * pointers.Count);
                Marshal.Copy(pointers.ToArray(), 0, array, pointers.Count);
                var ok = ScmNative.StartService(scm.Service, pointers.Count, array);
                return new StartOutcome(ok, ok ? 0 : Marshal.GetLastWin32Error());
            }
            finally
            {
                if (array != IntPtr.Zero) Marshal.FreeHGlobal(array);
                foreach (var pointer in pointers) Marshal.FreeHGlobal(pointer);
            }
        }); // Intentionally not cancelled: a late SCM response must not spawn an unobserved orphan.
        public NativeLease? TryAttach(uint pid, long startedNotBefore)
        {
            try
            {
                return new NativeLease(WindowsWorkerProcessLease.AttachNewServiceProcess(pid, startedNotBefore,
                    installation.AccountSid, installation.ExecutablePath, imageHash));
            }
            catch (IOException) { return null; } // Waiting process may still be installing its narrowly scoped peer ACL.
        }
    }
}
