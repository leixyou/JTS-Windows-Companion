using System.Runtime.Versioning;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.WorkerIpc;

public sealed record WorkerLaunchDescriptor(Guid SessionId, WindowsProcessIdentity Authority, string WorkerSid);

/// <summary>Trusted local provisioning/launch integration, not an RPC-selected executable or account.</summary>
[SupportedOSPlatform("windows")]
public interface IWorkerProcessLauncher
{
    // Starts the verified waiting Worker under its configured standard account, attaches its outer job and returns the lease.
    // A failed launch must confirm cleanup or throw JobExecutionStateUnknownException. It must never retry execution implicitly.
    ValueTask<WindowsWorkerProcessLease> LaunchAsync(WorkerLaunchDescriptor descriptor, CancellationToken token);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsWorkerJobExecutor : IJobExecutor
{
    private readonly string _workerSid;
    private readonly IWorkerProcessLauncher _launcher;
    public WindowsWorkerJobExecutor(string workerSid, IWorkerProcessLauncher launcher)
    {
        VerifiedWindowsProcess.ValidateSid(workerSid);
        if (!workerSid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) throw new WorkerIpcException();
        _workerSid = workerSid; _launcher = launcher ?? throw new ArgumentNullException(nameof(launcher));
    }
    public async ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken token)
    {
        using var authority = new VerifiedWindowsProcess((uint)Environment.ProcessId, 0);
        if (authority.Identity.AccountSid == _workerSid) throw new WorkerIpcException();
        WindowsPeerProcessAccess.AllowCurrentPeer(_workerSid, supervision: false);
        var session = Guid.NewGuid();
        using var pipe = WindowsWorkerPipe.Create(session, authority.Identity.AccountSid, _workerSid);
        using var start = CancellationTokenSource.CreateLinkedTokenSource(token);
        start.CancelAfter(TimeSpan.FromSeconds(10));
        var accepting = pipe.WaitForConnectionAsync(start.Token);
        WindowsWorkerProcessLease? lease = null;
        var sessionOwnsStop = false;
        try
        {
            lease = await _launcher.LaunchAsync(new WorkerLaunchDescriptor(session, authority.Identity, _workerSid), start.Token).ConfigureAwait(false);
            if (lease.Worker.Identity.AccountSid != _workerSid) throw new WorkerIpcException();
            await accepting.ConfigureAwait(false);
            WindowsWorkerPipe.VerifyClient(pipe, lease.Worker);
            sessionOwnsStop = true;
            return await WorkerAuthoritySession.ExecuteAsync(pipe, session, lease, binding, payload, output, token).ConfigureAwait(false);
        }
        finally
        {
            start.Cancel(); pipe.Dispose();
            try { await accepting.ConfigureAwait(false); } catch (Exception) { }
            try { if (lease is not null && !sessionOwnsStop) await lease.StopAndConfirmAsync().ConfigureAwait(false); }
            finally { lease?.Dispose(); }
        }
    }
}

[SupportedOSPlatform("windows")]
public static class WindowsWorkerEndpoint
{
    public static async Task RunOnceAsync(WorkerLaunchDescriptor trustedLaunch, IJobExecutor executor, CancellationToken token = default)
    {
        using var self = new VerifiedWindowsProcess((uint)Environment.ProcessId, 0);
        if (self.Identity.AccountSid != trustedLaunch.WorkerSid || self.Identity.AccountSid == trustedLaunch.Authority.AccountSid)
            throw new WorkerIpcException();
        using var authority = new VerifiedWindowsProcess(trustedLaunch.Authority.ProcessId, 0, trustedLaunch.Authority);
        WindowsPeerProcessAccess.AllowCurrentPeer(trustedLaunch.Authority.AccountSid, supervision: true);
        using var pipe = WindowsWorkerPipe.Connect(trustedLaunch.SessionId, authority);
        await WorkerExecutionSession.RunOnceAsync(pipe, trustedLaunch.SessionId, executor, token).ConfigureAwait(false);
    }
}
