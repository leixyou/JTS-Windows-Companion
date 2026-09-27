using JTS.WindowsCompanion.Runtime;
using JTS.WindowsCompanion.WorkerIpc;

namespace JTS.WindowsCompanion.WorkerService;

internal sealed record StartOutcome(bool Accepted, int Error);
internal interface IServiceProcessLease : IDisposable { Task StopAndConfirmAsync(); }
internal interface IServiceLaunchOperations<TLease> where TLease : IServiceProcessLease
{
    ServiceState ReadState();
    Task<StartOutcome> StartAsync(string[] publicArguments);
    TLease? TryAttach(uint pid, long startedNotBefore);
}

internal static class ServiceLaunchEngine
{
    // One fixed SCM service, shared by all launcher instances in the sole authority process.
    // Keep startup AND uncertain-start cleanup under the same gate so another request
    // cannot start a replacement process while the first request is still identifying it.
    private static readonly SemaphoreSlim LaunchGate = new(1, 1);
    internal static async ValueTask<TLease> LaunchAsync<TLease>(IServiceLaunchOperations<TLease> operations,
        WorkerLaunchDescriptor descriptor, CancellationToken token) where TLease : IServiceProcessLease
    {
        await LaunchGate.WaitAsync(token).ConfigureAwait(false);
        try { return await StartOnceAsync(operations, descriptor, token).ConfigureAwait(false); }
        finally { LaunchGate.Release(); }
    }

    private static async ValueTask<TLease> StartOnceAsync<TLease>(IServiceLaunchOperations<TLease> operations,
        WorkerLaunchDescriptor descriptor, CancellationToken token) where TLease : IServiceProcessLease
    {
        var arguments = WorkerLaunchArguments.Encode(descriptor);
        token.ThrowIfCancellationRequested();
        WorkerServicePolicy.RequireStopped(operations.ReadState()); // Never adopt or terminate a pre-existing Worker.
        var startedAfter = DateTime.UtcNow.ToFileTimeUtc();
        StartOutcome outcome;
        try
        {
            // StartService is a synchronous SCM RPC which can outlive caller cancellation. Observe its real outcome.
            outcome = await operations.StartAsync(arguments).ConfigureAwait(false);
        }
        catch
        {
            await CleanupAsync(operations, startedAfter).ConfigureAwait(false);
            throw new JobExecutionStateUnknownException();
        }
        if (!outcome.Accepted && outcome.Error is 2 or 3 or 5 or 6 or 1056 or 1058 or 1060 or 1068 or 1069 or 1072 or 1075)
            throw new WorkerServiceException("WORKER_SERVICE_NOT_STARTED"); // No ownership of another caller's service start.
        if (!outcome.Accepted)
        {
            await CleanupAsync(operations, startedAfter).ConfigureAwait(false);
            throw new JobExecutionStateUnknownException();
        }
        var stopOwnedByLease = false;
        try
        {
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(token);
            wait.CancelAfter(TimeSpan.FromSeconds(10));
            while (true)
            {
                wait.Token.ThrowIfCancellationRequested();
                var state = operations.ReadState();
                if (state.Type != 0x10 || state.Flags != 0 || state.State is not (2 or 4))
                    throw new WorkerServiceException("WORKER_SERVICE_START_FAILED");
                if (state.State == 4 && state.ProcessId != 0 && operations.TryAttach(state.ProcessId, startedAfter) is { } lease)
                {
                    if (wait.IsCancellationRequested)
                    {
                        stopOwnedByLease = true;
                        using (lease) await lease.StopAndConfirmAsync().ConfigureAwait(false);
                        wait.Token.ThrowIfCancellationRequested();
                    }
                    return lease;
                }
                await Task.Delay(50, wait.Token).ConfigureAwait(false);
            }
        }
        catch
        {
            if (!stopOwnedByLease && !await CleanupAsync(operations, startedAfter).ConfigureAwait(false)) throw new JobExecutionStateUnknownException();
            throw;
        }
    }
    private static async Task<bool> CleanupAsync<TLease>(IServiceLaunchOperations<TLease> operations, long startedAfter)
        where TLease : IServiceProcessLease
    {
        var started = System.Diagnostics.Stopwatch.StartNew();
        while (started.Elapsed < TimeSpan.FromSeconds(3))
        {
            try
            {
                var state = operations.ReadState();
                if (state.Type != 0x10 || state.Flags != 0 || state.State == 1) return false; // No proof of process drain from SCM state alone.
                if (state.State == 4 && state.ProcessId != 0 && operations.TryAttach(state.ProcessId, startedAfter) is { } lease)
                {
                    using (lease) await lease.StopAndConfirmAsync().ConfigureAwait(false);
                    return true;
                }
            }
            catch { return false; }
            await Task.Delay(50).ConfigureAwait(false);
        }
        return false;
    }
}
