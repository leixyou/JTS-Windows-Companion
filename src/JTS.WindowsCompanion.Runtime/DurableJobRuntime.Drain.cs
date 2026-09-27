namespace JTS.WindowsCompanion.Runtime;

public sealed partial class DurableJobRuntime
{
    /// <summary>Confirms cancellation completed, rather than merely that a cancellation signal was sent.</summary>
    public async ValueTask DrainRevokedOwnerAsync(string owner, CancellationToken token = default)
    {
        Task stopped;
        lock (_gate)
        {
            RequireRunning();
            if (!_revokedOwners.Contains(owner) || _readmittedGrants.ContainsKey(owner)) throw new JobRuntimeException("JOB_OWNER_NOT_REVOKED");
            stopped = _active?.Binding.OwnerDeviceId == owner ? _active.Finished.Task : Task.CompletedTask;
        }
        await stopped.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
        lock (_gate) RequireRunning(); // An executor whose stop became unknown must never get a successful receipt.
    }
}
