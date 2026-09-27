namespace JTS.WindowsCompanion.Runtime;

public sealed partial class DurableJobRuntime
{
    private readonly Dictionary<string, HashSet<Guid>> _readmittedGrants = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _ownerRevocationVersions = new(StringComparer.Ordinal);

    /// <summary>Trusted host only, after validating a newly persisted pairing. Old grants and cancelled jobs stay revoked.</summary>
    public async ValueTask ActivateOwnerGrantsAsync(string owner, IReadOnlyCollection<Guid> grants, CancellationToken token = default)
    {
        if (!JobBinding.IsHash(owner) || grants.Count is < 1 or > 64 || grants.Any(g => g == Guid.Empty)
            || grants.Distinct().Count() != grants.Count) throw new ArgumentException("An exact owner and new grants are required.");
        var accepted = grants.ToHashSet(); long version; Task stopped;
        lock (_gate)
        {
            RequireRunning();
            if (!_revokedOwners.Contains(owner)) return;
            if (accepted.Any(g => _revoked.Contains((owner, g)))) throw new JobRuntimeException("JOB_REBIND_REJECTED");
            if (_readmittedGrants.TryGetValue(owner, out var current) && current.SetEquals(accepted)) return;
            version = _ownerRevocationVersions[owner];
            stopped = _active?.Binding.OwnerDeviceId == owner ? _active.Finished.Task : Task.CompletedTask;
        }
        await stopped.WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
        lock (_gate)
        {
            RequireRunning(); token.ThrowIfCancellationRequested();
            if (_ownerRevocationVersions[owner] != version || accepted.Any(g => _revoked.Contains((owner, g))))
                throw new JobRuntimeException("JOB_REBIND_REJECTED");
            _readmittedGrants[owner] = accepted;
        }
    }

    private bool OwnerRejectsGrant(string owner, Guid grant) => _revokedOwners.Contains(owner)
        && (!_readmittedGrants.TryGetValue(owner, out var accepted) || !accepted.Contains(grant));
}
