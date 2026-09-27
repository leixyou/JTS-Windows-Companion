namespace JTS.WindowsCompanion.Control;

public sealed partial class CompanionControlHost
{
    private readonly Dictionary<string, HashSet<Guid>> _readmittedPeerGrants = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _peerRevocationVersions = new(StringComparer.Ordinal);

    internal async ValueTask ActivatePeerGrantsAsync(string owner, IReadOnlyCollection<Guid> grants, CancellationToken token)
    {
        if (grants.Count is < 1 or > 64 || grants.Distinct().Count() != grants.Count)
            throw new ControlProtocolException("CONTROL_REBIND_REJECTED");
        var accepted = grants.ToHashSet();
        long version; Task[] closed;
        lock (_gate)
        {
            RequireRunning();
            version = _peerRevocationVersions.GetValueOrDefault(owner);
            closed = _connections.Values.Where(c => c.Owner == owner).Select(c => c.Finished.Task).ToArray();
        }
        foreach (var id in accepted)
        {
            ControlPolicyCodec.Identity(owner, id);
            var grant = await _grants.FindAsync(owner, id, token).ConfigureAwait(false);
            if (grant is null || grant.OwnerDeviceId != owner || grant.GrantId != id || grant.ExpiresAt <= _clock.GetUtcNow())
                throw new ControlProtocolException("CONTROL_REBIND_REJECTED");
        }
        lock (_gate)
        {
            RequireRunning();
            if (_peerRevocationVersions.GetValueOrDefault(owner) != version) throw new ControlProtocolException("CONTROL_REBIND_REJECTED");
            if (!_revokedPeers.Contains(owner)) return;
            if (accepted.Any(g => _revoked.Contains((owner, g)))) throw new ControlProtocolException("CONTROL_REBIND_REJECTED");
            if (_readmittedPeerGrants.TryGetValue(owner, out var current) && current.SetEquals(accepted)) return;
        }
        await Task.WhenAll(closed).WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
        await _runtime.ActivateOwnerGrantsAsync(owner, accepted, token).ConfigureAwait(false);
        lock (_gate)
        {
            RequireRunning(); token.ThrowIfCancellationRequested();
            if (_peerRevocationVersions[owner] != version || accepted.Any(g => _revoked.Contains((owner, g))))
                throw new ControlProtocolException("CONTROL_REBIND_REJECTED");
            _readmittedPeerGrants[owner] = accepted;
        }
    }

    private bool PeerBlocked(string owner) => _revokedPeers.Contains(owner) && !_readmittedPeerGrants.ContainsKey(owner);
    private bool PeerGrantBlocked(string owner, Guid grant) => _revokedPeers.Contains(owner)
        && (!_readmittedPeerGrants.TryGetValue(owner, out var accepted) || !accepted.Contains(grant));
}
