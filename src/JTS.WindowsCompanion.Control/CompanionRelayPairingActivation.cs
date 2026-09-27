namespace JTS.WindowsCompanion.Control;

public sealed partial class CompanionRelayControlService
{
    private readonly SemaphoreSlim _pairingLifecycle = new(1, 1);
    private readonly Dictionary<string, Guid> _activatedEpochs = new(StringComparer.Ordinal);

    /// <summary>Local enrollment only: activates the exact persisted epoch after old work drains. Never an RPC.</summary>
    public async ValueTask ActivatePairingAsync(string owner, Guid pairingId, CancellationToken token = default)
    {
        ControlPolicyCodec.Identity(owner, pairingId);
        await _pairingLifecycle.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var pairing = await PairingBoundControlGrants.ReadPairingAsync(_pairings, owner, _clock, token).ConfigureAwait(false);
            if (pairing is null || pairing.PairingId != pairingId) throw new ControlProtocolException("CONTROL_REBIND_REJECTED");
            Task[] stopped;
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                token.ThrowIfCancellationRequested(); _stop.Token.ThrowIfCancellationRequested();
                stopped = PairingAwaitingActivation(owner, pairingId)
                    ? _active.Values.Where(c => c.Owner == owner).Select(c => c.Finished.Task).ToArray() : [];
            }
            await Task.WhenAll(stopped).WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            await _host.ActivatePeerGrantsAsync(owner, pairing.ApprovedGrantIds, token).ConfigureAwait(false);
            var current = await PairingBoundControlGrants.ReadPairingAsync(_pairings, owner, _clock, token).ConfigureAwait(false);
            if (current is null || !pairing.SamePolicy(current)) throw new ControlProtocolException("CONTROL_REBIND_REJECTED");
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                token.ThrowIfCancellationRequested(); _stop.Token.ThrowIfCancellationRequested();
                if (_revoked.Contains(owner)) _activatedEpochs[owner] = pairingId;
            }
        }
        finally { _pairingLifecycle.Release(); }
    }

    private bool PeerAwaitingActivation(string owner) => _revoked.Contains(owner) && !_activatedEpochs.ContainsKey(owner);
    private bool PairingAwaitingActivation(string owner, Guid epoch) => _revoked.Contains(owner)
        && (!_activatedEpochs.TryGetValue(owner, out var active) || active != epoch);
}
