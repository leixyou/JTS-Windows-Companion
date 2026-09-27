namespace JTS.WindowsCompanion.Control;

public sealed partial class CompanionRelayControlService
{
    public async ValueTask DrainRevokedPeerAsync(string owner, CancellationToken token = default)
    {
        await _pairingLifecycle.WaitAsync(token).ConfigureAwait(false);
        try
        {
            Task[] sessions;
            lock (_gate)
            {
                if (!PeerAwaitingActivation(owner)) throw new ControlProtocolException("CONTROL_PAIRING_NOT_REVOKED");
                sessions = _active.Values.Where(c => c.Owner == owner).Select(c => c.Finished.Task).ToArray();
            }
            await Task.WhenAll(sessions).WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
            await _host.DrainRevokedPeerAsync(owner, token).ConfigureAwait(false);
        }
        finally { _pairingLifecycle.Release(); }
    }
}
