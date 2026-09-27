namespace JTS.WindowsCompanion.Control;

public sealed partial class CompanionControlHost
{
    public async ValueTask DrainRevokedPeerAsync(string owner, CancellationToken token = default)
    {
        Task[] sessions;
        lock (_gate)
        {
            RequireRunning();
            if (!PeerBlocked(owner)) throw new ControlProtocolException("CONTROL_PAIRING_NOT_REVOKED");
            sessions = _connections.Values.Where(c => c.Owner == owner).Select(c => c.Finished.Task).ToArray();
        }
        await Task.WhenAll(sessions).WaitAsync(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
        await _runtime.DrainRevokedOwnerAsync(owner, token).ConfigureAwait(false);
    }
}
