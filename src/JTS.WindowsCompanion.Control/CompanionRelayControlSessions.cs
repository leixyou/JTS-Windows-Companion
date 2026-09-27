using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control;

public sealed partial class CompanionRelayControlService
{
    private async Task AcceptOfferAsync(RelayChannelOffer offer, CancellationToken token)
    {
        var now = _clock.GetUtcNow();
        offer.Binding.Validate();
        if (offer.Binding.CompanionDeviceId != _connector.DeviceId)
            throw new ControlProtocolException("CONTROL_COMPANION_IDENTITY_REQUIRED");
        if (!_connector.Supports(offer.Binding.Lane) || offer.ExpiresAt <= now) return;
        if (offer.ExpiresAt > now.AddSeconds(65)) throw new ControlProtocolException("CONTROL_RELAY_OFFER_INVALID");
        lock (_gate)
        {
            foreach (var id in _attempted.Where(p => p.Value <= now).Select(p => p.Key).ToArray()) _attempted.Remove(id);
            if (_revoked.Contains(offer.Binding.ControllerDeviceId) || _attempted.ContainsKey(offer.Binding.SessionId)
                || _active.ContainsKey(offer.Binding.SessionId) || _attempted.Count >= 512
                || _active.Count >= 16 || _active.Values.Count(c => c.Owner == offer.Binding.ControllerDeviceId) >= 4
                || (offer.Binding.Lane == RelayLane.Rdp && _active.Values.Any(c => c.Owner == offer.Binding.ControllerDeviceId && c.Lane == RelayLane.Rdp))) return;
            _attempted.Add(offer.Binding.SessionId, now.AddSeconds(65)); // Only IDs/expiry, never ticket material.
        }
        var pairing = await PairingBoundControlGrants.ReadPairingAsync(_pairings, offer.Binding.ControllerDeviceId, _clock, token).ConfigureAwait(false);
        if (pairing is null || !pairing.Trust.Allows(offer.Binding.Lane)) return;
        ActiveConnection connection;
        lock (_gate)
        {
            token.ThrowIfCancellationRequested();
            if (_revoked.Contains(offer.Binding.ControllerDeviceId)) return;
            connection = new(pairing, token, _clock, offer.Binding.Lane);
            _active.Add(offer.Binding.SessionId, connection);
        }
        _ = ServeOfferAsync(offer, connection); // This method always observes errors and completes its tracked drain handle.
    }

    private async Task ServeOfferAsync(RelayChannelOffer offer, ActiveConnection connection)
    {
        try { await _connector.ServeAsync(_host, offer, connection.Pairing.Trust, connection.Cancel.Token).ConfigureAwait(false); }
        catch (Exception)
        {
            if (!connection.Cancel.IsCancellationRequested) Volatile.Write(ref _lastSessionError, "CONTROL_RELAY_SESSION_FAILED");
            // Peer/channel failures are isolated; no raw exception or bearer data is logged.
        }
        finally
        {
            lock (_gate) _active.Remove(offer.Binding.SessionId);
            connection.Dispose(); connection.Finished.TrySetResult();
        }
    }

    private async Task ReconcilePairingsAsync(CancellationToken token)
    {
        ActiveConnection[] active;
        lock (_gate) active = _active.Values.ToArray();
        foreach (var group in active.GroupBy(c => c.Owner, StringComparer.Ordinal))
        {
            var current = await PairingBoundControlGrants.ReadPairingAsync(_pairings, group.Key, _clock, token).ConfigureAwait(false);
            if (current is null || group.Any(c => !c.Pairing.SamePolicy(current)))
                StopPeer(group.Key);
        }
    }

    private void StopPeer(string owner)
    {
        ActiveConnection[] active;
        lock (_gate)
        {
            if (!_revoked.Contains(owner) && _revoked.Count >= 4096)
            { _stop.Cancel(); throw new ControlProtocolException("CONTROL_PAIRING_CAPACITY"); }
            _revoked.Add(owner); active = _active.Values.Where(c => c.Owner == owner).ToArray();
        }
        try { _host.RevokePeer(owner); }
        finally
        {
            foreach (var connection in active)
                try { connection.Cancel.Cancel(); } catch (ObjectDisposedException) { }
        }
    }

    private sealed class ActiveConnection : IDisposable
    {
        internal ControlRelayPairing Pairing { get; }
        internal RelayLane Lane { get; }
        internal string Owner => Pairing.Trust.DeviceId;
        internal CancellationTokenSource Cancel { get; }
        internal TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly CancellationTokenSource _lease;
        internal ActiveConnection(ControlRelayPairing pairing, CancellationToken parent, TimeProvider clock, RelayLane lane)
        {
            Pairing = pairing; Lane = lane;
            var remaining = pairing.ExpiresAt - clock.GetUtcNow();
            _lease = new(remaining <= TimeSpan.Zero ? TimeSpan.Zero : remaining < TimeSpan.FromDays(1) ? remaining : TimeSpan.FromDays(1), clock);
            Cancel = CancellationTokenSource.CreateLinkedTokenSource(parent, _lease.Token);
        }
        public void Dispose() { Cancel.Dispose(); _lease.Dispose(); }
    }
}
