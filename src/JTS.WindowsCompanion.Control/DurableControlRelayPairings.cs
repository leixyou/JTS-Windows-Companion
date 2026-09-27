using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control;

/// <summary>Projects only locally approved Control trust/capability IDs from the independent device-pairing registry.</summary>
public sealed class DurableControlRelayPairings(DurableRelayPairingStore store) : IControlRelayPairings
{
    private readonly DurableRelayPairingStore _store = store ?? throw new ArgumentNullException(nameof(store));
    public string LocalDeviceId => _store.LocalDeviceId;
    public async ValueTask<ControlRelayPairing?> FindAsync(string controllerDeviceId, CancellationToken cancellationToken)
    {
        var policy = await _store.FindAsync(controllerDeviceId, cancellationToken).ConfigureAwait(false);
        return policy is not null && policy.AllowedLanes.Contains(RelayLane.Control)
            ? new(policy.PairingId, policy.PeerTrust, policy.ExpiresAt, policy.GrantsFor(RelayLane.Control)) : null;
    }
    public ValueTask RevokeAsync(string controllerDeviceId, Guid pairingId, CancellationToken cancellationToken)
        => _store.RevokeAsync(controllerDeviceId, pairingId, cancellationToken);
}
