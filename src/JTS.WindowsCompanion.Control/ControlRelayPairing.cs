using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control;

/// <summary>An immutable, locally confirmed pairing epoch. Relay admission must never create this record.</summary>
public sealed record ControlRelayPairing
{
    private readonly HashSet<Guid> _grants;
    public Guid PairingId { get; }
    public RelayPeerTrust Trust { get; }
    public DateTimeOffset ExpiresAt { get; }
    public ControlRelayPairing(Guid pairingId, RelayPeerTrust trust, DateTimeOffset expiresAt, IEnumerable<Guid>? approvedGrantIds = null)
    {
        ArgumentNullException.ThrowIfNull(trust);
        if (pairingId == Guid.Empty || !trust.Allows(RelayLane.Control)) throw new ArgumentException("An explicit control pairing is required.");
        _grants = approvedGrantIds?.ToHashSet() ?? [];
        if (_grants.Count > 4096 || _grants.Contains(Guid.Empty)) throw new ArgumentException("Invalid pairing/grant binding.");
        PairingId = pairingId; Trust = trust;
        ExpiresAt = DateTimeOffset.FromUnixTimeMilliseconds(expiresAt.ToUnixTimeMilliseconds());
    }
    public bool IncludesGrant(Guid grantId) => _grants.Contains(grantId);
    internal IReadOnlyCollection<Guid> ApprovedGrantIds => _grants.ToArray();
    internal bool SamePolicy(ControlRelayPairing other) => PairingId == other.PairingId && Trust.DeviceId == other.Trust.DeviceId
        && Trust.TlsPolicy == other.Trust.TlsPolicy && ExpiresAt == other.ExpiresAt && _grants.SetEquals(other._grants)
        && Enum.GetValues<RelayLane>().All(lane => Trust.Allows(lane) == other.Trust.Allows(lane));
}

/// <summary>Protected local pairing authority, separately persisted from capability grants and MCP approval.</summary>
public interface IControlRelayPairings
{
    string LocalDeviceId { get; }
    ValueTask<ControlRelayPairing?> FindAsync(string controllerDeviceId, CancellationToken cancellationToken);
    // Must durably revoke this exact epoch before returning; never a remote RPC or a best-effort notification.
    ValueTask RevokeAsync(string controllerDeviceId, Guid pairingId, CancellationToken cancellationToken);
}

internal sealed class PairingBoundControlGrants(IControlGrantProvider grants, IControlRelayPairings pairings,
    TimeProvider clock) : IDurableControlGrantProvider
{
    public async ValueTask<ControlGrant?> FindAsync(string owner, Guid id, CancellationToken token)
    {
        var pairing = await ReadPairingAsync(pairings, owner, clock, token).ConfigureAwait(false);
        if (pairing is null || !pairing.IncludesGrant(id)) return null;
        var grant = await grants.FindAsync(owner, id, token).ConfigureAwait(false);
        if (grant is null) return null;
        // A detached job cannot outlive its pairing, even if its capability grant lasts longer.
        return new(grant.OwnerDeviceId, grant.GrantId, grant.ExpiresAt < pairing.ExpiresAt ? grant.ExpiresAt : pairing.ExpiresAt,
            grant.Operations, grant.JobKinds, grant.AllowDisconnected);
    }
    public ValueTask RevokeAsync(string owner, Guid id, CancellationToken token)
        => grants is IDurableControlGrantProvider durable ? durable.RevokeAsync(owner, id, token)
            : ValueTask.FromException(new ControlProtocolException("CONTROL_DURABLE_REVOCATION_UNAVAILABLE"));

    internal static async Task<ControlRelayPairing?> ReadPairingAsync(IControlRelayPairings source, string owner,
        TimeProvider clock, CancellationToken token)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5), clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        try
        {
            var pairing = await source.FindAsync(owner, linked.Token).AsTask().WaitAsync(linked.Token).ConfigureAwait(false);
            if (pairing is null || pairing.ExpiresAt <= clock.GetUtcNow()) return null;
            if (pairing.Trust.DeviceId != owner) throw new ControlProtocolException("CONTROL_PAIRING_INVALID");
            return pairing;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch { throw new ControlProtocolException("CONTROL_PAIRING_UNAVAILABLE"); }
    }
}
