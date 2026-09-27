using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Pairing;

/// <summary>Immutable local pairing epoch, separate from lane-specific capabilities and MCP-client consent.</summary>
public sealed class RelayDevicePairing
{
    public const int MaximumGrantIds = 4096;
    private readonly Dictionary<RelayLane, IReadOnlyList<Guid>> _grants = [];
    private readonly IReadOnlyList<RelayLane> _lanes;
    public Guid PairingId { get; }
    public string ControllerDeviceId { get; }
    public RelayTlsPolicy TlsPolicy { get; }
    public DateTimeOffset ExpiresAt { get; }
    public IReadOnlyList<RelayLane> AllowedLanes => _lanes;

    public RelayDevicePairing(Guid pairingId, string controllerDeviceId, RelayTlsPolicy tlsPolicy,
        DateTimeOffset expiresAt, IEnumerable<RelayLane> allowedLanes,
        IReadOnlyDictionary<RelayLane, IReadOnlyList<Guid>>? approvedGrantIds = null)
    {
        PairingValidation.Identity(controllerDeviceId, pairingId);
        ArgumentNullException.ThrowIfNull(allowedLanes);
        var lanes = allowedLanes.Take(4).ToArray();
        if (!Enum.IsDefined(tlsPolicy) || lanes.Length is < 1 or > 3 || lanes.Distinct().Count() != lanes.Length
            || lanes.Any(l => !Enum.IsDefined(l))) throw new ArgumentException("Explicit lanes and TLS policy are required.");
        if (approvedGrantIds is not null && (approvedGrantIds.Count > 3 || approvedGrantIds.Keys.Any(l => !lanes.Contains(l))))
            throw new ArgumentException("Grant IDs cannot enable an unpaired lane.");
        var seen = new HashSet<Guid>();
        foreach (var lane in lanes.Order())
        {
            var ids = approvedGrantIds is not null && approvedGrantIds.TryGetValue(lane, out var supplied) ? supplied : Array.Empty<Guid>();
            if (ids is null || ids.Count > MaximumGrantIds - seen.Count) throw new ArgumentException("Pairing grant capacity exceeded.");
            var copy = ids.ToArray();
            if (copy.Length > MaximumGrantIds - seen.Count) throw new ArgumentException("Pairing grant capacity exceeded.");
            if (copy.Any(id => id == Guid.Empty || !seen.Add(id))) throw new ArgumentException("Each capability identifier must be exact and lane-specific.");
            _grants.Add(lane, Array.AsReadOnly(copy.Order().ToArray()));
        }
        PairingId = pairingId; ControllerDeviceId = controllerDeviceId; TlsPolicy = tlsPolicy;
        ExpiresAt = DateTimeOffset.FromUnixTimeMilliseconds(expiresAt.ToUnixTimeMilliseconds());
        _lanes = Array.AsReadOnly(lanes.Order().ToArray());
    }

    public IReadOnlyList<Guid> GrantsFor(RelayLane lane) => _grants.GetValueOrDefault(lane) ?? Array.Empty<Guid>();
    public RelayPeerTrust PeerTrust => new(ControllerDeviceId, TlsPolicy, _lanes);
    internal bool SamePolicy(RelayDevicePairing other) => PairingId == other.PairingId && ControllerDeviceId == other.ControllerDeviceId
        && TlsPolicy == other.TlsPolicy && ExpiresAt == other.ExpiresAt && _lanes.SequenceEqual(other._lanes)
        && _lanes.All(l => GrantsFor(l).SequenceEqual(other.GrantsFor(l)));
}

public sealed record RelayPairingRecord(string ControllerDeviceId, Guid PairingId, RelayDevicePairing? Policy,
    DateTimeOffset? ApprovedAt, DateTimeOffset? RevokedAt);

public sealed class PairingStoreException(string code) : IOException(code)
{
    public string Code { get; } = code;
}

internal static class PairingValidation
{
    internal static void Identity(string deviceId, Guid id)
    {
        Device(deviceId);
        if (id == Guid.Empty) throw new PairingStoreException("PAIRING_IDENTITY_INVALID");
    }
    internal static void Device(string id)
    {
        if (id is not { Length: 64 } || id.Any(c => !"0123456789abcdef".Contains(c)))
            throw new PairingStoreException("PAIRING_IDENTITY_INVALID");
    }
    internal static PairingStoreException Invalid() => new("PAIRING_STORE_INVALID");
}
