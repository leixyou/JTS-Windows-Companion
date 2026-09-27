using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control;

public enum ControlOperation { Status, Submit, Get, Cancel, Output }

/// <summary>Endpoint consent, loaded from a durable local provider; never relay admission or an RPC parameter.</summary>
public sealed class ControlGrant
{
    public string OwnerDeviceId { get; }
    public Guid GrantId { get; }
    public DateTimeOffset ExpiresAt { get; }
    public bool AllowDisconnected { get; }
    public IReadOnlyList<ControlOperation> Operations => _operations.Order().ToArray();
    public IReadOnlyList<string> JobKinds => _kinds.Order(StringComparer.Ordinal).ToArray();
    private readonly HashSet<ControlOperation> _operations;
    private readonly HashSet<string> _kinds;

    public ControlGrant(string ownerDeviceId, Guid grantId, DateTimeOffset expiresAt,
        IEnumerable<ControlOperation> operations, IEnumerable<string> jobKinds, bool allowDisconnected = false)
    {
        if (ownerDeviceId is not { Length: 64 } || ownerDeviceId.Any(c => !"0123456789abcdef".Contains(c)) || grantId == Guid.Empty)
            throw new ArgumentException("An exact device and grant are required.");
        _operations = operations.ToHashSet(); _kinds = jobKinds.ToHashSet(StringComparer.Ordinal);
        if (_operations.Count is 0 or > 5 || _operations.Any(o => !Enum.IsDefined(o)) || _kinds.Count > 32
            || _kinds.Any(k => k is not { Length: >= 1 and <= 64 } || k.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_'))))
            throw new ArgumentException("Invalid control permission bounds.");
        OwnerDeviceId = ownerDeviceId; GrantId = grantId;
        ExpiresAt = DateTimeOffset.FromUnixTimeMilliseconds(expiresAt.ToUnixTimeMilliseconds());
        AllowDisconnected = allowDisconnected;
    }

    internal bool Allows(ControlOperation operation) => _operations.Contains(operation);
    internal bool Allows(JobBinding binding) => binding.OwnerDeviceId == OwnerDeviceId && binding.GrantId == GrantId
        && Allows(ControlOperation.Submit) && _kinds.Contains(binding.Kind) && binding.Deadline <= ExpiresAt
        && (!binding.AllowDisconnected || AllowDisconnected);
    internal string[] CapabilityNames => _operations.Order().Select(ControlWire.Name).ToArray();
}

public interface IControlGrantProvider
{
    // Implementations must read the endpoint's current durable policy. No default allow provider exists.
    ValueTask<ControlGrant?> FindAsync(string authenticatedOwner, Guid grantId, CancellationToken cancellationToken);
}

/// <summary>Local administrator path only; deliberately not part of remote control RPC.</summary>
public interface IDurableControlGrantProvider : IControlGrantProvider
{
    ValueTask RevokeAsync(string ownerDeviceId, Guid grantId, CancellationToken cancellationToken);
}

public sealed class ControlProtocolException(string code) : IOException(code)
{
    public string Code { get; } = code;
}
