using System.Security.Cryptography;
using System.Text.Json;

namespace JTS.WindowsCompanion.Relay;

public enum RelayLane { Control, File, Rdp }
public enum RelayTlsPolicy { Tls13, ExplicitWindows10Tls12 }
public sealed record RelayPeerPresence(string DeviceId, DateTimeOffset? LastSeenAt);

/// <summary>Loaded from local pairing policy, never constructed from a relay offer or account login.</summary>
public sealed class RelayPeerTrust
{
    private readonly HashSet<RelayLane> _lanes;
    public string DeviceId { get; }
    public RelayTlsPolicy TlsPolicy { get; }
    public bool Allows(RelayLane lane) => _lanes.Contains(lane);
    public RelayPeerTrust(string deviceId, RelayTlsPolicy tlsPolicy, IEnumerable<RelayLane> allowedLanes)
    {
        ArgumentNullException.ThrowIfNull(allowedLanes);
        _lanes = allowedLanes.ToHashSet();
        if (!RelayWire.IsDeviceId(deviceId) || !Enum.IsDefined(tlsPolicy)
            || _lanes.Count is 0 or > 3 || _lanes.Any(l => !Enum.IsDefined(l)))
            throw new ArgumentException("An enrolled peer, TLS policy and explicit allowed lanes are required.");
        DeviceId = deviceId;
        TlsPolicy = tlsPolicy;
    }
    internal void Require(string peerDeviceId, RelayLane lane)
    {
        if (peerDeviceId != DeviceId || !_lanes.Contains(lane))
            throw new RelayProtocolException("RELAY_PEER_NOT_AUTHORIZED");
    }
}

public sealed class RelayProtocolException(string code) : IOException(code)
{
    public string Code { get; } = code;
}

public sealed record RelayBinding(
    Guid SessionId,
    RelayLane Lane,
    string ControllerDeviceId,
    string CompanionDeviceId)
{
    public void Validate()
    {
        if (SessionId == Guid.Empty || !Enum.IsDefined(Lane)
            || !RelayWire.IsDeviceId(ControllerDeviceId)
            || !RelayWire.IsDeviceId(CompanionDeviceId)
            || ControllerDeviceId == CompanionDeviceId)
            throw new RelayProtocolException("RELAY_BINDING_INVALID");
    }
}

// Do not use a record: generated ToString must never expose the bearer ticket.
public sealed class RelayChannelOffer
{
    internal RelayChannelOffer(RelayBinding binding, string ticket, DateTimeOffset expiresAt, Uri issuerOrigin)
    {
        Binding = binding;
        Ticket = ticket;
        ExpiresAt = expiresAt;
        IssuerOrigin = issuerOrigin;
    }

    public RelayBinding Binding { get; }
    public DateTimeOffset ExpiresAt { get; }
    internal string Ticket { get; }
    internal Uri IssuerOrigin { get; }
    private int _claimed;
    internal void Claim()
    {
        if (Interlocked.Exchange(ref _claimed, 1) != 0)
            throw new RelayProtocolException("RELAY_TICKET_ALREADY_CLAIMED");
    }
    public override string ToString() => "RelayChannelOffer (credentials omitted)";
}

internal static class RelayWire
{
    internal const int MaximumHttpBytes = 32 * 1024;
    internal const int MaximumPayloadBytes = 16 * 1024;
    internal static string LaneName(RelayLane lane) => lane switch
    {
        RelayLane.Control => "control", RelayLane.File => "file", RelayLane.Rdp => "rdp",
        _ => throw new RelayProtocolException("RELAY_LANE_INVALID"),
    };
    internal static RelayLane ParseLane(string value) => value switch
    {
        "control" => RelayLane.Control, "file" => RelayLane.File, "rdp" => RelayLane.Rdp,
        _ => throw new RelayProtocolException("RELAY_LANE_INVALID"),
    };
    internal static bool IsDeviceId(string value) => value is { Length: 64 }
        && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static string String(JsonElement value, string name, int maximum)
    {
        if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
            throw new RelayProtocolException("RELAY_RESPONSE_INVALID");
        var result = property.GetString()!;
        if (result.Length is 0 || result.Length > maximum || result.Contains('\0'))
            throw new RelayProtocolException("RELAY_RESPONSE_INVALID");
        return result;
    }
    internal static JsonDocument Parse(ReadOnlyMemory<byte> bytes)
    {
        try
        {
            var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            try { RejectDuplicates(document.RootElement); return document; }
            catch { document.Dispose(); throw; }
        }
        catch (JsonException) { throw new RelayProtocolException("RELAY_JSON_INVALID"); }
    }
    internal static void Properties(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object
            || !value.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(expected.Order()))
            throw new RelayProtocolException("RELAY_RESPONSE_INVALID");
    }
    private static void RejectDuplicates(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new JsonException();
                RejectDuplicates(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var child in value.EnumerateArray()) RejectDuplicates(child);
    }
    internal static DateTimeOffset Expiry(JsonElement value, DateTimeOffset now)
    {
        if (!value.TryGetProperty("expiresAtUnixSeconds", out var expiry)
            || expiry.ValueKind != JsonValueKind.Number || !expiry.TryGetInt64(out var seconds))
            throw new RelayProtocolException("RELAY_EXPIRY_INVALID");
        DateTimeOffset result;
        try { result = DateTimeOffset.FromUnixTimeSeconds(seconds); }
        catch (ArgumentOutOfRangeException) { throw new RelayProtocolException("RELAY_EXPIRY_INVALID"); }
        if (result <= now || result > now.AddSeconds(65)) throw new RelayProtocolException("RELAY_EXPIRY_INVALID");
        return result;
    }
}
