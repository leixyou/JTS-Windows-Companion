using System.Text.Json;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control;

internal sealed record LaneRequest(Guid Id, string Operation, Guid GrantId, JsonElement Parameters)
{
    internal static async Task<LaneRequest?> ReadAsync(Stream stream, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(90));
        var bytes = await ControlWire.ReadAsync(stream, deadline.Token).ConfigureAwait(false);
        if (bytes is null) return null;
        using var json = ControlWire.Parse(bytes); var value = json.RootElement;
        ControlWire.Fields(value, "version", "id", "operation", "grantId", "parameters");
        if (ControlWire.Integer(value, "version") != 1) throw new ControlProtocolException("LANE_VERSION_UNSUPPORTED");
        return new(ControlWire.Id(value, "id"), ControlWire.Text(value, "operation", 64),
            ControlWire.Id(value, "grantId"), value.GetProperty("parameters").Clone());
    }

    internal static async Task AuthorizeAsync(DurableRelayPairingStore pairings, string owner, RelayLane lane,
        Guid grant, CancellationToken token)
    {
        var pairing = await pairings.FindAsync(owner, token).ConfigureAwait(false);
        if (pairing is null || !pairing.AllowedLanes.Contains(lane) || !pairing.GrantsFor(lane).Contains(grant))
            throw new ControlProtocolException("LANE_GRANT_REQUIRED");
    }

    internal Task ReplyAsync(Stream stream, object? result, string? error, CancellationToken token)
        => ControlWire.WriteAsync(stream, JsonSerializer.SerializeToUtf8Bytes(new
        { version = 1, id = Id, ok = error is null, result = error is null ? result : null, errorCode = error }), token);

    internal void RequireOpen(string name)
    {
        if (Operation != name) throw new ControlProtocolException("LANE_OPEN_REQUIRED");
        ControlWire.Fields(Parameters);
    }
}
