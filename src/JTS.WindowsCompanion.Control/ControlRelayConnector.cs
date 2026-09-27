using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control;

// Injection is internal/test-only. Production always uses the sealed relay client and host's TLS entry point.
internal interface IControlRelayConnector
{
    string DeviceId { get; }
    Task TouchPresenceAsync(CancellationToken token);
    Task<IReadOnlyList<RelayChannelOffer>> PollAsync(CancellationToken token);
    Task ServeAsync(CompanionControlHost host, RelayChannelOffer offer, RelayPeerTrust trust, CancellationToken token);
    bool Supports(RelayLane lane) => lane == RelayLane.Control;
}

internal sealed class ControlRelayConnector(RelayControlClient client,
    IReadOnlyDictionary<RelayLane, ICompanionRelayLaneHandler>? lanes = null) : IControlRelayConnector
{
    public string DeviceId => client.DeviceId;
    public Task TouchPresenceAsync(CancellationToken token) => client.TouchPresenceAsync(token);
    public Task<IReadOnlyList<RelayChannelOffer>> PollAsync(CancellationToken token) => client.PollAsync(token);
    public bool Supports(RelayLane lane) => lane == RelayLane.Control || lanes?.ContainsKey(lane) == true;
    public async Task ServeAsync(CompanionControlHost host, RelayChannelOffer offer, RelayPeerTrust trust, CancellationToken token)
    {
        if (offer.Binding.Lane == RelayLane.Control)
            await host.ServeRelayAsync(client, offer, trust, token).ConfigureAwait(false);
        else
        {
            if (lanes is null || !lanes.TryGetValue(offer.Binding.Lane, out var handler))
                throw new ControlProtocolException("LANE_UNAVAILABLE");
            await using var stream = await client.OpenSecureChannelAsync(offer, trust, token).ConfigureAwait(false);
            await handler.ServeAsync(stream, offer.Binding.ControllerDeviceId, token).ConfigureAwait(false);
        }
    }
}

/// <summary>Called only after pinned TLS and exact relay session/lane binding. Each handler must validate its lane grant.</summary>
public interface ICompanionRelayLaneHandler
{
    Task ServeAsync(Stream stream, string ownerDeviceId, CancellationToken cancellationToken);
}

public enum RelayControlServiceState { NotStarted, Connecting, Online, BackingOff, Stopped, Faulted }
public sealed record RelayControlServiceStatus(RelayControlServiceState State, string? Code);

internal sealed record RelayControlTiming(TimeSpan Poll, TimeSpan Presence, TimeSpan InitialBackoff, TimeSpan MaximumBackoff)
{
    internal static RelayControlTiming Default { get; } = new(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15),
        TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30));
}
