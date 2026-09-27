using System.Net;
using System.Net.Sockets;
using JTS.WindowsCompanion.Relay;
using Xunit;

namespace JTS.WindowsCompanion.Pairing.Tests;

public sealed class IdentityTransportTests
{
    [Fact]
    public async Task ReopenedIdentityAuthenticatesPinnedTlsAndRetainsPairingBinding()
    {
        using var a = new IdentityFixture(); using var b = new IdentityFixture();
        string controllerId, companionId;
        using (var identity = ProtectedRelayIdentityStore.CreateNew(a.Path, a.EnrollmentId, a.Protector, TimeProvider.System)) controllerId = identity.Description.DeviceId;
        using (var identity = ProtectedRelayIdentityStore.CreateNew(b.Path, b.EnrollmentId, b.Protector, TimeProvider.System)) companionId = identity.Description.DeviceId;
        using var controller = ProtectedRelayIdentityStore.Open(a.Path, a.EnrollmentId, controllerId, a.Protector, TimeProvider.System);
        using var companion = ProtectedRelayIdentityStore.Open(b.Path, b.EnrollmentId, companionId, b.Protector, TimeProvider.System);
        var pairingPath = Path.Combine(b.Directory.FullName, "pairings.sqlite");
        using (var store = DurableRelayPairingStore.CreateNew(pairingPath, companionId, b.Protector))
            store.ApproveLocally(new(Guid.NewGuid(), controllerId, RelayTlsPolicy.ExplicitWindows10Tls12,
                DateTimeOffset.UtcNow.AddHours(1), [RelayLane.Control]), controllerId);
        using var reopened = new DurableRelayPairingStore(pairingPath, companion.Identity.DeviceId, b.Protector);
        var policy = await reopened.FindAsync(controllerId); Assert.NotNull(policy);
        await ExchangeAsync(controller.Identity, companion.Identity, policy.PeerTrust.TlsPolicy);
    }

    internal static async Task ExchangeAsync(RelayEndpointIdentity controller, RelayEndpointIdentity companion, RelayTlsPolicy policy)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var left = new TcpClient(); var accept = listener.AcceptTcpClientAsync(deadline.Token);
        await left.ConnectAsync((IPEndPoint)listener.LocalEndpoint, deadline.Token);
        using var right = await accept;
        var binding = new RelayBinding(Guid.NewGuid(), RelayLane.Control, controller.DeviceId, companion.DeviceId);
        var client = RelaySecureStream.AuthenticateAsync(left.GetStream(), controller, new(companion.DeviceId, policy, [RelayLane.Control]), binding, true, deadline.Token);
        var server = RelaySecureStream.AuthenticateAsync(right.GetStream(), companion, new(controller.DeviceId, policy, [RelayLane.Control]), binding, false, deadline.Token);
        var streams = await Task.WhenAll(client, server);
        await using var clientStream = streams[0]; await using var serverStream = streams[1];
        await clientStream.WriteAsync(new byte[] { 1, 2, 3 }, deadline.Token);
        var result = new byte[3]; await serverStream.ReadExactlyAsync(result, deadline.Token);
        Assert.Equal(new byte[] { 1, 2, 3 }, result);
        Assert.True(clientStream.IsMutuallyAuthenticated); Assert.True(serverStream.IsMutuallyAuthenticated);
    }
}
