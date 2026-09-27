using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using Xunit;

namespace JTS.WindowsCompanion.Relay.Tests;

public sealed class RelaySecureStreamTests
{
    [Theory]
    [InlineData(RelayLane.Control)]
    [InlineData(RelayLane.File)]
    [InlineData(RelayLane.Rdp)]
    public async Task PinnedMutualTlsOverRealWebSocketStreamCarriesOrderedBytes(RelayLane lane)
    {
        using var clientCertificate = TransportFixture.Certificate("controller");
        using var serverCertificate = TransportFixture.Certificate("companion");
        var client = new RelayEndpointIdentity(clientCertificate);
        var server = new RelayEndpointIdentity(serverCertificate);
        var binding = TransportFixture.Binding(client, server, lane);
        var pair = await TransportFixture.WebSocketsAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var policy = OperatingSystem.IsMacOS() ? RelayTlsPolicy.ExplicitWindows10Tls12 : RelayTlsPolicy.Tls13;
        var clientTask = RelaySecureStream.AuthenticateAsync(new RelayWebSocketStream(pair.Client), client, TransportFixture.Trust(server, policy), binding, true, deadline.Token);
        var serverTask = RelaySecureStream.AuthenticateAsync(new RelayWebSocketStream(pair.Server), server, TransportFixture.Trust(client, policy), binding, false, deadline.Token);
        var streams = await Task.WhenAll(clientTask, serverTask);
        await using var controller = streams[0];
        await using var companion = streams[1];
        Assert.True(controller.IsMutuallyAuthenticated);
        Assert.Equal(policy == RelayTlsPolicy.Tls13 ? SslProtocols.Tls13 : SslProtocols.Tls12, controller.SslProtocol);
        var sent = Enumerable.Range(0, 160_000).Select(i => (byte)i).ToArray();
        var received = new byte[sent.Length];
        await Task.WhenAll(controller.WriteAsync(sent, deadline.Token).AsTask(), companion.ReadExactlyAsync(received, deadline.Token).AsTask());
        Assert.Equal(sent, received);
    }

    [Fact]
    public async Task WrongPinnedPeerCannotReturnBusinessStream()
    {
        using var clientCertificate = TransportFixture.Certificate("controller");
        using var serverCertificate = TransportFixture.Certificate("companion");
        using var impostorCertificate = TransportFixture.Certificate("impostor");
        var client = new RelayEndpointIdentity(clientCertificate);
        var server = new RelayEndpointIdentity(serverCertificate);
        var impostor = new RelayEndpointIdentity(impostorCertificate);
        var binding = TransportFixture.Binding(client, server);
        var pair = await TransportFixture.WebSocketsAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var clientTask = RelaySecureStream.AuthenticateAsync(new RelayWebSocketStream(pair.Client), client, TransportFixture.Trust(server), binding, true, deadline.Token);
        var impostorBinding = binding with { CompanionDeviceId = impostor.DeviceId };
        var serverTask = RelaySecureStream.AuthenticateAsync(new RelayWebSocketStream(pair.Server), impostor, TransportFixture.Trust(client), impostorBinding, false, deadline.Token);
        await Assert.ThrowsAnyAsync<Exception>(() => Task.WhenAll(clientTask, serverTask));
        Assert.False(clientTask.IsCompletedSuccessfully);
        Assert.False(serverTask.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task CorrectPeerWithWrongLaneCannotReturnBusinessStream()
    {
        using var clientCertificate = TransportFixture.Certificate("controller");
        using var serverCertificate = TransportFixture.Certificate("companion");
        var client = new RelayEndpointIdentity(clientCertificate);
        var server = new RelayEndpointIdentity(serverCertificate);
        var binding = TransportFixture.Binding(client, server);
        var pair = await TransportFixture.WebSocketsAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var clientTask = RelaySecureStream.AuthenticateAsync(new RelayWebSocketStream(pair.Client), client, TransportFixture.Trust(server), binding, true, deadline.Token);
        var serverTask = RelaySecureStream.AuthenticateAsync(new RelayWebSocketStream(pair.Server), server, TransportFixture.Trust(client), binding with { Lane = RelayLane.Rdp }, false, deadline.Token);
        await Assert.ThrowsAnyAsync<Exception>(() => Task.WhenAll(clientTask, serverTask));
        Assert.False(clientTask.IsCompletedSuccessfully);
        Assert.False(serverTask.IsCompletedSuccessfully);
    }

    [Fact]
    public void CipherPolicyNeverAcceptsPlaintextOrWeakFallback()
    {
        Assert.True(RelaySecureStream.AcceptNegotiatedCipher(RelayTlsPolicy.Tls13, SslProtocols.Tls13, TlsCipherSuite.TLS_AES_128_GCM_SHA256));
        Assert.False(RelaySecureStream.AcceptNegotiatedCipher(RelayTlsPolicy.Tls13, SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
        Assert.False(RelaySecureStream.AcceptNegotiatedCipher(RelayTlsPolicy.ExplicitWindows10Tls12, SslProtocols.Tls12, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384));
        Assert.False(RelaySecureStream.AcceptNegotiatedCipher(RelayTlsPolicy.ExplicitWindows10Tls12, SslProtocols.Tls12, TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
    }

    [Fact]
    public async Task ApplicationBindingRejectsOverlongLengthBeforeAllocating()
    {
        var binding = new RelayBinding(Guid.NewGuid(), RelayLane.Control, new string('a', 64), new string('b', 64));
        var pair = await TransportFixture.WebSocketsAsync();
        using var sender = new RelayWebSocketStream(pair.Client);
        using var receiver = new RelayWebSocketStream(pair.Server);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await sender.WriteAsync(new byte[] { 0xff, 0xff, 0xff, 0xff }, deadline.Token);
        var error = await Assert.ThrowsAsync<RelayProtocolException>(() => RelaySecureStream.ExchangeBindingAsync(receiver, binding, deadline.Token));
        Assert.Equal("RELAY_BINDING_LIMIT", error.Code);
    }

    [Fact]
    public async Task WebSocketRejectsTextAfterReadiness()
    {
        var pair = await TransportFixture.WebSocketsAsync();
        using var sender = pair.Client;
        using var receiver = new RelayWebSocketStream(pair.Server);
        await sender.SendAsync(new byte[] { 65 }, WebSocketMessageType.Text, true, CancellationToken.None);
        await Assert.ThrowsAsync<RelayProtocolException>(() => receiver.ReadAsync(new byte[16]).AsTask());
    }

    [Fact]
    public async Task PendingWebSocketReadHonorsCancellation()
    {
        var pair = await TransportFixture.WebSocketsAsync();
        using var sender = pair.Client;
        using var receiver = new RelayWebSocketStream(pair.Server);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => receiver.ReadAsync(new byte[16], deadline.Token).AsTask());
    }

    [Fact]
    public async Task EmptyBinaryFragmentsAreBounded()
    {
        var pair = await TransportFixture.WebSocketsAsync();
        using var sender = pair.Client;
        using var receiver = new RelayWebSocketStream(pair.Server);
        for (var i = 0; i < 9; i++)
            await sender.SendAsync(ReadOnlyMemory<byte>.Empty, WebSocketMessageType.Binary, true, CancellationToken.None);
        var error = await Assert.ThrowsAsync<RelayProtocolException>(() => receiver.ReadAsync(new byte[16]).AsTask());
        Assert.Equal("RELAY_EMPTY_FRAGMENT_LIMIT", error.Code);
    }
}
