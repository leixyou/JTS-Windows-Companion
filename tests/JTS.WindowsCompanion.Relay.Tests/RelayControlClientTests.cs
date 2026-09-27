using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JTS.WindowsCompanion.Relay.Tests;

public sealed class RelayControlClientTests
{
    [Fact]
    public async Task SignsExactChallengeAndPayloadDigestWithoutTrailingNewline()
    {
        using var certificate = TransportFixture.Certificate("controller");
        var identity = new RelayEndpointIdentity(certificate);
        var nonce = Convert.ToBase64String(new byte[32]);
        var challengeId = Guid.NewGuid().ToString("D");
        var calls = 0;
        var handler = new TestHandler(async (request, token) =>
        {
            calls++;
            using var json = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            if (calls == 1)
            {
                Assert.Equal("/v1/challenges", request.RequestUri!.AbsolutePath);
                Assert.Equal(identity.DeviceId, json.RootElement.GetProperty("deviceId").GetString());
                Assert.Equal("presence", json.RootElement.GetProperty("operation").GetString());
                return Json(new { challengeId, nonceBase64 = nonce, expiresAtUnixSeconds = DateTimeOffset.UtcNow.AddSeconds(60).ToUnixTimeSeconds() });
            }
            Assert.Equal("/v1/presence", request.RequestUri!.AbsolutePath);
            var payload = Convert.FromBase64String(json.RootElement.GetProperty("payloadBase64").GetString()!);
            Assert.Equal("{}", Encoding.UTF8.GetString(payload));
            var signature = Convert.FromBase64String(json.RootElement.GetProperty("signatureBase64").GetString()!);
            Assert.Equal(64, signature.Length);
            using var key = certificate.GetECDsaPublicKey()!;
            var expected = Encoding.UTF8.GetBytes(string.Join('\n', "JTS-RELAY-AUTH-V2", "https://relay.example", identity.DeviceId,
                "presence", challengeId, nonce, RelayWire.Hash(payload)));
            Assert.True(key.VerifyData(expected, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            var otherOrigin = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(expected).Replace("https://relay.example", "https://other.example"));
            Assert.False(key.VerifyData(otherOrigin, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            var legacy = Encoding.UTF8.GetBytes(string.Join('\n', "JTS-RELAY-AUTH-V1", identity.DeviceId, "presence", challengeId, nonce, RelayWire.Hash(payload)));
            Assert.False(key.VerifyData(legacy, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            return Json(new { deviceId = identity.DeviceId });
        });
        using var client = new RelayControlClient(new Uri("https://relay.example/"), identity, handler, TimeProvider.System);
        await client.TouchPresenceAsync();
        Assert.Equal(2, calls);
    }

    [Theory]
    [InlineData("http://relay.example/", false)]
    [InlineData("http://127.0.0.1/", false)]
    [InlineData("http://localhost/", true)]
    [InlineData("https://user:password@relay.example/", false)]
    [InlineData("https://relay.example/path", false)]
    [InlineData("https://relay.example/?token=x", false)]
    public void RejectsUnsafeRelayOrigins(string origin, bool allowDevelopment)
    {
        using var certificate = TransportFixture.Certificate("controller");
        Assert.Throws<ArgumentException>(() => new RelayControlClient(new Uri(origin), new RelayEndpointIdentity(certificate), allowDevelopment));
    }

    [Fact]
    public async Task PollUsesCompanionRoleTicketAndExplicitControllerField()
    {
        using var certificate = TransportFixture.Certificate("companion");
        var identity = new RelayEndpointIdentity(certificate);
        var controller = new string('a', 64);
        var sessionId = Guid.NewGuid().ToString("D");
        var ticket = new string('X', 43);
        using var client = Client(identity, new
        {
            offers = new[] { new { sessionId, lane = "rdp", controllerDeviceId = controller, ticket,
                expiresAtUnixSeconds = DateTimeOffset.UtcNow.AddSeconds(60).ToUnixTimeSeconds(), channelPath = "/v1/channel" } },
        });
        var offer = Assert.Single(await client.PollAsync());
        Assert.Equal(controller, offer.Binding.ControllerDeviceId);
        Assert.Equal(identity.DeviceId, offer.Binding.CompanionDeviceId);
        Assert.Equal(RelayLane.Rdp, offer.Binding.Lane);
        Assert.DoesNotContain(ticket, offer.ToString());
        offer.Claim();
        Assert.Throws<RelayProtocolException>(() => offer.Claim());
    }

    [Fact]
    public async Task RelayOfferDoesNotGrantTrustOrNewLane()
    {
        using var certificate = TransportFixture.Certificate("companion");
        var identity = new RelayEndpointIdentity(certificate);
        using var client = new RelayControlClient(new Uri("https://relay.example/"), identity);
        var binding = new RelayBinding(Guid.NewGuid(), RelayLane.Rdp, new string('a', 64), identity.DeviceId);
        var offer = new RelayChannelOffer(binding, new string('X', 43), DateTimeOffset.UtcNow.AddSeconds(60), new Uri("https://relay.example/"));
        var unauthorizedPeer = new RelayPeerTrust(new string('b', 64), RelayTlsPolicy.Tls13, [RelayLane.Rdp]);
        var wrongLane = new RelayPeerTrust(new string('a', 64), RelayTlsPolicy.Tls13, [RelayLane.Control]);
        await Assert.ThrowsAsync<RelayProtocolException>(() => client.OpenSecureChannelAsync(offer, unauthorizedPeer));
        await Assert.ThrowsAsync<RelayProtocolException>(() => client.OpenSecureChannelAsync(offer, wrongLane));
    }

    [Fact]
    public async Task TicketCannotBeSentToDifferentRelayOrigin()
    {
        using var certificate = TransportFixture.Certificate("companion");
        var identity = new RelayEndpointIdentity(certificate);
        using var client = new RelayControlClient(new Uri("https://relay.example/"), identity);
        var binding = new RelayBinding(Guid.NewGuid(), RelayLane.Control, new string('a', 64), identity.DeviceId);
        var offer = new RelayChannelOffer(binding, new string('X', 43), DateTimeOffset.UtcNow.AddSeconds(60), new Uri("https://another.example/"));
        await Assert.ThrowsAsync<RelayProtocolException>(() => client.OpenChannelAsync(offer));
    }

    [Fact]
    public async Task NoAutomaticRetryAfterAdmissionFailure()
    {
        using var certificate = TransportFixture.Certificate("companion");
        var identity = new RelayEndpointIdentity(certificate);
        var calls = 0;
        using var client = new RelayControlClient(new Uri("https://relay.example/"), identity,
            new TestHandler((_, _) => { calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)); }), TimeProvider.System);
        var error = await Assert.ThrowsAsync<RelayProtocolException>(() => client.TouchPresenceAsync());
        Assert.Equal("RELAY_HTTP_401", error.Code);
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("{\"offers\":[],\"offers\":[]}")]
    [InlineData("{\"offers\":[],\"unexpected\":true}")]
    [InlineData("{\"offers\":null}")]
    public async Task RejectsAmbiguousOrInvalidResponse(string json)
    {
        using var certificate = TransportFixture.Certificate("companion");
        using var client = Client(new RelayEndpointIdentity(certificate), json);
        await Assert.ThrowsAsync<RelayProtocolException>(() => client.PollAsync());
    }

    [Fact]
    public async Task BoundedHttpResponseRejectsLargeBody()
    {
        using var certificate = TransportFixture.Certificate("companion");
        using var client = Client(new RelayEndpointIdentity(certificate), new string('a', RelayWire.MaximumHttpBytes + 1));
        var error = await Assert.ThrowsAsync<RelayProtocolException>(() => client.PollAsync());
        Assert.Equal("RELAY_RESPONSE_LIMIT", error.Code);
    }

    [Fact]
    public async Task UnsupportedNodeVersionFailsBeforeSigningChallenge()
    {
        using var certificate = TransportFixture.Certificate("companion");
        var calls = 0;
        using var client = new RelayControlClient(new Uri("https://relay.example/"), new RelayEndpointIdentity(certificate),
            new TestHandler((request, _) =>
            {
                calls++;
                Assert.Equal("/v1/info", request.RequestUri!.AbsolutePath);
                return Task.FromResult(Json(new { protocolVersion = 2, lanes = new[] { "control", "file", "rdp" } }));
            }, autoInfo: false), TimeProvider.System);
        var error = await Assert.ThrowsAsync<RelayProtocolException>(() => client.TouchPresenceAsync());
        Assert.Equal("RELAY_VERSION_UNSUPPORTED", error.Code);
        Assert.Equal(1, calls);
    }

    private static RelayControlClient Client(RelayEndpointIdentity identity, object response)
    {
        return new RelayControlClient(new Uri("https://relay.example/"), identity, new TestHandler((request, _) =>
            Task.FromResult(request.RequestUri!.AbsolutePath == "/v1/challenges"
                ? Json(new { challengeId = Guid.NewGuid().ToString("D"), nonceBase64 = Convert.ToBase64String(new byte[32]),
                    expiresAtUnixSeconds = DateTimeOffset.UtcNow.AddSeconds(60).ToUnixTimeSeconds() })
                : response is string raw ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(raw) } : Json(response))), TimeProvider.System);
    }

    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
    private sealed class TestHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond, bool autoInfo = true) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => autoInfo && request.RequestUri!.AbsolutePath == "/v1/info"
                ? Task.FromResult(Json(new { protocolVersion = 1, lanes = new[] { "control", "file", "rdp" } }))
                : respond(request, cancellationToken);
    }
}
