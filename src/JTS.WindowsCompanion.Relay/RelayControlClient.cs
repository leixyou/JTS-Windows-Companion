using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Net.Security;
using System.Text;
using System.Text.Json;

namespace JTS.WindowsCompanion.Relay;

/// <summary>Node admission only; successful HTTP authentication never authorizes endpoint business operations.</summary>
public sealed class RelayControlClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly Uri _origin;
    private readonly RelayEndpointIdentity _identity;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _protocolGate = new(1, 1);
    private bool _protocolValidated;
    public string DeviceId => _identity.DeviceId;

    public RelayControlClient(Uri origin, RelayEndpointIdentity identity, bool allowLoopbackDevelopmentHttp = false,
        bool validateOuterCertificate = false)
        : this(origin, identity, CreateOuterHandler(validateOuterCertificate),
            TimeProvider.System, allowLoopbackDevelopmentHttp) { }

    internal static SocketsHttpHandler CreateOuterHandler(bool validateCertificate)
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        // The relay is an untrusted carrier. Device authentication remains in RelaySecureStream's pinned mTLS.
        if (!validateCertificate) handler.SslOptions.RemoteCertificateValidationCallback = static (_, _, _, _) => true;
        return handler;
    }

    internal RelayControlClient(Uri origin, RelayEndpointIdentity identity, HttpMessageHandler handler,
        TimeProvider clock, bool allowLoopbackDevelopmentHttp = false)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(identity);
        if (!origin.IsAbsoluteUri || origin.AbsolutePath != "/" || origin.UserInfo.Length != 0
            || origin.Query.Length != 0 || origin.Fragment.Length != 0
            || (origin.Scheme != "https" && !(allowLoopbackDevelopmentHttp && origin.Scheme == "http"
                && IPAddress.TryParse(origin.Host, out var address) && IPAddress.IsLoopback(address))))
            throw new ArgumentException("An HTTPS origin or explicitly enabled numeric loopback development origin is required.", nameof(origin));
        _origin = origin;
        _identity = identity;
        _clock = clock;
        _http = new HttpClient(handler, disposeHandler: true) { BaseAddress = origin, Timeout = Timeout.InfiniteTimeSpan };
    }

    public async Task ProbeAsync(CancellationToken cancellationToken = default)
    {
        await _protocolGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_protocolValidated) return;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            using var request = new HttpRequestMessage(HttpMethod.Get, "v1/info");
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            using var json = await ReadResponseAsync(response, deadline.Token).ConfigureAwait(false);
            var value = json.RootElement;
            RelayWire.Properties(value, "protocolVersion", "lanes");
            if (value.GetProperty("protocolVersion").ValueKind != JsonValueKind.Number
                || !value.GetProperty("protocolVersion").TryGetInt32(out var version) || version != 1)
                throw new RelayProtocolException("RELAY_VERSION_UNSUPPORTED");
            var lanes = value.GetProperty("lanes");
            if (lanes.ValueKind != JsonValueKind.Array || lanes.GetArrayLength() != 3
                || lanes.EnumerateArray().Any(l => l.ValueKind != JsonValueKind.String)
                || !lanes.EnumerateArray().Select(l => l.GetString()).Order()
                    .SequenceEqual(new[] { "control", "file", "rdp" }))
                throw new RelayProtocolException("RELAY_LANES_UNSUPPORTED");
            _protocolValidated = true;
        }
        finally { _protocolGate.Release(); }
    }

    public async Task TouchPresenceAsync(CancellationToken cancellationToken = default)
    {
        using var response = await AuthenticateAsync("presence", new { }, cancellationToken).ConfigureAwait(false);
        RelayWire.Properties(response.RootElement, "deviceId");
        if (RelayWire.String(response.RootElement, "deviceId", 64) != _identity.DeviceId)
            throw new RelayProtocolException("RELAY_IDENTITY_MISMATCH");
    }

    public async Task<RelayChannelOffer> RequestSessionAsync(string companionDeviceId, RelayLane lane,
        CancellationToken cancellationToken = default)
    {
        var laneName = RelayWire.LaneName(lane);
        if (!RelayWire.IsDeviceId(companionDeviceId) || companionDeviceId == _identity.DeviceId)
            throw new ArgumentException("An enrolled peer device ID is required.", nameof(companionDeviceId));
        using var response = await AuthenticateAsync("sessions", new { peerDeviceId = companionDeviceId, lane = laneName }, cancellationToken).ConfigureAwait(false);
        return ParseOffer(response.RootElement, _identity.DeviceId, companionDeviceId, lane, isPoll: false);
    }

    public async Task<IReadOnlyList<RelayPeerPresence>> ListPeersAsync(CancellationToken cancellationToken = default)
    {
        using var response = await AuthenticateAsync("devices", new { }, cancellationToken).ConfigureAwait(false);
        RelayWire.Properties(response.RootElement, "devices");
        var devices = response.RootElement.GetProperty("devices");
        if (devices.ValueKind != JsonValueKind.Array || devices.GetArrayLength() > 256)
            throw new RelayProtocolException("RELAY_DEVICES_INVALID");
        var result = new List<RelayPeerPresence>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var device in devices.EnumerateArray())
        {
            RelayWire.Properties(device, "deviceId", "lastSeenAtUnixSeconds");
            var id = RelayWire.String(device, "deviceId", 64);
            if (!RelayWire.IsDeviceId(id) || id == _identity.DeviceId || !seen.Add(id))
                throw new RelayProtocolException("RELAY_DEVICES_INVALID");
            var lastSeen = device.GetProperty("lastSeenAtUnixSeconds");
            DateTimeOffset? at = null;
            if (lastSeen.ValueKind != JsonValueKind.Null)
            {
                if (lastSeen.ValueKind != JsonValueKind.Number || !lastSeen.TryGetInt64(out var seconds)
                    || seconds < 0 || seconds > _clock.GetUtcNow().AddSeconds(65).ToUnixTimeSeconds())
                    throw new RelayProtocolException("RELAY_DEVICES_INVALID");
                at = DateTimeOffset.FromUnixTimeSeconds(seconds);
            }
            result.Add(new RelayPeerPresence(id, at));
        }
        return result.AsReadOnly();
    }

    public async Task<IReadOnlyList<RelayChannelOffer>> PollAsync(CancellationToken cancellationToken = default)
    {
        using var response = await AuthenticateAsync("poll", new { }, cancellationToken).ConfigureAwait(false);
        RelayWire.Properties(response.RootElement, "offers");
        var offers = response.RootElement.GetProperty("offers");
        if (offers.ValueKind != JsonValueKind.Array || offers.GetArrayLength() > 32)
            throw new RelayProtocolException("RELAY_OFFERS_INVALID");
        var result = new List<RelayChannelOffer>();
        var sessions = new HashSet<Guid>();
        foreach (var offer in offers.EnumerateArray())
        {
            var controller = RelayWire.String(offer, "controllerDeviceId", 64);
            var lane = RelayWire.ParseLane(RelayWire.String(offer, "lane", 8));
            var parsed = ParseOffer(offer, controller, _identity.DeviceId, lane, isPoll: true);
            if (!sessions.Add(parsed.Binding.SessionId)) throw new RelayProtocolException("RELAY_OFFERS_INVALID");
            result.Add(parsed);
        }
        return result.AsReadOnly();
    }

    /// <summary>Pairing trust must come from local enrollment, not the relay. Revocation must cancel/close the returned session.</summary>
    public async Task<SslStream> OpenSecureChannelAsync(RelayChannelOffer offer, RelayPeerTrust pairedPeer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(offer);
        ArgumentNullException.ThrowIfNull(pairedPeer);
        var controller = offer.Binding.ControllerDeviceId == _identity.DeviceId;
        pairedPeer.Require(controller ? offer.Binding.CompanionDeviceId : offer.Binding.ControllerDeviceId, offer.Binding.Lane);
        var carrier = await OpenChannelAsync(offer, cancellationToken).ConfigureAwait(false);
        try
        {
            return await RelaySecureStream.AuthenticateAsync(carrier, _identity, pairedPeer,
                offer.Binding, controller, cancellationToken).ConfigureAwait(false);
        }
        catch { await carrier.DisposeAsync().ConfigureAwait(false); throw; }
    }

    internal async Task<RelayWebSocketStream> OpenChannelAsync(RelayChannelOffer offer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(offer);
        if (offer.IssuerOrigin != _origin
            || (offer.Binding.ControllerDeviceId != _identity.DeviceId && offer.Binding.CompanionDeviceId != _identity.DeviceId))
            throw new RelayProtocolException("RELAY_IDENTITY_MISMATCH");
        offer.Claim(); // Never retry an uncertain upgrade using the same ticket.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var remaining = offer.ExpiresAt - _clock.GetUtcNow();
        if (remaining <= TimeSpan.Zero) throw new RelayProtocolException("RELAY_TICKET_EXPIRED");
        deadline.CancelAfter(remaining < TimeSpan.FromSeconds(30) ? remaining : TimeSpan.FromSeconds(30));
        var socket = new ClientWebSocket();
        socket.Options.SetRequestHeader("Authorization", "Bearer " + offer.Ticket);
        socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(15);
        var uri = new UriBuilder(_origin) { Scheme = _origin.Scheme == "https" ? "wss" : "ws", Path = "/v1/channel" }.Uri;
        try
        {
            // Reuse the redirect-disabled handler so a bearer ticket cannot be forwarded to another origin.
            await socket.ConnectAsync(uri, _http, deadline.Token).ConfigureAwait(false);
            await RelayWebSocketStream.ExpectReadyAsync(socket, offer.Binding, deadline.Token).ConfigureAwait(false);
            return new RelayWebSocketStream(socket);
        }
        catch { socket.Dispose(); throw; }
    }

    internal async Task<JsonDocument> AuthenticateAsync(string operation, object payload, CancellationToken cancellationToken)
    {
        if (operation is not ("presence" or "devices" or "sessions" or "poll"))
            throw new ArgumentException("Unsupported relay operation.", nameof(operation));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        await ProbeAsync(deadline.Token).ConfigureAwait(false);
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        if (payloadBytes.Length > RelayWire.MaximumPayloadBytes) throw new RelayProtocolException("RELAY_PAYLOAD_LIMIT");
        using var challenge = await PostAsync("v1/challenges", new { deviceId = _identity.DeviceId, operation }, deadline.Token).ConfigureAwait(false);
        RelayWire.Properties(challenge.RootElement, "challengeId", "nonceBase64", "expiresAtUnixSeconds");
        _ = RelayWire.Expiry(challenge.RootElement, _clock.GetUtcNow());
        var id = RelayWire.String(challenge.RootElement, "challengeId", 128);
        if (!id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) throw new RelayProtocolException("RELAY_CHALLENGE_INVALID");
        var nonce = RelayWire.String(challenge.RootElement, "nonceBase64", 44);
        byte[] nonceBytes;
        try { nonceBytes = Convert.FromBase64String(nonce); }
        catch (FormatException) { throw new RelayProtocolException("RELAY_CHALLENGE_INVALID"); }
        if (nonceBytes.Length != 32 || Convert.ToBase64String(nonceBytes) != nonce)
            throw new RelayProtocolException("RELAY_CHALLENGE_INVALID");
        var signature = _identity.Sign(Encoding.UTF8.GetBytes(string.Join('\n',
            "JTS-RELAY-AUTH-V1", _identity.DeviceId, operation, id, nonce, RelayWire.Hash(payloadBytes))));
        return await PostAsync("v1/" + operation, new
        {
            deviceId = _identity.DeviceId, challengeId = id,
            payloadBase64 = Convert.ToBase64String(payloadBytes), signatureBase64 = Convert.ToBase64String(signature),
        }, deadline.Token).ConfigureAwait(false);
    }

    private async Task<JsonDocument> PostAsync(string path, object body, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        return await ReadResponseAsync(response, token).ConfigureAwait(false);
    }

    private static async Task<JsonDocument> ReadResponseAsync(HttpResponseMessage response, CancellationToken token)
    {
        if (!response.IsSuccessStatusCode) throw new RelayProtocolException("RELAY_HTTP_" + (int)response.StatusCode);
        if (response.Content.Headers.ContentLength > RelayWire.MaximumHttpBytes)
            throw new RelayProtocolException("RELAY_RESPONSE_LIMIT");
        await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        using var bytes = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
            if (count == 0) break;
            if (bytes.Length + count > RelayWire.MaximumHttpBytes) throw new RelayProtocolException("RELAY_RESPONSE_LIMIT");
            bytes.Write(buffer, 0, count);
        }
        return RelayWire.Parse(bytes.ToArray());
    }

    private RelayChannelOffer ParseOffer(JsonElement value, string controller, string companion, RelayLane lane, bool isPoll)
    {
        var names = new[] { "sessionId", "ticket", "expiresAtUnixSeconds", "channelPath" };
        RelayWire.Properties(value, isPoll ? [.. names, "controllerDeviceId", "lane"] : names);
        if (!Guid.TryParseExact(RelayWire.String(value, "sessionId", 36), "D", out var session)
            || RelayWire.String(value, "channelPath", 32) != "/v1/channel")
            throw new RelayProtocolException("RELAY_OFFER_INVALID");
        var ticket = RelayWire.String(value, "ticket", 43);
        if (ticket.Length != 43 || !ticket.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new RelayProtocolException("RELAY_TICKET_INVALID");
        var binding = new RelayBinding(session, lane, controller, companion);
        binding.Validate();
        return new RelayChannelOffer(binding, ticket, RelayWire.Expiry(value, _clock.GetUtcNow()), _origin);
    }

    public void Dispose() => _http.Dispose();
}
