using System.Net.Http.Json;
using System.Text.Json;

namespace JTS.WindowsCompanion.Enrollment;

internal sealed record EnrollmentClaim(string PeerSPKIBase64, string ResponseBase64, string SignatureBase64, string ClaimHash);
internal sealed record EnrollmentReceipt(Guid InvitationId, string ControllerDeviceId, string State, long ExpiresAtUnixSeconds,
    string OfferBase64, EnrollmentClaim? Claim);

internal interface IEnrollmentRelay
{
    Task<EnrollmentReceipt> ExchangeAsync(string operation, EnrollmentAttempt attempt, string peerSpki, CancellationToken token);
}

internal sealed class EnrollmentRelayClient : IEnrollmentRelay, IDisposable
{
    private readonly HttpClient _http;
    private readonly TimeSpan _timeout;
    internal EnrollmentRelayClient(Uri origin, bool validateCertificate = false)
        : this(origin, CreateHandler(validateCertificate), TimeSpan.FromSeconds(20)) { }
    internal EnrollmentRelayClient(Uri origin, HttpMessageHandler handler, TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
        _timeout = timeout;
        _http = new(handler) { BaseAddress = new Uri(EnrollmentCode.CanonicalOrigin(origin.AbsoluteUri) + "/"), Timeout = Timeout.InfiniteTimeSpan };
    }
    private static SocketsHttpHandler CreateHandler(bool validateCertificate)
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        if (!validateCertificate) handler.SslOptions.RemoteCertificateValidationCallback = static (_, _, _, _) => true;
        return handler;
    }
    public async Task<EnrollmentReceipt> ExchangeAsync(string operation, EnrollmentAttempt attempt, string peerSpki, CancellationToken token)
    {
        if (operation is not ("offer" or "receipt" or "claim")) throw new EnrollmentException("ENROLLMENT_OPERATION_INVALID");
        // ResponseHeadersRead ends HttpClient's timeout at the headers. One deadline must also cover the body.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(_timeout);
        token = deadline.Token;
        using var code = attempt.OpenCode(); var claimToken = code.Derive("relay-claim");
        try
        {
            var body = new Dictionary<string, object> { ["invitationId"] = code.InvitationId.ToString("D"), ["claimTokenBase64"] = Convert.ToBase64String(claimToken) };
            if (operation == "claim")
            {
                body["peerSPKIBase64"] = peerSpki; body["responseBase64"] = attempt.ResponseBase64!; body["signatureBase64"] = attempt.SignatureBase64!;
            }
            using var request = new HttpRequestMessage(HttpMethod.Post, "v1/enrollment/" + operation) { Content = JsonContent.Create(body) };
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) throw new HttpRequestException("ENROLLMENT_RELAY_UNAVAILABLE", null, response.StatusCode);
            if (response.Content.Headers.ContentLength > 32768) throw new EnrollmentException("ENROLLMENT_PAYLOAD_INVALID");
            using var input = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            using var buffer = new MemoryStream(); var chunk = new byte[4096]; int read;
            while ((read = await input.ReadAsync(chunk, token).ConfigureAwait(false)) != 0)
            { if (buffer.Length + read > 32768) throw new EnrollmentException("ENROLLMENT_PAYLOAD_INVALID"); await buffer.WriteAsync(chunk.AsMemory(0, read), token).ConfigureAwait(false); }
            return Parse(buffer.ToArray());
        }
        catch (IOException error) when (error is not EnrollmentException)
        { throw new HttpRequestException("ENROLLMENT_RELAY_UNAVAILABLE", error); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(claimToken); }
    }
    internal static EnrollmentReceipt Parse(byte[] bytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(bytes); var p = doc.RootElement; var hasClaim = p.TryGetProperty("claim", out var claim);
            EnrollmentCrypto.Fields(p, hasClaim ? ["invitationId", "controllerDeviceId", "state", "expiresAtUnixSeconds", "offerBase64", "claim"]
                : ["invitationId", "controllerDeviceId", "state", "expiresAtUnixSeconds", "offerBase64"]);
            var idString = p.GetProperty("invitationId").GetString()!;
            if (!Guid.TryParseExact(idString, "D", out var id) || id == Guid.Empty || id.ToString("D") != idString) throw Invalid();
            var controller = p.GetProperty("controllerDeviceId").GetString()!;
            if (controller.Length != 64 || controller.Any(c => !"0123456789abcdef".Contains(c))) throw Invalid();
            var state = p.GetProperty("state").GetString()!;
            if (state is not ("pending" or "claimed" or "bound" or "cancelled" or "expired")) throw Invalid();
            var expiry = p.GetProperty("expiresAtUnixSeconds").GetInt64(); if (expiry is < 1 or > 253402300799) throw Invalid();
            var offer = p.GetProperty("offerBase64").GetString()!; if (EnrollmentCrypto.Base64(offer).Length < 28) throw Invalid();
            EnrollmentClaim? value = null;
            if (hasClaim)
            {
                EnrollmentCrypto.Fields(claim, "peerSPKIBase64", "responseBase64", "signatureBase64", "claimHash");
                value = new(claim.GetProperty("peerSPKIBase64").GetString()!, claim.GetProperty("responseBase64").GetString()!,
                    claim.GetProperty("signatureBase64").GetString()!, claim.GetProperty("claimHash").GetString()!);
                if (EnrollmentCrypto.Base64(value.PeerSPKIBase64, 512).Length == 0 || EnrollmentCrypto.Base64(value.ResponseBase64).Length < 28
                    || EnrollmentCrypto.Base64(value.SignatureBase64, 64).Length != 64 || value.ClaimHash.Length != 64
                    || value.ClaimHash.Any(c => !"0123456789abcdef".Contains(c))) throw Invalid();
            }
            if (state is "claimed" or "bound" && value is null) throw Invalid();
            if (state == "pending" && value is not null) throw Invalid();
            return new(id, controller, state, expiry, offer, value);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or NullReferenceException) { throw Invalid(); }
    }
    private static EnrollmentException Invalid() => new("ENROLLMENT_PAYLOAD_INVALID");
    public void Dispose() => _http.Dispose();
}
