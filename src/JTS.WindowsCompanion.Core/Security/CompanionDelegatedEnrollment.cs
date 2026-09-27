using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Security;

public sealed record CompanionDelegatedWindowsIdentity(Guid DeviceId, string FingerprintSha256);

public sealed record CompanionDelegatedEnrollmentRequest(
    int SchemaVersion,
    Guid GrantId,
    string AuthorizationSource,
    Guid TargetId,
    string TargetBinding,
    CompanionPeerIdentity MacIdentity,
    CompanionDelegatedWindowsIdentity ExpectedWindows,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AuthorizationReference);

public sealed record CompanionDelegatedConsentReceipt(
    int SchemaVersion,
    Guid GrantId,
    string AuthorizationSource,
    Guid TargetId,
    string TargetBinding,
    CompanionPeerIdentity MacIdentity,
    CompanionDelegatedWindowsIdentity ExpectedWindows,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AuthorizationReference,
    string RequestSha256,
    string WindowsUserSid,
    int WindowsSessionId,
    DateTimeOffset ApprovedAtUtc);

public static class CompanionDelegatedEnrollmentValidation
{
    public const int MaximumRequestBytes = 16 * 1024;
    public const string AuthorizationSource = "ownerDelegated";
    public const string AuthorizationReference = "device-ai-control-enabled";
    private static readonly string[] RequestFields = [
        "schemaVersion", "grantId", "authorizationSource", "targetId", "targetBinding",
        "macIdentity", "expectedWindows", "issuedAtUtc", "expiresAtUtc", "authorizationReference",
    ];

    public static CompanionDelegatedEnrollmentRequest Parse(
        ReadOnlySpan<byte> utf8, string expectedSha256, DateTimeOffset now)
    {
        if (utf8.IsEmpty || utf8.Length > MaximumRequestBytes) throw Invalid();
        var expectedDigest = Fingerprint(expectedSha256);
        if (!CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(utf8), Convert.FromHexString(expectedDigest)))
        {
            throw new CompanionProtocolException("DELEGATED_ENROLLMENT_DIGEST_MISMATCH", "The enrollment request checksum does not match.");
        }

        try
        {
            var text = new UTF8Encoding(false, true).GetString(utf8);
            using var document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            RequireFields(root, RequestFields);
            var mac = root.GetProperty("macIdentity");
            RequireFields(mac, ["deviceId", "fingerprintSha256", "publicKeyBase64"]);
            var windows = root.GetProperty("expectedWindows");
            RequireFields(windows, ["deviceId", "fingerprintSha256"]);
            if (!root.GetProperty("schemaVersion").TryGetInt32(out var schema)) throw Invalid();
            var request = Normalize(new CompanionDelegatedEnrollmentRequest(
                schema, GuidValue(root, "grantId"), Text(root, "authorizationSource"),
                GuidValue(root, "targetId"), Text(root, "targetBinding"),
                new CompanionPeerIdentity(GuidValue(mac, "deviceId"), Text(mac, "fingerprintSha256"), Text(mac, "publicKeyBase64")),
                new CompanionDelegatedWindowsIdentity(GuidValue(windows, "deviceId"), Text(windows, "fingerprintSha256")),
                DateValue(root, "issuedAtUtc"), DateValue(root, "expiresAtUtc"), Text(root, "authorizationReference")));
            return ValidateRequest(request, now);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or InvalidOperationException or FormatException)
        {
            throw Invalid();
        }
    }

    public static CompanionDelegatedEnrollmentRequest ValidateRequest(
        CompanionDelegatedEnrollmentRequest request, DateTimeOffset now)
    {
        request = Normalize(request);
        if (now < request.IssuedAtUtc || now >= request.ExpiresAtUtc)
        {
            throw new CompanionProtocolException("DELEGATED_ENROLLMENT_EXPIRED", "The enrollment request is outside its import window.");
        }
        return request;
    }

    public static void ValidateWindowsBinding(
        CompanionDelegatedEnrollmentRequest request, CompanionIdentityMetadata windowsIdentity)
    {
        request = Normalize(request);
        if (windowsIdentity is null) throw Invalid();
        var actual = NormalizePeer(new CompanionPeerIdentity(
            windowsIdentity.DeviceId, windowsIdentity.FingerprintSha256, windowsIdentity.PublicKeyBase64));
        if (actual.DeviceId != request.ExpectedWindows.DeviceId
            || actual.FingerprintSha256 != request.ExpectedWindows.FingerprintSha256)
        {
            throw new CompanionProtocolException("DELEGATED_ENROLLMENT_WINDOWS_MISMATCH", "The enrollment request names a different Windows identity.");
        }
    }

    public static CompanionDelegatedConsentReceipt NormalizeReceipt(
        CompanionDelegatedConsentReceipt receipt, CompanionPeerIdentity peer)
    {
        if (receipt is null) throw Invalid();
        var request = Normalize(new CompanionDelegatedEnrollmentRequest(
            receipt.SchemaVersion, receipt.GrantId, receipt.AuthorizationSource, receipt.TargetId,
            receipt.TargetBinding, receipt.MacIdentity, receipt.ExpectedWindows,
            receipt.IssuedAtUtc, receipt.ExpiresAtUtc, receipt.AuthorizationReference));
        if (!CompanionPeerIdentityValidation.Matches(request.MacIdentity, NormalizePeer(peer))
            || receipt.ApprovedAtUtc < request.IssuedAtUtc
            || receipt.ApprovedAtUtc >= request.ExpiresAtUtc
            || receipt.WindowsSessionId < 0 || !ValidSid(receipt.WindowsUserSid)) throw Invalid();
        // Expiry gates import only. A persisted approval remains valid after that window.
        return receipt with
        {
            MacIdentity = request.MacIdentity,
            ExpectedWindows = request.ExpectedWindows,
            IssuedAtUtc = request.IssuedAtUtc,
            ExpiresAtUtc = request.ExpiresAtUtc,
            ApprovedAtUtc = receipt.ApprovedAtUtc.ToUniversalTime(),
            RequestSha256 = Fingerprint(receipt.RequestSha256),
        };
    }

    private static CompanionDelegatedEnrollmentRequest Normalize(CompanionDelegatedEnrollmentRequest request)
    {
        if (request is null || request.SchemaVersion != 1 || request.GrantId == Guid.Empty
            || request.TargetId == Guid.Empty || request.AuthorizationSource != AuthorizationSource
            || request.AuthorizationReference != AuthorizationReference
            || string.IsNullOrWhiteSpace(request.TargetBinding) || request.TargetBinding.Length > 512
            || request.TargetBinding.Any(char.IsControl) || request.ExpectedWindows is null
            || request.ExpectedWindows.DeviceId == Guid.Empty
            || request.ExpiresAtUtc <= request.IssuedAtUtc
            || request.ExpiresAtUtc - request.IssuedAtUtc > TimeSpan.FromMinutes(30)) throw Invalid();
        return request with
        {
            MacIdentity = NormalizePeer(request.MacIdentity),
            ExpectedWindows = request.ExpectedWindows with { FingerprintSha256 = Fingerprint(request.ExpectedWindows.FingerprintSha256) },
            IssuedAtUtc = request.IssuedAtUtc.ToUniversalTime(),
            ExpiresAtUtc = request.ExpiresAtUtc.ToUniversalTime(),
        };
    }

    private static CompanionPeerIdentity NormalizePeer(CompanionPeerIdentity peer)
    {
        if (peer is null) throw Invalid();
        try
        {
            var normalized = CompanionPeerIdentityValidation.Normalize(peer);
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(normalized.PublicKeyBase64), out _);
            if (verifier.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7") throw Invalid();
            return normalized;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or PlatformNotSupportedException)
        {
            throw Invalid();
        }
    }

    private static string Fingerprint(string value)
    {
        if (value is null || value.Length != 64 || !value.All(Uri.IsHexDigit)) throw Invalid();
        return value.ToUpperInvariant();
    }

    private static bool ValidSid(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 184) return false;
        var parts = value.Split('-');
        if (parts.Length is < 4 or > 18 || parts[0] != "S" || parts[1] != "1"
            || !ulong.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var authority)
            || authority > 0xFFFFFFFFFFFF) return false;
        return parts.Skip(3).All(part => uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }

    private static void RequireFields(JsonElement value, string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var remaining = new HashSet<string>(expected, StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!remaining.Remove(property.Name)) throw Invalid();
        }
        if (remaining.Count != 0) throw Invalid();
    }

    private static string Text(JsonElement value, string property)
    {
        var field = value.GetProperty(property);
        if (field.ValueKind != JsonValueKind.String) throw Invalid();
        return field.GetString() ?? throw Invalid();
    }

    private static Guid GuidValue(JsonElement value, string property) =>
        Guid.TryParseExact(Text(value, property), "D", out var result) && result != Guid.Empty ? result : throw Invalid();

    private static DateTimeOffset DateValue(JsonElement value, string property)
    {
        var text = Text(value, property);
        var hasZone = text.EndsWith('Z')
            || (text.Length >= 25 && (text[^6] is '+' or '-') && text[^3] == ':');
        if (text.Length > 40 || !hasZone || !value.GetProperty(property).TryGetDateTimeOffset(out var date)) throw Invalid();
        return date.ToUniversalTime();
    }

    private static CompanionProtocolException Invalid() =>
        new("DELEGATED_ENROLLMENT_INVALID", "The delegated enrollment metadata is invalid.");
}
