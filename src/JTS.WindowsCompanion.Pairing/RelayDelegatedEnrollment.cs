using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Pairing;

/// <summary>Public owner-delegated installation input. A node or remote RPC cannot import it.</summary>
public sealed record RelayDelegatedEnrollment(string ControllerDeviceID, string ControllerSPKIBase64,
    Guid PairingID, Guid GrantID, Guid FileGrantID, Guid RdpGrantID, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc)
{
    public const int MaximumBytes = 8192;
    public static RelayDelegatedEnrollment Parse(byte[] bytes, TimeProvider? clock = null)
    {
        try
        {
            if (bytes.Length is < 1 or > MaximumBytes) throw Invalid();
            _ = new UTF8Encoding(false, true).GetString(bytes);
            using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 }); var p = json.RootElement;
            var fields = new HashSet<string>(["version", "authorizationSource", "authorizationReference", "controllerDeviceID", "controllerSPKIBase64",
                "pairingID", "grantID", "fileGrantID", "rdpGrantID", "issuedAtUtc", "expiresAtUtc"], StringComparer.Ordinal);
            if (p.ValueKind != JsonValueKind.Object) throw Invalid();
            foreach (var entry in p.EnumerateObject()) if (!fields.Remove(entry.Name)) throw Invalid();
            if (fields.Count != 0 || p.GetProperty("version").GetInt32() != 1 || Text(p, "authorizationSource") != "ownerDelegated"
                || Text(p, "authorizationReference") != "device-ai-control-enabled") throw Invalid();
            var device = Text(p, "controllerDeviceID"); PairingValidation.Device(device);
            var encoded = Text(p, "controllerSPKIBase64"); var spki = Convert.FromBase64String(encoded);
            if (spki.Length is < 1 or > 512 || Convert.ToBase64String(spki) != encoded || Convert.ToHexStringLower(SHA256.HashData(spki)) != device) throw Invalid();
            using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(spki, out var used);
            if (used != spki.Length || key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7") throw Invalid();
            var request = new RelayDelegatedEnrollment(device, encoded, Id(p, "pairingID"), Id(p, "grantID"), Id(p, "fileGrantID"), Id(p, "rdpGrantID"),
                p.GetProperty("issuedAtUtc").GetDateTimeOffset(), p.GetProperty("expiresAtUtc").GetDateTimeOffset());
            if (new[] { request.PairingID, request.GrantID, request.FileGrantID, request.RdpGrantID }.Distinct().Count() != 4) throw Invalid();
            request.RequireCurrent(clock ?? TimeProvider.System); return request;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or FormatException or InvalidOperationException or CryptographicException)
        { throw Invalid(); }
    }
    public void RequireCurrent(TimeProvider clock)
    {
        var now = clock.GetUtcNow();
        if (IssuedAtUtc.Offset != TimeSpan.Zero || ExpiresAtUtc.Offset != TimeSpan.Zero || IssuedAtUtc > now || ExpiresAtUtc <= now
            || ExpiresAtUtc <= IssuedAtUtc || ExpiresAtUtc - IssuedAtUtc > TimeSpan.FromMinutes(30)) throw Invalid();
    }
    public RelayDevicePairing Pairing() => new(PairingID, ControllerDeviceID, RelayTlsPolicy.Tls13, DateTimeOffset.MaxValue,
        [RelayLane.Control, RelayLane.File, RelayLane.Rdp], new Dictionary<RelayLane, IReadOnlyList<Guid>>
        { [RelayLane.Control] = [GrantID], [RelayLane.File] = [FileGrantID], [RelayLane.Rdp] = [RdpGrantID] });
    private static string Text(JsonElement p, string name) => p.GetProperty(name).GetString() is { Length: > 0 and <= 1024 } text ? text : throw Invalid();
    private static Guid Id(JsonElement p, string name)
    { var text = Text(p, name); return Guid.TryParseExact(text, "D", out var id) && id != Guid.Empty && id.ToString("D") == text ? id : throw Invalid(); }
    private static PairingStoreException Invalid() => new("DELEGATED_ENROLLMENT_INVALID");
}
