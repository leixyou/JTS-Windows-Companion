using System.Globalization;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.WorkerService;

namespace JTS.WindowsCompanion.AuthorityService;

internal sealed record AuthorityConfiguration(Guid EnrollmentId, string DeviceId, string AuthoritySid, Uri RelayOrigin,
    WorkerServiceInstallation Worker)
{
    internal const int MaximumBytes = 16384;
    internal const string ServiceName = "JTSCompanionAuthority25";
    internal static AuthorityConfiguration Parse(byte[] bytes)
    {
        try
        {
            if (bytes.Length is < 1 or > MaximumBytes) throw Invalid();
            _ = new UTF8Encoding(false, true).GetString(bytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            Properties(root, "schemaVersion", "enabled", "enrollmentId", "deviceId", "authoritySid", "relayOrigin", "worker");
            if (root.GetProperty("schemaVersion").GetInt32() != 1) throw Invalid();
            if (!root.GetProperty("enabled").GetBoolean()) throw new AuthorityException("AUTHORITY_ROUTE_DISABLED");
            var enrollment = String(root, "enrollmentId", 36);
            if (!Guid.TryParseExact(enrollment, "D", out var id) || id == Guid.Empty || id.ToString("D") != enrollment) throw Invalid();
            var device = String(root, "deviceId", 64);
            if (device.Length != 64 || device.Any(c => !"0123456789abcdef".Contains(c))) throw Invalid();
            var authority = String(root, "authoritySid", 100); DedicatedSid(authority);
            var worker = root.GetProperty("worker"); Properties(worker, "accountName", "accountSid", "executablePath");
            var installation = new WorkerServiceInstallation(String(worker, "executablePath", 240), String(worker, "accountName", 22), String(worker, "accountSid", 100));
            if (installation.AccountSid == authority) throw new AuthorityException("AUTHORITY_WORKER_ACCOUNT_MUST_DIFFER");
            var originText = String(root, "relayOrigin", 2048);
            if (originText.Any(c => char.IsControl(c) || c == '\\') || !Uri.TryCreate(originText, UriKind.Absolute, out var origin)
                || origin.Scheme != "https" || origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0
                || origin.AbsolutePath != "/") throw new AuthorityException("AUTHORITY_RELAY_ORIGIN_REJECTED");
            return new(id, device, authority, origin, installation);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException or ArgumentException or OverflowException)
        { throw Invalid(); }
    }
    private static void DedicatedSid(string sid)
    {
        var parts = sid.Split('-');
        if (parts.Length != 8 || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            || !parts.Skip(4).All(p => uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n)
                && n.ToString(CultureInfo.InvariantCulture) == p) || uint.Parse(parts[7], CultureInfo.InvariantCulture) < 1000) throw Invalid();
    }
    private static void Properties(JsonElement element, params string[] names)
    {
        if (element.ValueKind != JsonValueKind.Object) throw Invalid();
        var remaining = names.ToHashSet(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject()) if (!remaining.Remove(property.Name)) throw Invalid();
        if (remaining.Count != 0) throw Invalid();
    }
    private static string String(JsonElement root, string name, int length)
    {
        var result = root.GetProperty(name).GetString();
        if (result is null || result.Length is < 1 || result.Length > length || result.Any(c => char.IsControl(c))) throw Invalid();
        return result;
    }
    private static AuthorityException Invalid() => new("AUTHORITY_CONFIGURATION_INVALID");
}

internal sealed class AuthorityException(string code) : IOException(code)
{ internal string Code { get; } = code; }
