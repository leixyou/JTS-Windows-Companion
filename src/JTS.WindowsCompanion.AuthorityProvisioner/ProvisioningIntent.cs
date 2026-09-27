using System.Globalization;
using System.Text;
using System.Text.Json;

namespace JTS.WindowsCompanion.AuthorityProvisioner;

// Written by the future elevated installer, not supplied by relay/CLI data or treated as consent proof.
internal sealed record ProvisioningIntent(Guid EnrollmentId, string AuthoritySid, string WorkerSid,
    DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, string? DelegationSha256 = null)
{
    internal const int MaximumBytes = 4096;
    internal static Guid ParseArguments(string[] args)
    {
        if (args is not ["--provision", var id] || !CanonicalId(id, out var enrollment))
            throw new ProvisioningException("PROVISION_ARGUMENTS_REJECTED");
        return enrollment;
    }
    internal static ProvisioningIntent Parse(byte[] bytes, Guid expectedEnrollment, string currentAccount, TimeProvider clock)
    {
        try
        {
            if (bytes.Length is < 1 or > MaximumBytes) throw Invalid();
            _ = new UTF8Encoding(false, true).GetString(bytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
            var root = document.RootElement;
            var names = new HashSet<string>(["schemaVersion", "operation", "enrollmentId", "authoritySid", "workerSid", "createdAt", "expiresAt"], StringComparer.Ordinal);
            if (root.TryGetProperty("delegationSha256", out _)) names.Add("delegationSha256");
            if (root.ValueKind != JsonValueKind.Object) throw Invalid();
            foreach (var property in root.EnumerateObject()) if (!names.Remove(property.Name)) throw Invalid();
            if (names.Count != 0 || root.GetProperty("schemaVersion").GetInt32() != 1
                || Text(root, "operation") != "initialize-new-authority") throw Invalid();
            if (!CanonicalId(Text(root, "enrollmentId"), out var id) || id != expectedEnrollment) throw Invalid();
            var authority = Text(root, "authoritySid"); var worker = Text(root, "workerSid");
            if (!StandardSid(authority) || !StandardSid(worker) || authority != currentAccount || authority == worker) throw Invalid();
            var hash = root.TryGetProperty("delegationSha256", out _) ? Text(root, "delegationSha256") : null;
            if (hash is not null && (hash.Length != 64 || hash.Any(c => !"0123456789abcdef".Contains(c)))) throw Invalid();
            var intent = new ProvisioningIntent(id, authority, worker, Timestamp(root, "createdAt"), Timestamp(root, "expiresAt"), hash);
            intent.RequireCurrent(clock); return intent;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or FormatException or OverflowException)
        { throw Invalid(); }
    }
    internal void RequireCurrent(TimeProvider clock)
    {
        var now = clock.GetUtcNow();
        if (CreatedAt > now || ExpiresAt <= now || ExpiresAt <= CreatedAt || ExpiresAt - CreatedAt > TimeSpan.FromMinutes(30))
            throw new ProvisioningException("PROVISION_INTENT_EXPIRED_OR_INVALID");
    }
    private static DateTimeOffset Timestamp(JsonElement root, string name)
    {
        if (!DateTimeOffset.TryParseExact(Text(root, name), "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out var value)
            || value.Offset != TimeSpan.Zero) throw Invalid();
        return value;
    }
    private static string Text(JsonElement root, string name)
    {
        var value = root.GetProperty(name).GetString();
        if (value is not { Length: > 0 and <= 100 } || value.Any(char.IsControl)) throw Invalid();
        return value;
    }
    private static bool CanonicalId(string text, out Guid id)
        => Guid.TryParseExact(text, "D", out id) && id != Guid.Empty && id.ToString("D") == text;
    private static bool StandardSid(string sid)
    {
        var parts = sid.Split('-');
        return parts.Length == 8 && sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            && parts.Skip(4).All(p => uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                && value.ToString(CultureInfo.InvariantCulture) == p) && uint.Parse(parts[7], CultureInfo.InvariantCulture) >= 1000;
    }
    private static ProvisioningException Invalid() => new("PROVISION_INTENT_INVALID");
}

internal sealed class ProvisioningException(string code) : IOException(code)
{ internal string Code { get; } = code; }
