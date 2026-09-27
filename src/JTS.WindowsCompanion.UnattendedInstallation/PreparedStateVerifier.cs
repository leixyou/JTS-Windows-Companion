using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal sealed record PreparedAuthorityState(string DeviceId, string ReceiptSha256, string? PublicKeySpkiBase64 = null);

internal static class PreparedStateVerifier
{
    private static readonly string[] Files = ["identity.sealed", "pairings.sqlite", "control-grants.sqlite", "jobs.sqlite"];
    internal static PreparedAuthorityState Verify(string directory, InstallSnapshot expected, DateTimeOffset started, DateTimeOffset now)
    {
        try
        {
            InstallJournal.RejectLinks(directory);
            var receiptPath = Path.Combine(directory, "ready.json"); InstallJournal.RejectLinks(receiptPath);
            using var receipt = new FileStream(receiptPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (receipt.Length is < 1 or > 16384) throw Invalid();
            var bytes = new byte[(int)receipt.Length]; receipt.ReadExactly(bytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 5 });
            var root = document.RootElement;
            Properties(root, "schemaVersion", "enrollmentId", "state", "authoritySid", "workerSid", "preparedAt", "identity", "files");
            if (root.GetProperty("schemaVersion").GetInt32() != 1 || root.GetProperty("state").GetString() != "staged-not-enabled"
                || root.GetProperty("enrollmentId").GetString() != expected.EnrollmentId.ToString("D")
                || root.GetProperty("authoritySid").GetString() != expected.Authority?.Sid
                || root.GetProperty("workerSid").GetString() != expected.Worker?.Sid) throw Invalid();
            var prepared = root.GetProperty("preparedAt").GetDateTimeOffset();
            if (prepared < started || prepared > now || now - started > TimeSpan.FromMinutes(30)) throw Invalid();
            var identity = root.GetProperty("identity"); Properties(identity, "DeviceId", "PublicKeySpkiBase64", "CertificateDerBase64", "CertificateExpiresAt");
            var device = identity.GetProperty("DeviceId").GetString();
            var spki = Convert.FromBase64String(identity.GetProperty("PublicKeySpkiBase64").GetString() ?? "");
            var der = Convert.FromBase64String(identity.GetProperty("CertificateDerBase64").GetString() ?? "");
            if (!InstallSnapshot.Hash(device) || spki.Length is < 1 or > 512 || der.Length is < 1 or > 8192
                || Convert.ToHexStringLower(SHA256.HashData(spki)) != device) throw Invalid();
            using var cert = X509CertificateLoader.LoadCertificate(der);
            using var key = cert.GetECDsaPublicKey();
            if (key is null || key.KeySize != 256 || !key.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(spki)
                || new DateTimeOffset(cert.NotAfter.ToUniversalTime()) != identity.GetProperty("CertificateExpiresAt").GetDateTimeOffset()
                || cert.NotAfter.ToUniversalTime() <= now.UtcDateTime.AddDays(1) || cert.NotBefore.ToUniversalTime() > now.UtcDateTime) throw Invalid();
            var inventory = root.GetProperty("files");
            var files = File.Exists(Path.Combine(directory, "delegation-receipt.json")) ? Files.Append("delegation-receipt.json").ToArray() : Files;
            if (inventory.ValueKind != JsonValueKind.Array || inventory.GetArrayLength() != files.Length) throw Invalid();
            var remaining = files.ToHashSet(StringComparer.Ordinal);
            foreach (var entry in inventory.EnumerateArray())
            {
                Properties(entry, "name", "bytes", "sha256"); var name = entry.GetProperty("name").GetString() ?? "";
                if (!remaining.Remove(name) || !InstallSnapshot.Hash(entry.GetProperty("sha256").GetString())) throw Invalid();
                var path = Path.Combine(directory, name); InstallJournal.RejectLinks(path);
                using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (file.Length is < 1 or > 16777216 || file.Length != entry.GetProperty("bytes").GetInt64()
                    || Convert.ToHexStringLower(SHA256.HashData(file)) != entry.GetProperty("sha256").GetString()) throw Invalid();
            }
            var allowed = files.Concat(Files.Select(n => n + ".lease")).Concat(["attempt.json", "ready.json"]).ToHashSet(StringComparer.Ordinal);
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            { InstallJournal.RejectLinks(path); if (Directory.Exists(path) || !allowed.Contains(Path.GetFileName(path))) throw Invalid(); }
            return new(device!, Convert.ToHexStringLower(SHA256.HashData(bytes)), Convert.ToBase64String(spki));
        }
        catch (Exception error) when (error is JsonException or CryptographicException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        { throw Invalid(); }
    }
    private static void Properties(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var names = fields.ToHashSet(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) if (!names.Remove(property.Name)) throw Invalid();
        if (names.Count != 0) throw Invalid();
    }
    private static UnattendedInstallationException Invalid() => new("INSTALL_PREPARED_STATE_INVALID");
}
