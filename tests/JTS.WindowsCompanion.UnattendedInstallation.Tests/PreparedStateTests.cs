using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class PreparedStateTests
{
    [Fact]
    public void ReceiptRequiresExactIdentityInventoryAndClosedFiles()
    {
        using var f = new ReceiptFixture(); var result = f.Verify();
        Assert.Equal(f.Device, result.DeviceId); Assert.Equal(64, result.ReceiptSha256.Length);
    }
    [Theory]
    [InlineData("identity")] [InlineData("account")] [InlineData("enrollment")] [InlineData("state")]
    [InlineData("before")] [InlineData("future")] [InlineData("missing-file")]
    [InlineData("corrupt-file")] [InlineData("extra-sidecar")] [InlineData("duplicate-file")]
    [InlineData("extra-field")] [InlineData("traversal")]
    public void ChangedOrForeignReadinessCannotPublish(string kind)
    {
        using var f = new ReceiptFixture(); var root = JsonNode.Parse(File.ReadAllBytes(f.Receipt))!;
        switch (kind)
        {
            case "identity": root["identity"]!["DeviceId"] = new string('c', 64); break;
            case "account": root["workerSid"] = f.Snapshot.Authority!.Sid; break;
            case "enrollment": root["enrollmentId"] = Guid.NewGuid(); break;
            case "state": root["state"] = "enabled"; break;
            case "before": root["preparedAt"] = f.Now.AddMinutes(-2); break;
            case "future": root["preparedAt"] = f.Now.AddSeconds(1); break;
            case "missing-file": File.Delete(Path.Combine(f.Directory, "jobs.sqlite")); break;
            case "corrupt-file": File.AppendAllText(Path.Combine(f.Directory, "identity.sealed"), "bad"); break;
            case "extra-sidecar": File.WriteAllText(Path.Combine(f.Directory, "jobs.sqlite-wal"), "pending"); break;
            case "duplicate-file": root["files"]![1]!["name"] = "identity.sealed"; break;
            case "extra-field": root["password"] = "forbidden"; break;
            case "traversal": root["files"]![0]!["name"] = "../outside"; break;
        }
        File.WriteAllText(f.Receipt, root.ToJsonString()); Assert.ThrowsAny<IOException>(() => f.Verify());
    }
    private sealed class ReceiptFixture : IDisposable
    {
        private readonly InstallationFixture _installation = new();
        internal string Directory { get; }
        internal string Receipt => Path.Combine(Directory, "ready.json");
        internal DateTimeOffset Now { get; } = new(2026, 9, 19, 10, 0, 0, TimeSpan.Zero);
        internal string Device { get; }
        internal InstallSnapshot Snapshot { get; }
        internal ReceiptFixture()
        {
            Directory = System.IO.Directory.CreateDirectory(Path.Combine(_installation.Root, "state")).FullName;
            Snapshot = _installation.Initial with { Phase = InstallPhase.AccountsCreated,
                Authority = _installation.Account("authority"), Worker = _installation.Account("worker") };
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var cert = new CertificateRequest("CN=fixture", key, HashAlgorithmName.SHA256).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
            var spki = key.ExportSubjectPublicKeyInfo(); Device = Convert.ToHexStringLower(SHA256.HashData(spki));
            var files = new[] { "identity.sealed", "pairings.sqlite", "control-grants.sqlite", "jobs.sqlite" }.Select(name =>
            {
                var bytes = RandomNumberGenerator.GetBytes(64); File.WriteAllBytes(Path.Combine(Directory, name), bytes);
                return new { name, bytes = bytes.Length, sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) };
            }).ToArray();
            File.WriteAllBytes(Receipt, JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, enrollmentId = Snapshot.EnrollmentId,
                state = "staged-not-enabled", authoritySid = Snapshot.Authority.Sid, workerSid = Snapshot.Worker.Sid, preparedAt = Now,
                identity = new { DeviceId = Device, PublicKeySpkiBase64 = Convert.ToBase64String(spki), CertificateDerBase64 = Convert.ToBase64String(cert.RawData),
                    CertificateExpiresAt = new DateTimeOffset(cert.NotAfter.ToUniversalTime()) }, files }));
        }
        internal PreparedAuthorityState Verify() => PreparedStateVerifier.Verify(Directory, Snapshot, Now.AddMinutes(-1), Now);
        public void Dispose() => _installation.Dispose();
    }
}
