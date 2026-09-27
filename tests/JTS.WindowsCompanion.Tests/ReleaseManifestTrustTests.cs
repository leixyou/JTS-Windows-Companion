using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class ReleaseManifestTrustTests : IDisposable
{
    private const string Agent = "JTS.WindowsCompanion.Agent.exe";
    private const string Broker = "JTS.WindowsCompanion.UacBroker.exe";
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "jts-release-tests-" + Guid.NewGuid().ToString("N"));

    public ReleaseManifestTrustTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void VerifiedRelease_AcceptsExactUnsignedFilesAndReturnsLockedHandle()
    {
        var path = Write(Agent, "unsigned agent");
        var payload = Payload(Agent, Hash("unsigned agent"));
        var release = Verify(payload);
        Assert.Equal(1, release.SchemaVersion);
        Assert.Equal(new[] { Agent }, release.FileNames);
        Assert.Equal("2.0.0-test", release.ReleaseId);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))), release.PayloadSha256);
        using var file = release.OpenVerifiedFile(path, Agent);
        Assert.Equal(0, file.Position);
        Assert.False(file.CanWrite);
        Assert.Equal("unsigned agent", new StreamReader(file, leaveOpen: true).ReadToEnd());
        if (OperatingSystem.IsWindows())
            Assert.Throws<IOException>(() => File.Open(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite).Dispose());
    }

    [Fact]
    public void VerifiedRelease_RejectsTamperedMixedOrWrongRoleExecutable()
    {
        var path = Write(Agent, "other release");
        var release = Verify(Payload(Agent, Hash("approved agent")));
        Assert.Throws<UnauthorizedAccessException>(() => release.VerifyFile(path, Agent));
        File.WriteAllText(path, "approved agent");
        Assert.Throws<UnauthorizedAccessException>(() => release.VerifyFile(path, Broker));
        var renamed = Write(Broker, "approved agent");
        Assert.Throws<UnauthorizedAccessException>(() => release.VerifyFile(renamed, Agent));
    }

    [Fact]
    public void BundleSchema_VerifiesNativeLibrariesAndExposesOnlyImmutableNames()
    {
        const string library = "e_sqlite3.dll";
        var executable = Write(Agent, "managed single-file app");
        var native = Write(library, "approved native library");
        var payload = JsonSerializer.Serialize(new { schemaVersion = 2, releaseId = "2.5.0-test", files = new[]
        {
            new { fileName = library, sha256 = Hash("approved native library") },
            new { fileName = Agent, sha256 = Hash("managed single-file app") },
        }});
        var release = Verify(payload);
        Assert.Equal(2, release.SchemaVersion);
        Assert.Equal(new[] { Agent, library }, release.FileNames);
        var names = Assert.IsAssignableFrom<IList<string>>(release.FileNames);
        Assert.True(names.IsReadOnly);
        Assert.Throws<NotSupportedException>(() => names[0] = "attacker.dll");
        release.VerifyFile(executable, Agent);
        using (var lease = release.OpenVerifiedFile(native, library))
        {
            Assert.False(lease.CanWrite);
            Assert.Equal(0, lease.Position);
        }
        File.WriteAllText(native, "changed native library");
        Assert.Throws<UnauthorizedAccessException>(() => release.VerifyFile(native, library));
        Assert.Throws<UnauthorizedAccessException>(() => release.VerifyFile(executable, "unlisted.dll"));
    }

    [Theory]
    [InlineData(1, 64, true)]
    [InlineData(1, 65, false)]
    [InlineData(2, 128, true)]
    [InlineData(2, 129, false)]
    [InlineData(2, 0, false)]
    public void Verify_EnforcesSchemaInventoryBounds(int schemaVersion, int count, bool accepted)
    {
        // Maximum length names keep even the 128-entry schema-2 envelope below the unchanged 64 KiB limit.
        var payload = JsonSerializer.Serialize(new { schemaVersion, releaseId = "test", files = Enumerable.Range(0, count)
            .Select(i => new { fileName = new string('a', 120) + i.ToString("D4") + ".exe", sha256 = Hash("payload") }).ToArray() });
        if (accepted)
        {
            Assert.InRange(Sign(payload).Length, 1, 65536);
            Assert.Equal(count, Verify(payload).FileNames.Count);
        }
        else Assert.Throws<UnauthorizedAccessException>(() => Verify(payload));
    }

    [Theory]
    [InlineData("e_sqlite3.dll")]
    [InlineData("CoreCLR.DLL")]
    public void Verify_DllNamesRequireBundleSchema(string name)
    {
        Assert.Throws<UnauthorizedAccessException>(() => Verify(Payload(name, Hash("native"))));
        Assert.Equal(name, Assert.Single(Verify(Payload(name, Hash("native"), schemaVersion: 2)).FileNames));
    }

    [Theory]
    [InlineData("../runtime.dll")]
    [InlineData("runtime\\native.dll")]
    [InlineData("runtime/native.dll")]
    [InlineData("runtime.dll:stream")]
    [InlineData("runtime.dll ")]
    [InlineData("runtime.runtimeconfig.json")]
    [InlineData("runtime.deps.json")]
    [InlineData("runtime.pdb")]
    [InlineData("runtime.so")]
    [InlineData("runtime.dll.exe.config")]
    [InlineData(".dll")]
    [InlineData("NUL.dll")]
    [InlineData("con.exe")]
    [InlineData("COM1.native.dll")]
    [InlineData("Lpt9.dll")]
    public void BundleSchema_RejectsUnsafeOrNonbinaryNames(string name) =>
        Assert.Throws<UnauthorizedAccessException>(() => Verify(Payload(name, Hash("native"), schemaVersion: 2)));

    [Fact]
    public void BundleSchema_RejectsOversizeNamesDuplicatesAndUnsupportedVersion()
    {
        Assert.Throws<UnauthorizedAccessException>(() => Verify(Payload(new string('a', 125) + ".dll", Hash("native"), 2)));
        var hash = Hash("native");
        var payload = JsonSerializer.Serialize(new { schemaVersion = 2, releaseId = "test", files = new[]
        {
            new { fileName = "runtime.dll", sha256 = hash }, new { fileName = "RUNTIME.DLL", sha256 = hash },
        }});
        Assert.Throws<UnauthorizedAccessException>(() => Verify(payload));
        foreach (var unsupported in new[] { 0, 3, int.MaxValue })
            Assert.Throws<UnauthorizedAccessException>(() => Verify(Payload(Agent, hash, unsupported)));
    }

    [Fact]
    public void Verify_RejectsWrongKeyAndTamperedSignedPayload()
    {
        var payload = Payload(Agent, Hash("approved agent"));
        var envelope = Sign(payload);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<UnauthorizedAccessException>(() => ReleaseManifestTrust.Verify(envelope, wrongKey.ExportSubjectPublicKeyInfoPem()));
        var altered = JsonSerializer.SerializeToUtf8Bytes(new
        {
            payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.Replace("2.0.0-test", "2.0.0-evil"))),
            signature = Convert.ToBase64String(_key.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
        });
        Assert.Throws<UnauthorizedAccessException>(() => ReleaseManifestTrust.Verify(altered, _key.ExportSubjectPublicKeyInfoPem()));
    }

    [Theory]
    [InlineData("{\"schemaVersion\":1,\"schemaVersion\":1,\"releaseId\":\"test\",\"files\":[]}")]
    [InlineData("{\"schemaVersion\":2,\"releaseId\":\"test\",\"files\":[]}")]
    [InlineData("{\"schemaVersion\":1,\"releaseId\":\"test\",\"files\":[],\"allowUnsigned\":true}")]
    [InlineData("{\"schemaVersion\":1,\"releaseId\":\"test\",\"files\":[]}")]
    [InlineData("{\"schemaVersion\":1,\"releaseId\":\"\",\"files\":[]}")]
    [InlineData("{\"schemaVersion\":1,\"releaseId\":\"test\"}")]
    [InlineData("{\"schemaVersion\":2,\"schemaVersion\":2,\"releaseId\":\"test\",\"files\":[]}")]
    [InlineData("{\"schemaVersion\":2,\"releaseId\":\"test\",\"files\":[],\"nativeDirectory\":\"anywhere\"}")]
    public void Verify_RejectsMalformedSignedSchema(string payload) =>
        Assert.Throws<UnauthorizedAccessException>(() => Verify(payload));

    [Theory]
    [InlineData("../Agent.exe")]
    [InlineData("folder\\Agent.exe")]
    [InlineData("Agent.exe:stream")]
    [InlineData("Agent.exe ")]
    [InlineData("Agent.dll")]
    [InlineData("*")]
    public void Verify_RejectsUnsafeFileName(string name) =>
        Assert.Throws<UnauthorizedAccessException>(() => Verify(Payload(name, Hash("agent"))));

    [Fact]
    public void Verify_RejectsDuplicateFileNamesAndUntrustedChecksums()
    {
        var hash = Hash("agent");
        var payload = JsonSerializer.Serialize(new { schemaVersion = 1, releaseId = "test", files = new[]
        {
            new { fileName = Agent, sha256 = hash }, new { fileName = Agent.ToUpperInvariant(), sha256 = hash },
        }});
        Assert.Throws<UnauthorizedAccessException>(() => Verify(payload));
        Assert.Throws<UnauthorizedAccessException>(() => Verify(Payload(Agent, "arbitrary-checksum")));
    }

    [Theory]
    [InlineData("{\"payload\":\"\",\"signature\":\"\",\"signature\":\"\"}")]
    [InlineData("{\"payload\":\"\",\"signature\":\"\",\"publicKey\":\"attacker-key\"}")]
    [InlineData("{\"payload\":\"YQ==\\n\",\"signature\":\"\"}")]
    [InlineData("[]")]
    public void Verify_RejectsAmbiguousEnvelope(string envelope) =>
        Assert.Throws<UnauthorizedAccessException>(() => ReleaseManifestTrust.Verify(Encoding.UTF8.GetBytes(envelope), _key.ExportSubjectPublicKeyInfoPem()));

    [Fact]
    public void Verify_RejectsPrivateKeyWrongCurveAndOversizeEnvelope()
    {
        var envelope = Sign(Payload(Agent, Hash("agent")));
        Assert.Throws<UnauthorizedAccessException>(() => ReleaseManifestTrust.Verify(envelope, _key.ExportPkcs8PrivateKeyPem()));
        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<UnauthorizedAccessException>(() => ReleaseManifestTrust.Verify(envelope, wrongCurve.ExportSubjectPublicKeyInfoPem()));
        Assert.Throws<UnauthorizedAccessException>(() => ReleaseManifestTrust.Verify(new byte[65537], _key.ExportSubjectPublicKeyInfoPem()));
    }

    [Fact]
    public void VerifiedRelease_RejectsSymbolicLink()
    {
        if (OperatingSystem.IsWindows()) return; // Windows reparse-point acceptance is also exercised on its authorized runner.
        var target = Write("target.exe", "agent");
        var link = Path.Combine(_directory, Agent);
        File.CreateSymbolicLink(link, target);
        Assert.Throws<UnauthorizedAccessException>(() => Verify(Payload(Agent, Hash("agent"))).VerifyFile(link, Agent));
    }

    [Fact]
    public void LoadForExecutable_DoesNotTrustAdjacentOrEnvironmentPublicKey()
    {
        // A default test build has no embedded release anchor. Even a valid adjacent manifest/key is not trusted.
        if (typeof(ReleaseManifestTrust).Assembly.GetManifestResourceNames().Contains("JTS.Companion.ReleasePublicKey")) return;
        var path = Write(Agent, "agent");
        File.WriteAllBytes(Path.Combine(_directory, ReleaseManifestTrust.ManifestFileName), Sign(Payload(Agent, Hash("agent"))));
        Write("release-public.pem", _key.ExportSubjectPublicKeyInfoPem());
        Assert.Throws<UnauthorizedAccessException>(() => ReleaseManifestTrust.LoadForExecutable(path));
    }

    private VerifiedReleaseManifest Verify(string payload) => ReleaseManifestTrust.Verify(Sign(payload), _key.ExportSubjectPublicKeyInfoPem());
    private byte[] Sign(string payload)
    {
        var bytes = Encoding.UTF8.GetBytes(payload);
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            payload = Convert.ToBase64String(bytes),
            signature = Convert.ToBase64String(_key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
        });
    }
    private static string Payload(string name, string hash, int schemaVersion = 1) => JsonSerializer.Serialize(new
    {
        schemaVersion, releaseId = "2.0.0-test", files = new[] { new { fileName = name, sha256 = hash } },
    });
    private static string Hash(string content) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
    private string Write(string name, string content)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, content);
        return path;
    }
    public void Dispose()
    {
        _key.Dispose();
        Directory.Delete(_directory, recursive: true);
    }
}
