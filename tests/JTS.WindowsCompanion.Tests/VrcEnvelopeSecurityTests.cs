using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Worker;

namespace JTS.WindowsCompanion.Tests;

public sealed class VrcEnvelopeSecurityTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
    private const string JobId = "avatar-pilot-001";
    private const long TotalBytes = 12_345;
    private const string BundleSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task JobEnvelope_VerifiesPairedIdentitySignatureAndExactArtifactBinding()
    {
        using var windows = new TestIdentity(Guid.Parse("11111111-1111-4111-8111-111111111111"));
        using var client = new TestIdentity(Guid.Parse("22222222-2222-4222-8222-222222222222"));
        var security = Security(windows, client);
        var envelope = SignedJobEnvelope(windows, client);

        var verified = await security.VerifyJobAsync(
            Element(envelope),
            JobId,
            TotalBytes,
            BundleSha256,
            CancellationToken.None);

        Assert.Equal(JobId, verified.JobId);
        Assert.Equal(BundleSha256, verified.BundleSha256);
        Assert.Equal(client.DeviceId, verified.ClientDeviceId);
        Assert.Equal(windows.DeviceId, verified.WindowsDeviceId);
    }

    [Theory]
    [InlineData("job")]
    [InlineData("hash")]
    [InlineData("size")]
    [InlineData("identity")]
    [InlineData("signature")]
    [InlineData("expired")]
    public async Task JobEnvelope_FailsClosedWhenAnySignedBindingChanges(string mutation)
    {
        using var windows = new TestIdentity(Guid.Parse("11111111-1111-4111-8111-111111111111"));
        using var client = new TestIdentity(Guid.Parse("22222222-2222-4222-8222-222222222222"));
        var security = Security(windows, client);
        var envelope = SignedJobEnvelope(windows, client);
        envelope = mutation switch
        {
            "job" => envelope with { JobId = "avatar-pilot-002" },
            "hash" => envelope with { BundleSha256 = new string('a', 64) },
            "size" => envelope with { TotalBytes = TotalBytes + 1 },
            "identity" => envelope with { ClientDeviceId = Guid.NewGuid() },
            "signature" => envelope with { SignatureBase64 = Convert.ToBase64String(new byte[64]) },
            "expired" => envelope with
            {
                IssuedAtUnixMilliseconds = (Now - VrcEnvelopeSecurity.MaximumEnvelopeAge - TimeSpan.FromSeconds(1))
                    .ToUnixTimeMilliseconds(),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        var failure = await Assert.ThrowsAsync<CompanionProtocolException>(() => security.VerifyJobAsync(
            Element(envelope),
            mutation == "job" ? envelope.JobId : JobId,
            mutation == "size" ? envelope.TotalBytes : TotalBytes,
            mutation == "hash" ? envelope.BundleSha256 : BundleSha256,
            CancellationToken.None).AsTask());

        Assert.Equal("WORKER_JOB_SIGNATURE_INVALID", failure.Code);
    }

    [Fact]
    public async Task JobEnvelope_RejectsUnsignedAdditionalFields()
    {
        using var windows = new TestIdentity(Guid.Parse("11111111-1111-4111-8111-111111111111"));
        using var client = new TestIdentity(Guid.Parse("22222222-2222-4222-8222-222222222222"));
        var security = Security(windows, client);
        var envelope = Element(new
        {
            signed = SignedJobEnvelope(windows, client),
            shell = "not accepted",
        }).GetProperty("signed");
        var expanded = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
        {
            ["schemaVersion"] = envelope.GetProperty("schemaVersion").GetString(),
            ["windowsDeviceId"] = envelope.GetProperty("windowsDeviceId").GetGuid(),
            ["clientDeviceId"] = envelope.GetProperty("clientDeviceId").GetGuid(),
            ["clientFingerprintSha256"] = envelope.GetProperty("clientFingerprintSha256").GetString(),
            ["jobId"] = envelope.GetProperty("jobId").GetString(),
            ["totalBytes"] = envelope.GetProperty("totalBytes").GetInt64(),
            ["bundleSha256"] = envelope.GetProperty("bundleSha256").GetString(),
            ["issuedAtUnixMilliseconds"] = envelope.GetProperty("issuedAtUnixMilliseconds").GetInt64(),
            ["signatureBase64"] = envelope.GetProperty("signatureBase64").GetString(),
            ["shell"] = "not accepted",
        }, ControlMessageSerializer.Options);

        var failure = await Assert.ThrowsAsync<CompanionProtocolException>(() => security.VerifyJobAsync(
            expanded,
            JobId,
            TotalBytes,
            BundleSha256,
            CancellationToken.None).AsTask());

        Assert.Equal("WORKER_JOB_ENVELOPE_INVALID", failure.Code);
    }

    [Fact]
    public async Task ResultEnvelope_IsSignedByWindowsAndBindsPairedClientAndArtifact()
    {
        using var windows = new TestIdentity(Guid.Parse("11111111-1111-4111-8111-111111111111"));
        using var client = new TestIdentity(Guid.Parse("22222222-2222-4222-8222-222222222222"));
        var security = Security(windows, client);

        var envelope = await security.SignResultAsync(
            JobId,
            "collected",
            TotalBytes,
            BundleSha256,
            CancellationToken.None);
        var canonical = VrcEnvelopeCanonicalizer.Result(envelope);
        var signature = Convert.FromBase64String(envelope.SignatureBase64);

        Assert.Equal(windows.DeviceId, envelope.WindowsDeviceId);
        Assert.Equal(client.DeviceId, envelope.ClientDeviceId);
        Assert.True(windows.Verify(canonical, signature));
        canonical[^1] ^= 0x01;
        Assert.False(windows.Verify(canonical, signature));
    }

    [Fact]
    public void CanonicalFixtures_MatchSwiftByteForByte()
    {
        var job = new VrcJobEnvelope(
            VrcEnvelopeSecurity.JobSchemaVersion,
            Guid.Parse("11111111-1111-4111-8111-111111111111"),
            Guid.Parse("22222222-2222-4222-8222-222222222222"),
            new string('a', 64),
            JobId,
            TotalBytes,
            BundleSha256,
            1_800_000_000_000,
            string.Empty);
        var result = new VrcResultEnvelope(
            VrcEnvelopeSecurity.ResultSchemaVersion,
            Guid.Parse("11111111-1111-4111-8111-111111111111"),
            new string('b', 64),
            Guid.Parse("22222222-2222-4222-8222-222222222222"),
            new string('a', 64),
            JobId,
            "collected",
            TotalBytes,
            BundleSha256,
            1_800_000_000_000,
            string.Empty);

        Assert.Equal(
            "c46a1fc9519ae1e61ff7136ac41e7d9fa51b3e4e047722bee66d29e9ce1e88e3",
            Convert.ToHexString(SHA256.HashData(VrcEnvelopeCanonicalizer.Job(job))).ToLowerInvariant());
        Assert.Equal(
            "43ef803a1c88f7084cd0fa324eed4f122baa6d633fbe820ba24d4bc7d17422ed",
            Convert.ToHexString(SHA256.HashData(VrcEnvelopeCanonicalizer.Result(result))).ToLowerInvariant());
    }

    private static VrcEnvelopeSecurity Security(TestIdentity windows, TestIdentity client) => new(
        windows,
        new PeerContextSource(client),
        () => Now);

    private static VrcJobEnvelope SignedJobEnvelope(TestIdentity windows, TestIdentity client)
    {
        var unsigned = new VrcJobEnvelope(
            VrcEnvelopeSecurity.JobSchemaVersion,
            windows.DeviceId,
            client.DeviceId,
            client.Fingerprint,
            JobId,
            TotalBytes,
            BundleSha256,
            Now.ToUnixTimeMilliseconds(),
            SignatureBase64: string.Empty);
        var canonical = VrcEnvelopeCanonicalizer.Job(unsigned);
        var signature = client.Sign(canonical);
        return unsigned with { SignatureBase64 = Convert.ToBase64String(signature) };
    }

    private static JsonElement Element(object value) => JsonSerializer.SerializeToElement(
        value,
        ControlMessageSerializer.Options);

    private sealed class PeerContextSource(TestIdentity client) : ICompanionAuthorizedPeerContextSource
    {
        public bool TryGetAuthorizedPeerContext(out CompanionAuthorizedPeerContext? context)
        {
            context = new CompanionAuthorizedPeerContext(
                client.DeviceId,
                client.Fingerprint,
                Convert.ToBase64String(client.PublicKey),
                new string('c', 64));
            return true;
        }
    }

    private sealed class TestIdentity : ICompanionIdentity, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public TestIdentity(Guid deviceId)
        {
            DeviceId = deviceId;
            PublicKey = _key.ExportSubjectPublicKeyInfo();
            Fingerprint = Convert.ToHexString(SHA256.HashData(PublicKey));
        }

        public Guid DeviceId { get; }

        public byte[] PublicKey { get; }

        public string Fingerprint { get; }

        public ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new CompanionIdentityMetadata(
                DeviceId,
                Fingerprint,
                Convert.ToBase64String(PublicKey)));

        public ValueTask<byte[]> SignAsync(
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken) => ValueTask.FromResult(Sign(payload.Span));

        public byte[] Sign(ReadOnlySpan<byte> payload) => _key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature) => _key.VerifyData(
            payload,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void Dispose() => _key.Dispose();
    }
}
