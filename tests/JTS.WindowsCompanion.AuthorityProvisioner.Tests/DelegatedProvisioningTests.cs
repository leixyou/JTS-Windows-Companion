using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;
using Xunit;

namespace JTS.WindowsCompanion.AuthorityProvisioner.Tests;

public sealed class DelegatedProvisioningTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InstallationCreatesExactThreeLaneBindingThatSurvivesRequestExpiryAndCanBeRevoked(bool allowTls12)
    {
        using var f = new ProvisioningFixture(); var request = Request(f.Clock.Now) with { allowWindows10TLS12 = allowTls12 }; var bytes = JsonSerializer.SerializeToUtf8Bytes(request);
        var intent = f.Intent with { DelegationSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) };
        f.State().Create(f.Paths, intent, bytes);
        using var ready = JsonDocument.Parse(File.ReadAllBytes(f.Paths.FilePath("ready.json")));
        var windows = ready.RootElement.GetProperty("identity").GetProperty("DeviceId").GetString()!;
        Assert.Equal(5, ready.RootElement.GetProperty("files").GetArrayLength());
        f.Clock.Now = f.Clock.Now.AddHours(1);
        using (var pairings = new DurableRelayPairingStore(f.Paths.FilePath("pairings.sqlite"), windows, f.Protector, clock: f.Clock))
        using (var grants = new DurableControlGrantStore(f.Paths.FilePath("control-grants.sqlite"), f.Protector, clock: f.Clock))
        {
            var policy = await pairings.FindAsync(request.controllerDeviceID); Assert.NotNull(policy);
            Assert.Equal(allowTls12 ? RelayTlsPolicy.ExplicitWindows10Tls12 : RelayTlsPolicy.Tls13, policy.TlsPolicy);
            Assert.Equal(request.fileGrantID, Assert.Single(policy.GrantsFor(RelayLane.File)));
            Assert.Equal(request.rdpGrantID, Assert.Single(policy.GrantsFor(RelayLane.Rdp)));
            Assert.NotNull(await grants.FindAsync(request.controllerDeviceID, request.grantID, default));
            await pairings.RevokeAsync(request.controllerDeviceID, request.pairingID);
        }
        using var reopened = new DurableRelayPairingStore(f.Paths.FilePath("pairings.sqlite"), windows, f.Protector, clock: f.Clock);
        Assert.Null(await reopened.FindAsync(request.controllerDeviceID));
        Assert.NotNull(Assert.Single(reopened.ListLocally()).RevokedAt);
        using var receipt = JsonDocument.Parse(File.ReadAllBytes(f.Paths.FilePath("delegation-receipt.json")));
        Assert.Equal("ownerDelegated", receipt.RootElement.GetProperty("authorizationSource").GetString());
        Assert.Equal(intent.DelegationSha256, receipt.RootElement.GetProperty("requestSha256").GetString());
        Assert.Equal(ProvisioningFixture.Authority, receipt.RootElement.GetProperty("authoritySid").GetString());
    }
    [Fact]
    public void ModifiedRequestOrExpiredInputCannotInitializeAnyState()
    {
        using var f = new ProvisioningFixture(); var bytes = JsonSerializer.SerializeToUtf8Bytes(Request(f.Clock.Now));
        Assert.Throws<ProvisioningException>(() => f.State().Create(f.Paths, f.Intent with { DelegationSha256 = new string('0', 64) }, bytes));
        Assert.Empty(Directory.GetFiles(f.Paths.State));
        var expired = JsonSerializer.SerializeToUtf8Bytes(Request(f.Clock.Now.AddHours(-1)));
        Assert.Throws<PairingStoreException>(() => f.State().Create(f.Paths,
            f.Intent with { DelegationSha256 = Convert.ToHexStringLower(SHA256.HashData(expired)) }, expired));
        Assert.Empty(Directory.GetFiles(f.Paths.State));
    }
    [Fact]
    public void PublicKeyHashAndDistinctLaneGrantsAreMandatory()
    {
        var now = DateTimeOffset.UtcNow; var request = Request(now);
        Assert.Throws<PairingStoreException>(() => RelayDelegatedEnrollment.Parse(JsonSerializer.SerializeToUtf8Bytes(request with { controllerDeviceID = new string('f', 64) })));
        Assert.Throws<PairingStoreException>(() => RelayDelegatedEnrollment.Parse(JsonSerializer.SerializeToUtf8Bytes(request with { fileGrantID = request.grantID })));
        Assert.Throws<PairingStoreException>(() => RelayDelegatedEnrollment.Parse(JsonSerializer.SerializeToUtf8Bytes(request with { authorizationReference = "human-clicked" })));
    }
    [Fact]
    public void MissingCompatibilityRemainsTls13AndMalformedOrDuplicateValuesAreRejected()
    {
        var request = Request(DateTimeOffset.UtcNow);
        var json = JsonSerializer.Serialize(request);
        Assert.DoesNotContain("allowWindows10TLS12", json);
        Assert.Equal(RelayTlsPolicy.Tls13, RelayDelegatedEnrollment.Parse(System.Text.Encoding.UTF8.GetBytes(json)).Pairing().TlsPolicy);
        foreach (var value in new[] { "null", "1", "\"true\"", "{}", "[]", "true,\"allowWindows10TLS12\":false" })
            Assert.Throws<PairingStoreException>(() => RelayDelegatedEnrollment.Parse(System.Text.Encoding.UTF8.GetBytes(json[..^1] + ",\"allowWindows10TLS12\":" + value + "}")));
    }

    [Fact]
    public void CompatibilityChangeCannotBypassThePinnedRequestDigest()
    {
        using var f = new ProvisioningFixture(); var request = Request(f.Clock.Now);
        var original = JsonSerializer.SerializeToUtf8Bytes(request);
        var changed = JsonSerializer.SerializeToUtf8Bytes(request with { allowWindows10TLS12 = true });
        Assert.Throws<ProvisioningException>(() => f.State().Create(f.Paths,
            f.Intent with { DelegationSha256 = Convert.ToHexStringLower(SHA256.HashData(original)) }, changed));
        Assert.Empty(Directory.GetFiles(f.Paths.State));
    }

    private static DelegationRequest Request(DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var spki = key.ExportSubjectPublicKeyInfo();
        return new(1, "ownerDelegated", "device-ai-control-enabled", Convert.ToHexStringLower(SHA256.HashData(spki)), Convert.ToBase64String(spki),
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), now, now.AddMinutes(20));
    }
    private sealed record DelegationRequest(int version, string authorizationSource, string authorizationReference,
        string controllerDeviceID, string controllerSPKIBase64, Guid pairingID, Guid grantID, Guid fileGrantID, Guid rdpGrantID,
        DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc,
        [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        bool? allowWindows10TLS12 = null);
}
