using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class DelegatedEnrollmentContractTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 26, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ParseAcceptsExactBoundRequestAndNormalizesPublicValues()
    {
        var request = Request();
        request = request with
        {
            MacIdentity = request.MacIdentity with { FingerprintSha256 = request.MacIdentity.FingerprintSha256.ToLowerInvariant() },
            ExpectedWindows = request.ExpectedWindows with { FingerprintSha256 = request.ExpectedWindows.FingerprintSha256.ToLowerInvariant() },
        };
        var bytes = Serialize(request);
        var parsed = CompanionDelegatedEnrollmentValidation.Parse(bytes, Digest(bytes).ToLowerInvariant(), Now);
        Assert.Equal(request.GrantId, parsed.GrantId);
        Assert.Equal(request.TargetId, parsed.TargetId);
        Assert.Equal(request.TargetBinding, parsed.TargetBinding);
        Assert.Equal(request.MacIdentity.PublicKeyBase64, parsed.MacIdentity.PublicKeyBase64);
        Assert.Equal(request.MacIdentity.FingerprintSha256.ToUpperInvariant(), parsed.MacIdentity.FingerprintSha256);
        Assert.Equal(request.ExpectedWindows.FingerprintSha256.ToUpperInvariant(), parsed.ExpectedWindows.FingerprintSha256);
    }

    [Fact]
    public void ParseRequiresMatchingRawRequestDigestAndBoundedUtf8()
    {
        var bytes = Serialize(Request());
        var changed = bytes.Concat(" "u8.ToArray()).ToArray();
        Assert.Equal("DELEGATED_ENROLLMENT_DIGEST_MISMATCH", Assert.Throws<CompanionProtocolException>(() =>
            CompanionDelegatedEnrollmentValidation.Parse(changed, Digest(bytes), Now)).Code);
        Assert.Throws<CompanionProtocolException>(() => CompanionDelegatedEnrollmentValidation.Parse(bytes, "bad", Now));
        foreach (var invalid in new byte[][]
        {
            [], new byte[CompanionDelegatedEnrollmentValidation.MaximumRequestBytes + 1],
            [0x7B, 0x22, 0xFF, 0x22, 0x3A, 0x30, 0x7D],
        })
        {
            Assert.Throws<CompanionProtocolException>(() => Parse(invalid));
        }
    }

    [Fact]
    public void ParseRejectsDuplicateUnknownMissingAndWrongCaseFields()
    {
        var text = Encoding.UTF8.GetString(Serialize(Request()));
        Assert.Throws<CompanionProtocolException>(() => Parse(Encoding.UTF8.GetBytes(
            text.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal))));
        Assert.Throws<CompanionProtocolException>(() => Parse(Encoding.UTF8.GetBytes(
            text.Replace("\"macIdentity\":{", "\"macIdentity\":{\"deviceId\":\"" + Guid.NewGuid() + "\",", StringComparison.Ordinal))));
        foreach (var mutation in new Action<JsonObject>[]
        {
            root => root["unexpected"] = true,
            root => root.Remove("grantId"),
            root => { root["TargetId"] = root["targetId"]!.DeepClone(); root.Remove("targetId"); },
            root => root["expectedWindows"]!.AsObject()["publicKeyBase64"] = "unexpected",
            root => root["macIdentity"]!.AsObject().Remove("fingerprintSha256"),
        })
        {
            Assert.Throws<CompanionProtocolException>(() => Parse(Mutate(mutation)));
        }
    }

    [Fact]
    public void ParseRejectsUnapprovedSourceAndTargetMetadata()
    {
        var request = Request();
        foreach (var invalid in new[]
        {
            request with { SchemaVersion = 2 },
            request with { GrantId = Guid.Empty },
            request with { TargetId = Guid.Empty },
            request with { TargetBinding = " " },
            request with { TargetBinding = new string('x', 513) },
            request with { TargetBinding = "host\nother" },
            request with { AuthorizationSource = "remoteRequest" },
            request with { AuthorizationReference = "owner-authorized-device-delegation" },
        })
        {
            Assert.Throws<CompanionProtocolException>(() => Parse(Serialize(invalid)));
        }
    }

    [Fact]
    public void ImportWindowMustBeCurrentAndNoLongerThanThirtyMinutes()
    {
        var request = Request() with { IssuedAtUtc = Now, ExpiresAtUtc = Now.AddMinutes(30) };
        Assert.Equal(request, Parse(Serialize(request)));
        foreach (var invalid in new[]
        {
            request with { IssuedAtUtc = Now.AddTicks(1) },
            request with { ExpiresAtUtc = Now },
            request with { ExpiresAtUtc = Now.AddMinutes(30).AddTicks(1) },
            request with { IssuedAtUtc = Now.AddMinutes(1), ExpiresAtUtc = Now },
        })
        {
            Assert.Throws<CompanionProtocolException>(() => Parse(Serialize(invalid)));
        }
        var parsed = Parse(Serialize(request));
        Assert.Equal("DELEGATED_ENROLLMENT_EXPIRED", Assert.Throws<CompanionProtocolException>(() =>
            CompanionDelegatedEnrollmentValidation.ValidateRequest(parsed, request.ExpiresAtUtc)).Code);
    }

    [Fact]
    public void ParseRejectsDatesWithoutZoneAndInvalidFieldTypes()
    {
        foreach (var mutation in new Action<JsonObject>[]
        {
            root => root["issuedAtUtc"] = "2026-09-26T11:59:00",
            root => root["expiresAtUtc"] = "tomorrow",
            root => root["schemaVersion"] = "1",
            root => root["targetBinding"] = 12,
            root => root["macIdentity"] = null,
            root => root["expectedWindows"] = new JsonArray(),
        })
        {
            Assert.Throws<CompanionProtocolException>(() => Parse(Mutate(mutation)));
        }
    }

    [Fact]
    public void IdentityRequiresMatchingFingerprintCompleteSpkiAndNistP256()
    {
        var request = Request();
        var key = Convert.FromBase64String(request.MacIdentity.PublicKeyBase64);
        var trailingKey = key.Concat(new byte[] { 0 }).ToArray();
        // The secp256k1 generator point is valid, but this curve is not NIST P-256.
        var secp256k1 = Convert.FromHexString(
            "3056301006072A8648CE3D020106052B8104000A03420004" +
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        foreach (var identity in new[]
        {
            request.MacIdentity with { DeviceId = Guid.Empty },
            request.MacIdentity with { FingerprintSha256 = new string('0', 64) },
            request.MacIdentity with { PublicKeyBase64 = "bad" },
            request.MacIdentity with { PublicKeyBase64 = Convert.ToBase64String(trailingKey), FingerprintSha256 = Digest(trailingKey) },
            request.MacIdentity with { PublicKeyBase64 = Convert.ToBase64String(secp256k1), FingerprintSha256 = Digest(secp256k1) },
        })
        {
            Assert.Throws<CompanionProtocolException>(() => Parse(Serialize(request with { MacIdentity = identity })));
        }
    }

    [Fact]
    public void WindowsBindingRequiresDeviceIdAndVerifiedPublicKeyFingerprint()
    {
        var windows = Peer();
        var request = Request() with { ExpectedWindows = new(windows.DeviceId, windows.FingerprintSha256) };
        var metadata = new CompanionIdentityMetadata(windows.DeviceId, windows.FingerprintSha256, windows.PublicKeyBase64);
        CompanionDelegatedEnrollmentValidation.ValidateWindowsBinding(request, metadata);
        foreach (var invalid in new[]
        {
            metadata with { DeviceId = Guid.NewGuid() },
            metadata with { FingerprintSha256 = new string('0', 64) },
            metadata with { PublicKeyBase64 = Peer().PublicKeyBase64 },
        })
        {
            Assert.Throws<CompanionProtocolException>(() => CompanionDelegatedEnrollmentValidation.ValidateWindowsBinding(request, invalid));
        }
    }

    [Fact]
    public void ReceiptRemainsValidAfterImportWindowAndKeepsAuditBindings()
    {
        var request = Request() with { IssuedAtUtc = Now.AddYears(-1), ExpiresAtUtc = Now.AddYears(-1).AddMinutes(10) };
        var receipt = Receipt(request) with { ApprovedAtUtc = request.IssuedAtUtc.AddMinutes(1) };
        Assert.Throws<CompanionProtocolException>(() => Parse(Serialize(request)));
        var normalized = CompanionDelegatedEnrollmentValidation.NormalizeReceipt(receipt, request.MacIdentity);
        Assert.Equal(receipt, normalized);
        Assert.Equal("device-ai-control-enabled", normalized.AuthorizationReference);
        Assert.Equal(request.ExpectedWindows, normalized.ExpectedWindows);
    }

    [Fact]
    public void ReceiptRejectsPeerMismatchInvalidAuditAndApprovalOutsideWindow()
    {
        var request = Request();
        var receipt = Receipt(request);
        Assert.Throws<CompanionProtocolException>(() => CompanionDelegatedEnrollmentValidation.NormalizeReceipt(receipt, Peer()));
        foreach (var invalid in new[]
        {
            receipt with { RequestSha256 = "bad" },
            receipt with { WindowsUserSid = "S-1-5-21-4294967296" },
            receipt with { WindowsUserSid = "S-1-5-21\nforged" },
            receipt with { WindowsSessionId = -1 },
            receipt with { ApprovedAtUtc = request.IssuedAtUtc.AddTicks(-1) },
            receipt with { ApprovedAtUtc = request.ExpiresAtUtc },
            receipt with { MacIdentity = Peer() },
        })
        {
            Assert.Throws<CompanionProtocolException>(() => CompanionDelegatedEnrollmentValidation.NormalizeReceipt(invalid, request.MacIdentity));
        }
    }

    private static CompanionDelegatedEnrollmentRequest Request() => new(
        1, Guid.NewGuid(), "ownerDelegated", Guid.NewGuid(), "rdp://authorized-lab/current-user",
        Peer(), new(Guid.NewGuid(), new string('A', 64)), Now.AddMinutes(-1), Now.AddMinutes(10),
        "device-ai-control-enabled");

    private static CompanionDelegatedConsentReceipt Receipt(CompanionDelegatedEnrollmentRequest request) => new(
        request.SchemaVersion, request.GrantId, request.AuthorizationSource, request.TargetId,
        request.TargetBinding, request.MacIdentity, request.ExpectedWindows, request.IssuedAtUtc,
        request.ExpiresAtUtc, request.AuthorizationReference, Digest(Serialize(request)), "S-1-5-21-100-200-300-1001", 2, Now);

    private static CompanionPeerIdentity Peer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        return new(Guid.NewGuid(), Digest(publicKey), Convert.ToBase64String(publicKey));
    }

    private static byte[] Mutate(Action<JsonObject> mutation)
    {
        var root = JsonNode.Parse(Serialize(Request()))!.AsObject();
        mutation(root);
        return Encoding.UTF8.GetBytes(root.ToJsonString());
    }

    private static byte[] Serialize(CompanionDelegatedEnrollmentRequest request) =>
        JsonSerializer.SerializeToUtf8Bytes(request, ControlMessageSerializer.Options);
    private static string Digest(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static CompanionDelegatedEnrollmentRequest Parse(byte[] bytes) =>
        CompanionDelegatedEnrollmentValidation.Parse(bytes, Digest(bytes), Now);
}
