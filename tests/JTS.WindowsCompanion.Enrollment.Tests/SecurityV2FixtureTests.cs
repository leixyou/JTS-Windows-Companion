using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Pairing;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class SecurityV2FixtureTests
{
    [Fact]
    public void IndependentPythonConfirmationSignatureAndTranscriptAgree()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "confirmation-v2.json")));
        var p = document.RootElement; var c = EnrollmentConfirmation.Parse(p.GetProperty("confirmation"));
        Assert.Equal(Convert.FromBase64String(p.GetProperty("transcriptBase64").GetString()!), c.Transcript());
        var request = new RelayDelegatedEnrollment(c.ControllerDeviceId, p.GetProperty("controllerSPKIBase64").GetString()!, Guid.NewGuid(),
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.FromUnixTimeSeconds(c.ConfirmedAtUnixSeconds - 1), DateTimeOffset.FromUnixTimeSeconds(c.ExpiresAtUnixSeconds));
        var attempt = new EnrollmentAttempt(Guid.Parse(c.InvitationId), c.RelayOrigin, "", "claimed", request.IssuedAtUtc,
            ClaimHash: c.ClaimHash, ExpiresAtUnixSeconds: c.ExpiresAtUnixSeconds);
        c.Verify(attempt, request, c.PeerDeviceId, new TestClock(request.ExpiresAtUtc.AddDays(30)));
    }
    [Fact]
    public void IndependentPythonRevocationAndReceiptAreByteExact()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "revocation-v2.json")));
        var p = document.RootElement; var request = RevocationRequest.Parse(p.GetProperty("revocation"));
        request.Verify(request.RelayOrigin, request.PeerDeviceId, p.GetProperty("controllerSPKIBase64").GetString()!);
        Assert.Equal(Convert.FromBase64String(p.GetProperty("requestTranscriptBase64").GetString()!), request.Transcript());
        Assert.Equal(p.GetProperty("requestHash").GetString(), request.RequestHash);
        var receipt = JsonSerializer.Deserialize<RevocationReceipt>(p.GetProperty("receipt"), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        Assert.Equal(Convert.FromBase64String(p.GetProperty("receiptTranscriptBase64").GetString()!), receipt.Transcript());
        using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(p.GetProperty("peerSPKIBase64").GetString()!), out _);
        Assert.True(key.VerifyData(receipt.Transcript(), Convert.FromBase64String(receipt.SignatureBase64), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
}
