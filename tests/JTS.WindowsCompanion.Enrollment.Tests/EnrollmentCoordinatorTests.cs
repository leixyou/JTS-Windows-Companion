using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Relay;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class EnrollmentCoordinatorTests
{
    [Fact]
    public async Task ClaimedIsNotBoundAndCommitNeverNeedsRdp()
    {
        using var f = new EnrollmentFixture();
        Assert.Equal("pending", (await f.Coordinator.EnrollAsync(f.Code)).State);
        await f.Coordinator.StepAsync();
        Assert.Equal("claimed", (await f.Coordinator.StatusAsync()).State);
        Assert.Empty(f.Pairings.ListLocally()); Assert.Empty(f.Grants.ListLocally());
        using (var code = EnrollmentCode.Parse(f.Code))
        {
            var claim = Assert.Single(f.Relay.Submitted);
            var transcript = EnrollmentCrypto.Transcript(code.InvitationId, f.Request.ControllerDeviceID,
                EnrollmentCrypto.Base64(f.Relay.Receipt.OfferBase64), EnrollmentCrypto.Base64(claim.ResponseBase64), EnrollmentCrypto.Base64(claim.PeerSPKIBase64, 512));
            Assert.Equal(EnrollmentCrypto.Hash(transcript), claim.ClaimHash);
            using var verifier = ECDsa.Create(); verifier.ImportSubjectPublicKeyInfo(EnrollmentCrypto.Base64(f.Spki, 512), out _);
            Assert.True(verifier.VerifyData(transcript, EnrollmentCrypto.Base64(claim.SignatureBase64, 64), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            var clear = EnrollmentCrypto.Decrypt(code, "response", EnrollmentCrypto.Base64(claim.ResponseBase64), EnrollmentCrypto.Hash(EnrollmentCrypto.Base64(f.Relay.Receipt.OfferBase64)));
            using var response = JsonDocument.Parse(clear);
            using var bundle = JsonDocument.Parse(Convert.FromBase64String(response.RootElement.GetProperty("enrollmentBase64").GetString()!));
            Assert.Equal(f.Identity.DeviceId, bundle.RootElement.GetProperty("peerDeviceID").GetString());
            Assert.Equal(f.Request.PairingID, bundle.RootElement.GetProperty("pairingID").GetGuid());
            Assert.True(bundle.RootElement.GetProperty("allowWindows10TLS12").GetBoolean());
        }
        f.Confirm(); await f.Coordinator.StepAsync();
        Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State);
        Assert.Equal(RelayTlsPolicy.ExplicitWindows10Tls12, Assert.Single(f.Pairings.ListLocally()).Policy!.TlsPolicy);
        Assert.True(Assert.Single(f.Grants.ListLocally()).Grant!.AllowDisconnected);
        f.Clock.Now = f.Clock.Now.AddDays(7); f.Restart(); await f.Coordinator.StepAsync();
        Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State); // Failed/missing RDP login has no input to enrollment.
    }
    [Fact]
    public async Task LostClaimResponseAndRestartReuseExactCiphertextAndProof()
    {
        using var f = new EnrollmentFixture(); f.Relay.LoseClaimResponse = true;
        await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        var first = Assert.Single(f.Relay.Submitted); f.Restart(); await f.Coordinator.StepAsync();
        Assert.Equal(first, f.Relay.Submitted.Last()); Assert.Equal(2, f.Relay.Submitted.Count);
        Assert.Empty(f.Pairings.ListLocally());
        f.Confirm(); f.Restart(); await f.Coordinator.StepAsync(); Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State);
    }
    [Theory]
    [InlineData("response-persisted")]
    [InlineData("commit-authorized")]
    [InlineData("grant-persisted")]
    [InlineData("pairing-persisted")]
    [InlineData("pairing-activated")]
    public async Task RestartRecoversEveryDurableCommitBoundary(string boundary)
    {
        using var f = new EnrollmentFixture();
        var threw = false; f.Checkpoint = point => { if (!threw && point == boundary) { threw = true; throw new SimulatedCrash(); } };
        await f.Coordinator.EnrollAsync(f.Code);
        if (boundary == "response-persisted") await Assert.ThrowsAsync<SimulatedCrash>(() => f.Coordinator.StepAsync());
        else
        {
            await f.Coordinator.StepAsync(); f.Confirm();
            await Assert.ThrowsAsync<SimulatedCrash>(() => f.Coordinator.StepAsync());
        }
        f.Checkpoint = null; f.Restart();
        if (boundary == "response-persisted") { await f.Coordinator.StepAsync(); f.Confirm(); }
        else f.Clock.Now = f.Clock.Now.AddHours(1); // A bound durable authorization remains recoverable after code expiry.
        await f.Coordinator.StepAsync();
        Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State);
        Assert.Single(f.Pairings.ListLocally()); Assert.Single(f.Grants.ListLocally());
    }
    [Fact]
    public async Task OfflinePendingSurvivesRestartAndDoesNotAuthorizeAnything()
    {
        using var f = new EnrollmentFixture(); f.Relay.Offline = true;
        await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Restart();
        Assert.Equal("pending", (await f.Coordinator.StatusAsync()).State); Assert.Empty(f.Pairings.ListLocally());
        f.Relay.Offline = false; await f.Coordinator.StepAsync(); Assert.Equal("claimed", (await f.Coordinator.StatusAsync()).State);
    }
    [Fact]
    public async Task ExpiredUnboundAttemptDoesNotCreateCredentials()
    {
        using var f = new EnrollmentFixture(); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        f.Relay.Receipt = f.Relay.Receipt with { State = "expired" }; await f.Coordinator.StepAsync();
        Assert.Equal("expired", (await f.Coordinator.StatusAsync()).State); Assert.Empty(f.Pairings.ListLocally());
    }
    [Fact]
    public async Task ReceiptIsRecoveredAfterOriginalExpiryWhenAlreadyBound()
    {
        using var f = new EnrollmentFixture(); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Confirm();
        f.Clock.Now = f.Clock.Now.AddHours(1); f.Restart(); await f.Coordinator.StepAsync();
        Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State);
    }
    [Fact]
    public async Task SubstitutedReceiptKeyCannotBind()
    {
        using var f = new EnrollmentFixture(); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Confirm();
        f.Relay.Receipt = f.Relay.Receipt with { Claim = f.Relay.Receipt.Claim! with { PeerSPKIBase64 = Convert.ToBase64String(new byte[91]) } };
        await f.Coordinator.StepAsync(); Assert.Equal("faulted", (await f.Coordinator.StatusAsync()).State); Assert.Empty(f.Pairings.ListLocally());
    }
    [Fact]
    public async Task SecretIsProtectedAtRestAndRevocationDoesNotResurrectOnRestart()
    {
        using var f = new EnrollmentFixture(); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        Assert.DoesNotContain(f.Code, Encoding.UTF8.GetString(File.ReadAllBytes(f.Path)));
        Assert.DoesNotContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Encoding.UTF8.GetString(File.ReadAllBytes(f.Path)));
        f.Confirm(); await f.Coordinator.StepAsync();
        var status = await f.Coordinator.StatusAsync(); await f.Coordinator.RevokeAsync(status.InvitationId!.Value); f.Restart();
        Assert.Equal("revoked", (await f.Coordinator.StatusAsync()).State);
        Assert.NotNull(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.NotNull(Assert.Single(f.Grants.ListLocally()).RevokedAt);
        await Assert.ThrowsAsync<EnrollmentException>(() => f.Coordinator.EnrollAsync(f.Code));
    }
    [Fact]
    public async Task ReusedPairingEpochIsRejectedBeforeAnyClaim()
    {
        using var f = new EnrollmentFixture();
        await f.Pairings.RevokeAsync(f.Request.ControllerDeviceID, f.Request.PairingID);
        await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        Assert.Equal("faulted", (await f.Coordinator.StatusAsync()).State);
        Assert.Empty(f.Relay.Submitted); Assert.Empty(f.Grants.ListLocally());
    }
    [Fact]
    public async Task BindingWaitsForExactDurablePairingRuntimeActivationAndRetriesAfterFailure()
    {
        using var f = new EnrollmentFixture();
        f.Activation = (owner, epoch, _) =>
        {
            Assert.Equal(f.Request.ControllerDeviceID, owner); Assert.Equal(f.Request.PairingID, epoch);
            Assert.Equal(epoch, Assert.Single(f.Pairings.ListLocally()).PairingId);
            Assert.Equal(f.Request.GrantID, Assert.Single(f.Grants.ListLocally()).GrantId);
            throw new SimulatedCrash();
        };
        await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        Assert.Equal(0, f.ActivationCalls); f.Confirm();
        await Assert.ThrowsAsync<SimulatedCrash>(() => f.Coordinator.StepAsync());
        Assert.Equal("committing", (await f.Coordinator.StatusAsync()).State);
        f.Restart(); f.Activation = null; await f.Coordinator.StepAsync();
        Assert.Equal(2, f.ActivationCalls); Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State);
    }
    [Fact]
    public async Task SlowRevokedWorkDrainKeepsCommitPendingAndRetriesWithoutServiceRestart()
    {
        using var f = new EnrollmentFixture();
        f.Activation = (_, _, _) => ValueTask.FromException(new TimeoutException());
        await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Confirm(); await f.Coordinator.StepAsync();
        var status = await f.Coordinator.StatusAsync();
        Assert.Equal("committing", status.State); Assert.Equal("ENROLLMENT_ACTIVATION_PENDING", status.ErrorCode);
        f.Activation = null; await f.Coordinator.StepAsync();
        Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State); Assert.Equal(2, f.ActivationCalls);
    }
    private sealed class SimulatedCrash : Exception;
}
