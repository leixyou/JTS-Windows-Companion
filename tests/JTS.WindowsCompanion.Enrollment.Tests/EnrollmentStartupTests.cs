using JTS.WindowsCompanion.Control;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class EnrollmentStartupTests
{
    private static async Task Bound(EnrollmentFixture f)
    { await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Confirm(); await f.Coordinator.StepAsync(); }
    [Theory]
    [InlineData("bound")]
    [InlineData("committing")]
    public async Task UnsignedLegacyAuthorizationIsRetiredBeforeAnExecutingHostExists(string state)
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f); var identity = f.Identity.DeviceId;
        f.RewriteAttempt(a => a with { Confirmation = null, State = state }); f.Startup();
        var status = await f.Coordinator.StatusAsync(); Assert.Equal("revoked", status.State);
        Assert.Equal("ENROLLMENT_LEGACY_CONFIRMATION_REQUIRED", status.ErrorCode); Assert.Equal(identity, status.DeviceId);
        Assert.NotNull(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.NotNull(Assert.Single(f.Grants.ListLocally()).RevokedAt);
        Assert.Equal(0, f.DrainCalls); Assert.Empty(f.Revocations.Completed);
        var newCode = f.Code.Replace(status.InvitationId!.Value.ToString("D"), Guid.NewGuid().ToString("D"));
        Assert.Equal("pending", (await f.Coordinator.EnrollAsync(newCode)).State);
    }
    [Theory]
    [InlineData("startup-revocation-journaled")]
    [InlineData("startup-pairing-revoked")]
    [InlineData("startup-grant-revoked")]
    public async Task LegacyMigrationRecoversEveryDenyPersistenceBoundary(string boundary)
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f); f.RewriteAttempt(a => a with { Confirmation = null });
        Assert.Throws<Interrupted>(() => f.Startup(point => { if (point == boundary) throw new Interrupted(); }));
        f.Startup(); Assert.Equal("revoked", (await f.Coordinator.StatusAsync()).State);
        Assert.NotNull(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.NotNull(Assert.Single(f.Grants.ListLocally()).RevokedAt);
    }
    [Fact]
    public async Task SignedV2BindingSurvivesWallClockCorrectionWithoutAnotherApproval()
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f);
        f.Clock.Now = f.Clock.Now.AddMinutes(-5); f.Startup();
        Assert.Equal("bound", (await f.Coordinator.StatusAsync()).State);
        Assert.Null(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.Null(Assert.Single(f.Grants.ListLocally()).RevokedAt);
    }
    [Fact]
    public void ExplicitLocalJsonInstallationWithoutCodeJournalIsNotMistakenForUnsignedRelayConsent()
    {
        using var f = new EnrollmentFixture(mailbox: true);
        f.Pairings.ApproveLocally(f.Request.Pairing(), f.Request.ControllerDeviceID);
        f.Grants.ApproveLocally(new(f.Request.ControllerDeviceID, f.Request.GrantID, DateTimeOffset.MaxValue,
            Enum.GetValues<ControlOperation>(), ["powershell.v1"], true));
        f.Startup();
        Assert.Null(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.Null(Assert.Single(f.Grants.ListLocally()).RevokedAt);
    }
    [Fact]
    public async Task PendingClaimHasNoAuthorityAndIsNotRetiredAsLegacyBound()
    {
        using var f = new EnrollmentFixture(mailbox: true); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        f.Startup(); Assert.Equal("claimed", (await f.Coordinator.StatusAsync()).State);
        Assert.Empty(f.Pairings.ListLocally()); Assert.Empty(f.Grants.ListLocally());
    }
    [Fact]
    public async Task PersistedRemoteDenyTombstonesPrecedeSchedulerButReceiptStillWaitsForRuntimeDrain()
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f); f.PersistRevocationOnly(f.RevokeRequest());
        f.Startup();
        Assert.Equal("revoking", (await f.Coordinator.StatusAsync()).State);
        Assert.NotNull(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.NotNull(Assert.Single(f.Grants.ListLocally()).RevokedAt);
        Assert.Empty(f.Revocations.Completed); Assert.Equal(0, f.DrainCalls);
        await f.Coordinator.StepAsync(); Assert.Single(f.Revocations.Completed); Assert.Equal(1, f.DrainCalls);
        Assert.Equal("revoked", (await f.Coordinator.StatusAsync()).State);
    }
    private sealed class Interrupted : Exception;
}
