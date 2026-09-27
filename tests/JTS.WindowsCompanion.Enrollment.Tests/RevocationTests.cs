using System.Security.Cryptography;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class RevocationTests
{
    private static async Task Bound(EnrollmentFixture f)
    { await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Confirm(); await f.Coordinator.StepAsync(); }
    [Fact]
    public async Task SignedMailboxRevokesDurableAuthorityAndConfirmsOnlyAfterExecutorDrain()
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Drain = async (_, _) => { started.TrySetResult(); await finish.Task; };
        var request = f.RevokeRequest(); f.Deliver(request);
        var step = f.Coordinator.StepAsync(); await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.NotNull(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.NotNull(Assert.Single(f.Grants.ListLocally()).RevokedAt);
        Assert.Empty(f.Revocations.Completed); finish.SetResult(); await step;
        var receipt = Assert.Single(f.Revocations.Completed); Assert.Equal(request.RequestHash, receipt.RequestHash);
        using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(f.Spki), out _);
        Assert.True(key.VerifyData(receipt.Transcript(), Convert.FromBase64String(receipt.SignatureBase64), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.Equal("revoked", (await f.Coordinator.StatusAsync()).State);
    }
    [Fact]
    public async Task LostReceiptAcknowledgementAndRestartResendExactSignedReceipt()
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f); f.Deliver(f.RevokeRequest()); f.Revocations.LoseCompletion = true;
        await f.Coordinator.StepAsync(); var first = Assert.Single(f.Revocations.Completed);
        f.Revocations.Pending.Clear(); f.Clock.Now = f.Clock.Now.AddDays(30); f.Restart(); await f.Coordinator.StepAsync();
        Assert.Equal(first, f.Revocations.Completed.Last()); Assert.Equal(2, f.Revocations.Completed.Count); Assert.Equal(1, f.DrainCalls);
    }
    [Fact]
    public async Task DurablePendingRevocationRetriesLocallyEvenWhenRelayStopsDelivering()
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f); f.Deliver(f.RevokeRequest());
        f.Drain = (_, _) => ValueTask.FromException(new TimeoutException()); await f.Coordinator.StepAsync(); Assert.Empty(f.Revocations.Completed);
        f.Revocations.Pending.Clear(); f.Revocations.Offline = true; f.Restart(); f.Drain = null; await f.Coordinator.StepAsync();
        Assert.Equal("revoked", (await f.Coordinator.StatusAsync()).State); Assert.Empty(f.Revocations.Completed);
        f.Revocations.Offline = false; await f.Coordinator.StepAsync(); Assert.Single(f.Revocations.Completed);
    }
    [Theory]
    [InlineData("epoch")]
    [InlineData("grant")]
    [InlineData("file")]
    [InlineData("rdp")]
    [InlineData("origin")]
    [InlineData("peer")]
    [InlineData("signature")]
    public async Task ForeignOrOverbroadRevocationDoesNotTouchLocalAuthority(string field)
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f); var request = f.RevokeRequest();
        request = field switch {
            "epoch" => request with { PairingId = Guid.NewGuid().ToString("D") },
            "grant" => request with { GrantId = Guid.NewGuid().ToString("D") },
            "file" => request with { FileGrantId = Guid.NewGuid().ToString("D") },
            "rdp" => request with { RdpGrantId = Guid.NewGuid().ToString("D") },
            "origin" => request with { RelayOrigin = "https://other.example.test" },
            "peer" => request with { PeerDeviceId = new string('a', 64) },
            _ => request,
        };
        request = f.Sign(request);
        if (field == "signature") request = request with { SignatureBase64 = Convert.ToBase64String(new byte[64]) };
        f.Deliver(request); await f.Coordinator.StepAsync();
        Assert.Empty(f.Revocations.Completed); Assert.Null(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.Null(Assert.Single(f.Grants.ListLocally()).RevokedAt);
    }
    [Fact]
    public async Task DelayedOldEpochRequestCannotRevokeNewPairingOrCancelItsWork()
    {
        using var f = new EnrollmentFixture(mailbox: true); await Bound(f); var old = f.RevokeRequest();
        await f.Coordinator.RevokeAsync((await f.Coordinator.StatusAsync()).InvitationId!.Value);
        var fresh = f.Request with { PairingID = Guid.NewGuid(), GrantID = Guid.NewGuid(), FileGrantID = Guid.NewGuid(), RdpGrantID = Guid.NewGuid() };
        f.Pairings.ApproveLocally(fresh.Pairing(), fresh.ControllerDeviceID);
        f.Grants.ApproveLocally(new(fresh.ControllerDeviceID, fresh.GrantID, DateTimeOffset.MaxValue, Enum.GetValues<ControlOperation>(), ["powershell.v1"], true));
        var calls = f.DrainCalls; f.Deliver(old); await f.Coordinator.StepAsync();
        Assert.Single(f.Revocations.Completed); Assert.Equal(calls, f.DrainCalls);
        Assert.Equal(fresh.PairingID, (await f.Pairings.FindAsync(fresh.ControllerDeviceID))!.PairingId);
        Assert.Null(f.Grants.ListLocally().Single(g => g.GrantId == fresh.GrantID).RevokedAt);
    }
    [Fact]
    public async Task OfflineMailboxPollingDoesNotHoldLocalManagementLock()
    {
        using var f = new EnrollmentFixture(mailbox: true);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Revocations.PollWait = release.Task;
        var step = f.Coordinator.StepAsync();
        try { Assert.Equal("idle", (await f.Coordinator.StatusAsync().WaitAsync(TimeSpan.FromSeconds(2))).State); }
        finally { release.TrySetResult(); await step; }
    }
    [Fact]
    public async Task ExistingDelegatedJsonInstallationCanRevokeWithoutCodeAttemptHistory()
    {
        using var f = new EnrollmentFixture(mailbox: true);
        f.Pairings.ApproveLocally(f.Request.Pairing(), f.Request.ControllerDeviceID);
        f.Grants.ApproveLocally(new(f.Request.ControllerDeviceID, f.Request.GrantID, DateTimeOffset.MaxValue,
            Enum.GetValues<ControlOperation>(), ["powershell.v1"], true));
        f.Deliver(f.RevokeRequest()); await f.Coordinator.StepAsync();
        Assert.Single(f.Revocations.Completed); Assert.NotNull(Assert.Single(f.Pairings.ListLocally()).RevokedAt);
        Assert.NotNull(Assert.Single(f.Grants.ListLocally()).RevokedAt); Assert.Equal(1, f.DrainCalls);
    }
    [Fact]
    public async Task RevokeDuringStagedClaimPreventsLaterConfirmationFromResurrectingIt()
    {
        using var f = new EnrollmentFixture(mailbox: true); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        f.Deliver(f.RevokeRequest()); await f.Coordinator.StepAsync(); f.Confirm(); f.Restart(); await f.Coordinator.StepAsync();
        Assert.Equal("revoked", (await f.Coordinator.StatusAsync()).State); Assert.Equal(0, f.ActivationCalls);
        Assert.NotNull(Assert.Single(f.Pairings.ListLocally()).RevokedAt); Assert.NotNull(Assert.Single(f.Grants.ListLocally()).RevokedAt);
    }
}

internal sealed class FakeRevocationRelay : IRevocationRelay
{
    internal readonly List<RevocationDelivery> Pending = [];
    internal readonly List<RevocationReceipt> Completed = [];
    internal bool LoseCompletion, Offline;
    internal Task? PollWait;
    public async Task<IReadOnlyList<RevocationDelivery>> PollAsync(CancellationToken token)
    { if (Offline) throw new HttpRequestException(); if (PollWait is not null) await PollWait.WaitAsync(token); return Pending.ToArray(); }
    public Task CompleteAsync(RevocationReceipt receipt, CancellationToken token)
    {
        if (Offline) throw new HttpRequestException(); Completed.Add(receipt);
        if (LoseCompletion) { LoseCompletion = false; throw new HttpRequestException(); }
        Pending.RemoveAll(d => d.Revocation.RevocationId == receipt.RevocationId); return Task.CompletedTask;
    }
}
