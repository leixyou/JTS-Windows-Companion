using System.Net.Http;
using JTS.WindowsCompanion.Relay;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class RelayControlServiceTests
{
    [Fact]
    public async Task FirstInstallWaitsForAdmissionThenUsesNormalFatalRevocationRules()
    {
        await using var f = new RelayServiceFixture(waitForRelayAdmission: true); var admitted = false;
        f.Connector.Touch = _ => admitted ? Task.CompletedTask : throw new RelayProtocolException("RELAY_HTTP_403");
        var run = f.Start(); await RelayServiceFixture.Until(() => f.Connector.PresenceCount >= 2);
        Assert.Equal(0, f.Connector.PollCount); Assert.Equal("CONTROL_RELAY_ADMISSION_REQUIRED", f.Service.Status.Code);
        admitted = true; await RelayServiceFixture.Until(() => f.Connector.PollCount > 0);
        admitted = false;
        await Assert.ThrowsAsync<ControlProtocolException>(() => run);
        Assert.Equal(RelayControlServiceState.Faulted, f.Service.Status.State);
    }
    [Fact]
    public async Task PendingAdmissionCanBeCancelledAndNeverStartsBusinessSessions()
    {
        await using var f = new RelayServiceFixture(waitForRelayAdmission: true);
        f.Connector.Touch = _ => throw new RelayProtocolException("RELAY_HTTP_401");
        var run = f.Start(); await RelayServiceFixture.Until(() => f.Connector.PresenceCount >= 2);
        await f.Service.DisposeAsync(); await run.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(0, f.Connector.PollCount); Assert.Empty(f.Connector.Served);
        Assert.Equal(RelayControlServiceState.Stopped, f.Service.Status.State);
    }
    [Fact]
    public async Task PresenceContinuesWhileSessionRunsAndStopDrainsWithoutRestart()
    {
        await using var f = new RelayServiceFixture(); f.Connector.Batches.Enqueue([f.Offer()]);
        var run = f.Start();
        await RelayServiceFixture.Until(() => f.Connector.Served.Count == 1 && f.Connector.PresenceCount >= 2);
        Assert.Equal(RelayControlServiceState.Online, f.Service.Status.State);
        await Assert.ThrowsAsync<ControlProtocolException>(() => f.Service.RunAsync());
        await f.Service.DisposeAsync(); await run;
        Assert.Equal(1, f.Connector.ClosedCount); Assert.Equal(RelayControlServiceState.Stopped, f.Service.Status.State);
    }

    [Theory]
    [InlineData("401")]
    [InlineData("403")]
    [InlineData("version")]
    [InlineData("tls")]
    public async Task TrustAndProtocolFailureStopsInsteadOfBlindReconnect(string kind)
    {
        await using var f = new RelayServiceFixture();
        f.Connector.Touch = _ => throw (kind == "tls"
            ? new HttpRequestException(HttpRequestError.SecureConnectionError, "fixture-private")
            : new RelayProtocolException(kind == "version" ? "RELAY_VERSION_UNSUPPORTED" : "RELAY_HTTP_" + kind));
        var error = await Assert.ThrowsAsync<ControlProtocolException>(() => f.Start());
        Assert.Equal("CONTROL_RELAY_STOPPED_UNEXPECTEDLY", error.Code);
        Assert.Equal(1, f.Connector.PresenceCount); Assert.Equal(0, f.Connector.PollCount);
        Assert.Equal(RelayControlServiceState.Faulted, f.Service.Status.State);
        Assert.DoesNotContain("fixture-private", f.Service.Status.ToString());
    }

    [Fact]
    public async Task TransientOutageRetriesPresenceAndPollingButDoesNotReopenExistingOffer()
    {
        await using var f = new RelayServiceFixture(); var offer = f.Offer();
        f.Connector.Poll = _ => f.Connector.PollCount == 2
            ? throw new RelayProtocolException("RELAY_HTTP_503")
            : Task.FromResult<IReadOnlyList<RelayChannelOffer>>([f.Offer(id: offer.Binding.SessionId)]);
        _ = f.Start(); await RelayServiceFixture.Until(() => f.Connector.PollCount >= 4);
        Assert.Single(f.Connector.Served); Assert.True(f.Connector.PresenceCount >= 2);
        Assert.Equal(RelayControlServiceState.Online, f.Service.Status.State);
    }

    [Fact]
    public async Task FailedChannelIsVisibleAndSameSessionIsNeverRetried()
    {
        await using var f = new RelayServiceFixture(); var id = Guid.NewGuid();
        f.Connector.Poll = _ => Task.FromResult<IReadOnlyList<RelayChannelOffer>>([f.Offer(id: id)]);
        f.Connector.Serve = (_, _, _) => throw new IOException("private-ticket-not-for-status");
        _ = f.Start(); await RelayServiceFixture.Until(() => f.Connector.PollCount >= 3);
        Assert.Single(f.Connector.Served); Assert.Equal("CONTROL_RELAY_SESSION_FAILED", f.Service.LastSessionError);
    }

    [Fact]
    public async Task UnpairedAndNonControlOffersDoNotReachBusinessHandler()
    {
        await using var f = new RelayServiceFixture(); var control = f.Offer();
        f.Connector.Batches.Enqueue([f.Offer(RelayLane.File), f.Offer(RelayLane.Rdp), f.Offer(owner: new string('c', 64)), control]);
        _ = f.Start(); await RelayServiceFixture.Until(() => f.Connector.PollCount >= 2);
        Assert.Equal(control.Binding.SessionId, Assert.Single(f.Connector.Served));
    }

    [Fact]
    public async Task PerPeerCapacityDefersWithoutBurningOffersOrBlockingPolling()
    {
        await using var f = new RelayServiceFixture(); var offers = Enumerable.Range(0, 6).Select(_ => f.Offer()).ToArray();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Connector.Poll = _ => Task.FromResult<IReadOnlyList<RelayChannelOffer>>(offers);
        f.Connector.Serve = (_, _, token) => release.Task.WaitAsync(token);
        _ = f.Start(); await RelayServiceFixture.Until(() => f.Connector.PollCount >= 3);
        Assert.Equal(4, f.Connector.Served.Count); release.SetResult();
        await RelayServiceFixture.Until(() => f.Connector.Served.Count == 6);
        Assert.Equal(6, f.Connector.Served.Distinct().Count());
    }

    [Fact]
    public async Task RevocationAfterDurableCommitClosesSessionDespiteCallerCancellation()
    {
        await using var f = new RelayServiceFixture(); using var caller = new CancellationTokenSource();
        var pairing = f.Pairing!; var offer = f.Offer();
        f.Connector.Poll = _ => Task.FromResult<IReadOnlyList<RelayChannelOffer>>([offer]);
        f.AfterRevoke = caller.Cancel;
        _ = f.Start(); await RelayServiceFixture.Until(() => f.Connector.Served.Count == 1);
        await f.Service.RevokePairingAsync(f.Owner, pairing.PairingId, caller.Token);
        await RelayServiceFixture.Until(() => f.Connector.ClosedCount == 1);
        Assert.Null(f.Pairing); Assert.True(caller.IsCancellationRequested);
        Assert.Single(f.Connector.Served);
    }

    [Fact]
    public async Task FailedPairingReadStopsServiceAndFailedRevokeNeverClaimsDurableSuccess()
    {
        await using var f = new RelayServiceFixture(); f.Connector.Batches.Enqueue([f.Offer()]);
        f.PairingReadFails = true;
        await Assert.ThrowsAsync<ControlProtocolException>(() => f.Start());
        Assert.Empty(f.Connector.Served); Assert.NotNull(f.Pairing);
    }

    [Fact]
    public async Task FailedDurableRevokeClosesLiveConnectionsAndKeepsFaultVisible()
    {
        await using var f = new RelayServiceFixture(); f.Connector.Batches.Enqueue([f.Offer()]);
        var run = f.Start(); await RelayServiceFixture.Until(() => f.Connector.Served.Count == 1);
        f.RevokeFails = true;
        Assert.Equal("CONTROL_PAIRING_REVOCATION_NOT_DURABLE", (await Assert.ThrowsAsync<ControlProtocolException>(() =>
            f.Service.RevokePairingAsync(f.Owner, f.Pairing!.PairingId).AsTask())).Code);
        await run; Assert.NotNull(f.Pairing); Assert.Equal(1, f.Connector.ClosedCount);
        Assert.Equal(RelayControlServiceState.Faulted, f.Service.Status.State);
    }

    [Fact]
    public async Task ChangedPairingEpochCancelsOldSessionsInsteadOfSilentlyAdoptingNewTrust()
    {
        await using var f = new RelayServiceFixture(); f.Connector.Batches.Enqueue([f.Offer()]);
        _ = f.Start(); await RelayServiceFixture.Until(() => f.Connector.Served.Count == 1);
        f.Pairing = new(Guid.NewGuid(), f.Pairing!.Trust, f.Pairing.ExpiresAt, [f.GrantId]);
        await RelayServiceFixture.Until(() => f.Connector.ClosedCount == 1);
        f.Connector.Batches.Enqueue([f.Offer()]);
        var polls = f.Connector.PollCount; await RelayServiceFixture.Until(() => f.Connector.PollCount >= polls + 2);
        Assert.Single(f.Connector.Served);
    }
}
