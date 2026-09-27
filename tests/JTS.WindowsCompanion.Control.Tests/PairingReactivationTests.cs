using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class PairingReactivationTests
{
    [Fact]
    public async Task NewDurableEpochExplicitlyReopensAllLanesWithoutAdmittingTheOldGrant()
    {
        await using var f = new RelayServiceFixture(); f.Connector.AllLanes = true;
        var old = f.Pairing!; f.Connector.Batches.Enqueue([f.Offer()]);
        _ = f.Start(); await RelayServiceFixture.Until(() => f.Connector.Served.Count == 1);
        await f.Service.RevokePairingAsync(f.Owner, old.PairingId);
        await RelayServiceFixture.Until(() => f.Connector.ClosedCount == 1);
        var freshGrant = Guid.NewGuid();
        f.AdditionalGrants[freshGrant] = new(f.Owner, freshGrant, DateTimeOffset.UtcNow.AddHours(1),
            Enum.GetValues<ControlOperation>(), ["fixture.echo"], true);
        f.Pairing = new(Guid.NewGuid(), new(f.Owner, RelayTlsPolicy.Tls13, [RelayLane.Control, RelayLane.File, RelayLane.Rdp]),
            DateTimeOffset.UtcNow.AddMinutes(30), [freshGrant]);
        await Assert.ThrowsAsync<ControlProtocolException>(() => f.Service.ActivatePairingAsync(f.Owner, old.PairingId).AsTask());
        f.Connector.Batches.Enqueue([f.Offer()]);
        var before = f.Connector.PollCount; await RelayServiceFixture.Until(() => f.Connector.PollCount > before + 1);
        Assert.Single(f.Connector.Served); // Persisting new trust alone cannot clear a live revocation.
        await f.Service.ActivatePairingAsync(f.Owner, f.Pairing.PairingId);
        var checkedGrants = 0;
        f.Connector.Serve = async (host, _, token) =>
        {
            Assert.Equal(freshGrant, (await host.RequireGrantAsync(f.Owner, freshGrant, ControlOperation.Submit, token)).GrantId);
            Assert.Equal("CONTROL_GRANT_REJECTED", (await Assert.ThrowsAsync<ControlProtocolException>(() =>
                host.RequireGrantAsync(f.Owner, f.GrantId, ControlOperation.Submit, token).AsTask())).Code);
            Interlocked.Increment(ref checkedGrants);
            await Task.Delay(Timeout.Infinite, token);
        };
        f.Connector.Batches.Enqueue([f.Offer(), f.Offer(RelayLane.File), f.Offer(RelayLane.Rdp)]);
        await RelayServiceFixture.Until(() => checkedGrants == 3);
        Assert.Equal(4, f.Connector.Served.Count);
        await f.Service.ActivatePairingAsync(f.Owner, f.Pairing.PairingId).AsTask().WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, f.Connector.ClosedCount); // Replaying the same activation does not drain its new live channels.
    }

    [Fact]
    public async Task NewGrantCanExecuteAfterRebindingWhileOldJobsAndGrantStayRevoked()
    {
        await using var f = new ControlFixture(durableGrants: true);
        await using var oldConnection = await f.ConnectAsync(); var oldJob = Guid.NewGuid();
        using var started = await oldConnection.CallAsync("job.submit", f.Submission(oldJob, "fixture.block", true));
        Assert.True(started.RootElement.GetProperty("ok").GetBoolean());
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        f.Host.RevokePeer(f.ClientIdentity.DeviceId);
        await f.Host.RevokeGrantDurablyAsync(f.ClientIdentity.DeviceId, f.GrantId);
        await f.WaitForAsync(oldJob, DurableJobState.Cancelled);
        var newGrant = Guid.NewGuid();
        f.DurableGrants!.ApproveLocally(new(f.ClientIdentity.DeviceId, newGrant, DateTimeOffset.UtcNow.AddHours(1),
            Enum.GetValues<ControlOperation>(), ["fixture.echo"], true));
        await f.Host.ActivatePeerGrantsAsync(f.ClientIdentity.DeviceId, [newGrant], default);
        await using var fresh = await f.ConnectAsync();
        using var denied = await fresh.CallAsync("job.submit", f.Submission(Guid.NewGuid(), detached: true), f.GrantId);
        Assert.False(denied.RootElement.GetProperty("ok").GetBoolean());
        var newJob = Guid.NewGuid();
        using var accepted = await fresh.CallAsync("job.submit", f.Submission(newJob, detached: true), newGrant);
        Assert.True(accepted.RootElement.GetProperty("ok").GetBoolean());
        await RelayServiceFixture.Until(() => f.Store.Get(newJob, f.ClientIdentity.DeviceId, newGrant).State == DurableJobState.Succeeded);
        Assert.Equal(DurableJobState.Cancelled, f.Store.Get(oldJob, f.ClientIdentity.DeviceId, f.GrantId).State);
        Assert.Null(await f.DurableGrants.FindAsync(f.ClientIdentity.DeviceId, f.GrantId, default));
        Assert.Equal(2, f.Executions);
    }
}
