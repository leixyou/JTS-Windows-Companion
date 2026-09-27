using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class DurablePairingControlTests
{
    [Fact]
    public async Task DurableAdapterProjectsOnlyControlGrantIdsAndRevocationSurvivesRestart()
    {
        using var f = new ControlPolicyFixture(); var localId = new string('b', 64);
        var path = Path.Combine(f.Directory.FullName, "pairings.sqlite"); var grant = Guid.NewGuid(); var fileGrant = Guid.NewGuid();
        var policy = new RelayDevicePairing(Guid.NewGuid(), f.Owner, RelayTlsPolicy.Tls13, f.Clock.GetUtcNow().AddHours(1),
            [RelayLane.Control, RelayLane.File, RelayLane.Rdp], new Dictionary<RelayLane, IReadOnlyList<Guid>>
            { [RelayLane.Control] = [grant], [RelayLane.File] = [fileGrant] });
        using (var store = DurableRelayPairingStore.CreateNew(path, localId, f.Protector, clock: f.Clock)) store.ApproveLocally(policy, f.Owner);
        using (var reopened = new DurableRelayPairingStore(path, localId, f.Protector, clock: f.Clock))
        {
            var adapter = new DurableControlRelayPairings(reopened);
            var found = await adapter.FindAsync(f.Owner, default); Assert.NotNull(found);
            Assert.True(found.IncludesGrant(grant)); Assert.False(found.IncludesGrant(fileGrant)); Assert.Equal(policy.PairingId, found.PairingId);
            await adapter.RevokeAsync(f.Owner, policy.PairingId, default);
        }
        using var final = new DurableRelayPairingStore(path, localId, f.Protector, clock: f.Clock);
        Assert.Null(await new DurableControlRelayPairings(final).FindAsync(f.Owner, default));
    }

    [Fact]
    public async Task FileOnlyPairingCannotAuthorizeControlOrActivateOldCapabilities()
    {
        using var f = new ControlPolicyFixture(); using var grants = f.Create(); var grant = f.Grant(); grants.ApproveLocally(grant);
        using var store = DurableRelayPairingStore.CreateNew(Path.Combine(f.Directory.FullName, "pairings.sqlite"), new string('b', 64), f.Protector, clock: f.Clock);
        store.ApproveLocally(new(Guid.NewGuid(), f.Owner, RelayTlsPolicy.Tls13, f.Clock.GetUtcNow().AddHours(1), [RelayLane.File]), f.Owner);
        var adapter = new DurableControlRelayPairings(store);
        Assert.Null(await adapter.FindAsync(f.Owner, default));
        Assert.Null(await new PairingBoundControlGrants(grants, adapter, f.Clock).FindAsync(f.Owner, grant.GrantId, default));
        Assert.NotNull(await grants.FindAsync(f.Owner, grant.GrantId, default));
    }

    [Fact]
    public async Task ServiceRejectsPairingRegistryForDifferentLocalIdentityBeforeAttachingRuntime()
    {
        using var f = new ControlPolicyFixture(); using var grants = f.Create();
        using var pairings = DurableRelayPairingStore.CreateNew(Path.Combine(f.Directory.FullName, "pairings.sqlite"), new string('c', 64), f.Protector, clock: f.Clock);
        using var jobs = DurableJobStore.CreateNew(Path.Combine(f.Directory.FullName, "jobs.sqlite"), f.Protector, clock: f.Clock);
        Assert.Equal("CONTROL_PAIRING_LOCAL_IDENTITY_MISMATCH", Assert.Throws<ControlProtocolException>(() =>
            new CompanionRelayControlService(new FakeRelayConnector(), jobs, grants, new DurableControlRelayPairings(pairings),
                new PolicyTestExecutor(), f.Clock, RelayControlTiming.Default)).Code);
        await using var runtime = new DurableJobRuntime(jobs, new PolicyTestAuthority(grants), new PolicyTestExecutor(), f.Clock);
    }

    [Fact]
    public async Task RestartedServiceDoesNotRunDetachedReceiptUnderUnlinkedPairingGrant()
    {
        using var f = new ControlPolicyFixture(); using var grants = f.Create(); var grant = f.Grant(); grants.ApproveLocally(grant);
        using var jobs = DurableJobStore.CreateNew(Path.Combine(f.Directory.FullName, "jobs.sqlite"), f.Protector, clock: f.Clock);
        var executor = new PolicyTestExecutor(); var id = Guid.NewGuid();
        await using (var before = new DurableJobRuntime(jobs, new PolicyTestAuthority(grants), executor, f.Clock))
            await before.SubmitAsync(new(id, "fixture.sensitive_permission", f.Owner, grant.GrantId,
                f.Clock.GetUtcNow().AddMinutes(1), new byte[] { 1 }, true));
        using var pairings = DurableRelayPairingStore.CreateNew(Path.Combine(f.Directory.FullName, "pairings.sqlite"), new string('b', 64), f.Protector, clock: f.Clock);
        pairings.ApproveLocally(new(Guid.NewGuid(), f.Owner, RelayTlsPolicy.Tls13, f.Clock.GetUtcNow().AddHours(1), [RelayLane.Control]), f.Owner);
        await using var service = new CompanionRelayControlService(new FakeRelayConnector(), jobs, grants,
            new DurableControlRelayPairings(pairings), executor, f.Clock, RelayControlTiming.Default);
        _ = service.RunAsync();
        await RelayServiceFixture.Until(() => jobs.Get(id, f.Owner, grant.GrantId).State == DurableJobState.Cancelled);
        Assert.Equal(0, executor.Executions);
    }
}
