using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class PairingBoundControlTests
{
    [Fact]
    public async Task PairingDoesNotImplicitlyReuseOldCapabilityGrants()
    {
        await using var f = new RelayServiceFixture(); var pairing = f.Pairing!;
        var provider = new PairingBoundControlGrants(f, f, TimeProvider.System);
        Assert.NotNull(await provider.FindAsync(f.Owner, f.GrantId, default));
        f.Pairing = new(Guid.NewGuid(), pairing.Trust, pairing.ExpiresAt);
        Assert.Null(await provider.FindAsync(f.Owner, f.GrantId, default));
    }

    [Fact]
    public async Task DetachedJobGrantIsCappedAtPairingExpiry()
    {
        await using var f = new RelayServiceFixture();
        var grant = await new PairingBoundControlGrants(f, f, TimeProvider.System).FindAsync(f.Owner, f.GrantId, default);
        Assert.Equal(f.Pairing!.ExpiresAt, grant!.ExpiresAt);
        Assert.True(grant.ExpiresAt < f.Grant.ExpiresAt);
    }

    [Fact]
    public async Task ExpiredPairingCannotAuthorizeNewRequests()
    {
        await using var f = new RelayServiceFixture();
        f.Pairing = new(f.Pairing!.PairingId, f.Pairing.Trust, DateTimeOffset.UtcNow.AddSeconds(-1), [f.GrantId]);
        Assert.Null(await new PairingBoundControlGrants(f, f, TimeProvider.System).FindAsync(f.Owner, f.GrantId, default));
    }

    [Fact]
    public async Task PairingRevocationStopsDetachedTaskAndDeniesReconnectWithoutAffectingStoredCapability()
    {
        await using var f = new ControlFixture();
        await using var client = await f.ConnectAsync(); var id = Guid.NewGuid();
        using var receipt = await client.CallAsync("job.submit", f.Submission(id, "fixture.block", true));
        Assert.True(receipt.RootElement.GetProperty("ok").GetBoolean());
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        f.Host.RevokePeer(f.ClientIdentity.DeviceId);
        await f.WaitForAsync(id, Runtime.DurableJobState.Cancelled);
        Assert.Equal("PAIRING_REVOKED", f.Store.Get(id, f.ClientIdentity.DeviceId, f.GrantId).ResultCode);
        Assert.NotNull(f.Grant); // Pairing and capability records remain distinct.
        await Assert.ThrowsAnyAsync<Exception>(async () => { await using var _ = await f.ConnectAsync(); });
    }
}
