using Xunit;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Pairing.Tests;

public sealed class PairingPersistenceTests
{
    [Theory]
    [InlineData(RelayTlsPolicy.Tls13)]
    [InlineData(RelayTlsPolicy.ExplicitWindows10Tls12)]
    public async Task AllThreeLanePoliciesReopenExactlyWithSealedGrantBindings(RelayTlsPolicy tls)
    {
        using var f = new PairingFixture();
        var grants = Enum.GetValues<RelayLane>().ToDictionary(l => l, _ => (IReadOnlyList<Guid>)new[] { Guid.NewGuid() });
        var policy = f.Policy(tls: tls, lanes: Enum.GetValues<RelayLane>(), grants: grants);
        using (var store = f.Create())
        {
            var approved = store.ApproveLocally(policy, f.PeerId); Assert.Null(approved.RevokedAt);
            Assert.Equal(f.Clock.GetUtcNow(), approved.ApprovedAt);
            Assert.Equal("wal", f.Sql("PRAGMA journal_mode;"));
            foreach (var file in System.IO.Directory.GetFiles(f.Directory.FullName).Where(p => !p.EndsWith(".lease", StringComparison.Ordinal)))
            {
                var bytes = File.ReadAllBytes(file);
                foreach (var id in grants.Values.SelectMany(v => v)) Assert.True(bytes.AsSpan().IndexOf(id.ToByteArray()) < 0);
            }
        }
        using var reopened = f.Open(); var restored = await reopened.FindAsync(f.PeerId);
        Assert.NotNull(restored); Assert.True(policy.SamePolicy(restored));
        Assert.Null(await reopened.FindAsync(new string('c', 64))); Assert.Equal(1L, f.Sql("PRAGMA user_version;"));
    }

    [Fact]
    public async Task RevokedKnownAndUnknownEpochsRemainTombstonedAcrossReopen()
    {
        using var f = new PairingFixture(); var known = f.Policy(); var absent = f.Policy();
        using (var store = f.Create())
        {
            store.ApproveLocally(known, f.PeerId); await store.RevokeAsync(f.PeerId, known.PairingId);
            await store.RevokeAsync(f.PeerId, absent.PairingId);
        }
        using var reopened = f.Open(); Assert.Null(await reopened.FindAsync(f.PeerId));
        foreach (var policy in new[] { known, absent })
        {
            Assert.Equal("PAIRING_EPOCH_CONFLICT", Assert.Throws<PairingStoreException>(() => reopened.ApproveLocally(policy, f.PeerId)).Code);
            await reopened.RevokeAsync(f.PeerId, policy.PairingId);
        }
        Assert.Equal(2, reopened.ListLocally().Count); Assert.All(reopened.ListLocally(), r => Assert.NotNull(r.RevokedAt));
    }

    [Fact]
    public async Task NewEpochRequiresPriorRevocationAndDoesNotInheritOldGrants()
    {
        using var f = new PairingFixture(); using var store = f.Create(); var grant = Guid.NewGuid();
        var old = f.Policy(grants: new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.Control] = [grant] });
        store.ApproveLocally(old, f.PeerId); var next = f.Policy();
        Assert.Equal("PAIRING_PEER_ALREADY_PAIRED", Assert.Throws<PairingStoreException>(() => store.ApproveLocally(next, f.PeerId)).Code);
        await store.RevokeAsync(f.PeerId, old.PairingId); store.ApproveLocally(next, f.PeerId);
        Assert.Empty((await store.FindAsync(f.PeerId))!.GrantsFor(RelayLane.Control));
        Assert.Equal("PAIRING_EPOCH_CONFLICT", (await Assert.ThrowsAsync<PairingStoreException>(() => store.RevokeAsync(f.PeerId, old.PairingId).AsTask())).Code);
        Assert.Equal(next.PairingId, (await store.FindAsync(f.PeerId))!.PairingId);
    }

    [Fact]
    public async Task ExpiryAndBackwardsClockCannotAuthorizeAndCapacityDoesNotEvictHistory()
    {
        using var f = new PairingFixture(); using var store = f.Create(1); var policy = f.Policy(); store.ApproveLocally(policy, f.PeerId);
        f.Clock.Advance(TimeSpan.FromMinutes(-1)); Assert.Null(await store.FindAsync(f.PeerId));
        f.Clock.Advance(TimeSpan.FromHours(2)); Assert.Null(await store.FindAsync(f.PeerId));
        await store.RevokeAsync(f.PeerId, policy.PairingId);
        Assert.Equal("PAIRING_STORE_CAPACITY", Assert.Throws<PairingStoreException>(() => store.ApproveLocally(f.Policy(), f.PeerId)).Code);
        Assert.NotNull(Assert.Single(store.ListLocally()).RevokedAt);
    }

    [Fact]
    public async Task CancelledOrWrongOwnerRevocationCannotChangeApproval()
    {
        using var f = new PairingFixture(); using var store = f.Create(); var policy = f.Policy(); store.ApproveLocally(policy, f.PeerId);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.RevokeAsync(f.PeerId, policy.PairingId, cancelled.Token).AsTask());
        await Assert.ThrowsAsync<PairingStoreException>(() => store.RevokeAsync(new string('c', 64), policy.PairingId).AsTask());
        Assert.NotNull(await store.FindAsync(f.PeerId));
    }

    [Fact]
    public async Task IdenticalRepeatedApprovalIsIdempotentButChangesConflict()
    {
        using var f = new PairingFixture(); using var store = f.Create(); var policy = f.Policy();
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => store.ApproveLocally(policy, f.PeerId))));
        Assert.All(results, r => Assert.Equal(results[0].ApprovedAt, r.ApprovedAt)); Assert.Single(store.ListLocally());
        var changed = f.Policy(id: policy.PairingId, tls: RelayTlsPolicy.ExplicitWindows10Tls12);
        Assert.Equal("PAIRING_EPOCH_CONFLICT", Assert.Throws<PairingStoreException>(() => store.ApproveLocally(changed, f.PeerId)).Code);
    }

    [Fact]
    public void MissingStoreWrongProtectorAndWrongLocalIdentityNeverReinitialize()
    {
        using var f = new PairingFixture();
        Assert.Equal("PAIRING_STORE_NOT_INITIALIZED", Assert.Throws<PairingStoreException>(() => f.Open()).Code); Assert.False(File.Exists(f.Path));
        using (var store = f.Create()) store.ApproveLocally(f.Policy(), f.PeerId);
        Assert.Throws<IOException>(() => f.Create()); using var wrong = new TestProtector();
        Assert.Equal("PAIRING_STORE_INVALID", Assert.Throws<PairingStoreException>(() => new DurableRelayPairingStore(f.Path, f.LocalId, wrong)).Code);
        Assert.Equal("PAIRING_STORE_INVALID", Assert.Throws<PairingStoreException>(() => new DurableRelayPairingStore(f.Path, new string('c', 64), f.Protector)).Code);
        using var reopened = f.Open(); Assert.Single(reopened.ListLocally());
    }

    [Fact]
    public void ConfirmationMustMatchPeerAndCannotApproveSelf()
    {
        using var f = new PairingFixture(); using var store = f.Create();
        Assert.Equal("PAIRING_CONFIRMATION_MISMATCH", Assert.Throws<PairingStoreException>(() => store.ApproveLocally(f.Policy(), f.LocalId)).Code);
        Assert.Equal("PAIRING_CONFIRMATION_MISMATCH", Assert.Throws<PairingStoreException>(() => store.ApproveLocally(f.Policy(peer: f.LocalId), f.LocalId)).Code);
        Assert.Empty(store.ListLocally());
    }

    [Fact]
    public void LeaseReparsePathAndUnboundedInventoryAreRejected()
    {
        using var f = new PairingFixture();
        using (var store = f.Create())
        {
            Assert.Throws<IOException>(() => f.Open());
            Assert.Throws<ArgumentOutOfRangeException>(() => store.ListLocally(count: 65));
            Assert.Throws<ArgumentOutOfRangeException>(() => store.ListLocally(offset: -1));
        }
        if (!OperatingSystem.IsWindows())
        {
            var link = System.IO.Path.Combine(f.Directory.FullName, "linked.sqlite"); File.CreateSymbolicLink(link, f.Path);
            Assert.Throws<ArgumentException>(() => new DurableRelayPairingStore(link, f.LocalId, f.Protector));
        }
    }
}
