using System.Text;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class DurableControlGrantTests
{
    [Fact]
    public async Task ApprovalReopensWithExactPolicyAndOwnerIsolation()
    {
        using var f = new ControlPolicyFixture(); var grant = f.Grant();
        using (var store = f.Create())
        {
            var record = store.ApproveLocally(grant);
            Assert.Equal(f.Clock.GetUtcNow(), record.ApprovedAt); Assert.Null(record.RevokedAt);
            Assert.Same(record.Grant, grant);
        }
        using var reopened = f.Open();
        var restored = await reopened.FindAsync(f.Owner, grant.GrantId, default);
        Assert.NotNull(restored); Assert.True(ControlPolicyCodec.SameGrant(grant, restored));
        Assert.Null(await reopened.FindAsync(new string('b', 64), grant.GrantId, default));
        Assert.Equal(1L, f.Sql("PRAGMA user_version;"));
        Assert.Equal("wal", f.Sql("PRAGMA journal_mode;"));
        Assert.DoesNotContain("fixture.sensitive_permission", Encoding.UTF8.GetString(File.ReadAllBytes(f.Path)));
    }

    [Fact]
    public async Task RevocationAndUnknownGrantTombstonesSurviveRestartAndCannotBeReapproved()
    {
        using var f = new ControlPolicyFixture(); var known = f.Grant(); var absent = f.Grant();
        using (var store = f.Create())
        {
            store.ApproveLocally(known);
            await store.RevokeAsync(f.Owner, known.GrantId, default);
            await store.RevokeAsync(f.Owner, absent.GrantId, default);
        }
        using var reopened = f.Open();
        foreach (var grant in new[] { known, absent })
        {
            Assert.Null(await reopened.FindAsync(f.Owner, grant.GrantId, default));
            Assert.Equal("CONTROL_POLICY_GRANT_CONFLICT", Assert.Throws<ControlPolicyException>(() => reopened.ApproveLocally(grant)).Code);
        }
        Assert.All(reopened.ListLocally(), record => Assert.NotNull(record.RevokedAt));
        await reopened.RevokeAsync(f.Owner, known.GrantId, default);
        Assert.Equal(2, reopened.ListLocally().Count);
    }

    [Fact]
    public void GrantIdentifierCannotChangeOwnerExpiryOrPermissions()
    {
        using var f = new ControlPolicyFixture(); using var store = f.Create(); var grant = f.Grant();
        var saved = store.ApproveLocally(grant);
        var repeated = store.ApproveLocally(f.Grant(grant.GrantId));
        Assert.Equal(saved.ApprovedAt, repeated.ApprovedAt);
        Assert.True(ControlPolicyCodec.SameGrant(saved.Grant!, repeated.Grant!));
        var changes = new[] { f.Grant(grant.GrantId, hours: 2), f.Grant(grant.GrantId, owner: new string('b', 64)),
            new ControlGrant(f.Owner, grant.GrantId, grant.ExpiresAt, [ControlOperation.Status], []) };
        foreach (var changed in changes)
            Assert.Equal("CONTROL_POLICY_GRANT_CONFLICT", Assert.Throws<ControlPolicyException>(() => store.ApproveLocally(changed)).Code);
    }

    [Fact]
    public async Task ExpiredOrNotYetApprovedPolicyNeverAuthorizesAndRecordsAreNotEvicted()
    {
        using var f = new ControlPolicyFixture(); using var store = f.Create(capacity: 1); var grant = f.Grant();
        store.ApproveLocally(grant);
        f.Clock.Advance(TimeSpan.FromHours(-1));
        Assert.Null(await store.FindAsync(f.Owner, grant.GrantId, default));
        f.Clock.Advance(TimeSpan.FromHours(2));
        Assert.Null(await store.FindAsync(f.Owner, grant.GrantId, default));
        Assert.Equal("CONTROL_POLICY_CAPACITY", Assert.Throws<ControlPolicyException>(() => store.ApproveLocally(f.Grant())).Code);
        await store.RevokeAsync(f.Owner, grant.GrantId, default); // Existing revocation still fits a full registry.
        Assert.NotNull(Assert.Single(store.ListLocally()).RevokedAt);
    }

    [Fact]
    public async Task CancelledMutationNeverCommitsAndWrongOwnerCannotRevoke()
    {
        using var f = new ControlPolicyFixture(); using var store = f.Create(); var grant = f.Grant(); store.ApproveLocally(grant);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.RevokeAsync(f.Owner, grant.GrantId, cancelled.Token).AsTask());
        await Assert.ThrowsAsync<ControlPolicyException>(() => store.RevokeAsync(new string('b', 64), grant.GrantId, default).AsTask());
        Assert.NotNull(await store.FindAsync(f.Owner, grant.GrantId, default));
    }

    [Fact]
    public void MissingExistingOrWrongKeyStoreIsNeverSilentlyReinitialized()
    {
        using var f = new ControlPolicyFixture();
        Assert.Equal("CONTROL_POLICY_NOT_INITIALIZED", Assert.Throws<ControlPolicyException>(() => f.Open()).Code);
        Assert.False(File.Exists(f.Path));
        using (var store = f.Create()) store.ApproveLocally(f.Grant());
        Assert.Throws<IOException>(() => f.Create());
        using var wrong = new FixtureProtector();
        Assert.Equal("CONTROL_POLICY_INVALID", Assert.Throws<ControlPolicyException>(() => new DurableControlGrantStore(f.Path, wrong)).Code);
        using var valid = f.Open(); Assert.Single(valid.ListLocally());
    }

    [Fact]
    public void StoreLeaseAndSymlinkTargetsAreRejected()
    {
        using var f = new ControlPolicyFixture();
        using (var store = f.Create()) Assert.Throws<IOException>(() => f.Open());
        var link = Path.Combine(f.Directory.FullName, "linked.sqlite");
        // Windows symlink creation requires a separate privilege; its reparse behavior is a real Windows gate.
        if (!OperatingSystem.IsWindows())
        {
            File.CreateSymbolicLink(link, f.Path);
            Assert.Throws<ArgumentException>(() => new DurableControlGrantStore(link, f.Protector));
        }
    }
}
