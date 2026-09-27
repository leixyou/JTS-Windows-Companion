using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class DurableControlHostTests
{
    [Fact]
    public async Task DurableRevokeStopsActiveDetachedTaskAndRejectsReconnect()
    {
        await using var f = new ControlFixture(durableGrants: true);
        await using var client = await f.ConnectAsync(); var id = Guid.NewGuid();
        using var receipt = await client.CallAsync("job.submit", f.Submission(id, "fixture.block", true));
        Assert.True(receipt.RootElement.GetProperty("ok").GetBoolean());
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await f.Host.RevokeGrantDurablyAsync(f.ClientIdentity.DeviceId, f.GrantId);
        Assert.NotNull(Assert.Single(f.DurableGrants!.ListLocally()).RevokedAt);
        await f.WaitForAsync(id, DurableJobState.Cancelled);
        await using var reconnect = await f.ConnectAsync();
        using var denied = await reconnect.CallAsync("device.status", new { });
        Assert.Equal("CONTROL_GRANT_REJECTED", denied.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task CancellationAfterDurableCommitCannotSkipLiveRevocation()
    {
        using var caller = new CancellationTokenSource();
        await using var f = new ControlFixture(true, store => new AfterCommitCancellation(store, caller));
        await using var client = await f.ConnectAsync(); var id = Guid.NewGuid();
        using var receipt = await client.CallAsync("job.submit", f.Submission(id, "fixture.block", true));
        Assert.True(receipt.RootElement.GetProperty("ok").GetBoolean());
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await f.Host.RevokeGrantDurablyAsync(f.ClientIdentity.DeviceId, f.GrantId, caller.Token);
        Assert.True(caller.IsCancellationRequested);
        await f.WaitForAsync(id, DurableJobState.Cancelled);
    }

    [Fact]
    public async Task FailedPersistenceStopsHostAndDoesNotClaimDurableRevoke()
    {
        await using var f = new ControlFixture(true, store => new FailingRevocation(store));
        await using var client = await f.ConnectAsync(); var id = Guid.NewGuid();
        using var receipt = await client.CallAsync("job.submit", f.Submission(id, "fixture.block", true));
        Assert.True(receipt.RootElement.GetProperty("ok").GetBoolean());
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var error = await Assert.ThrowsAsync<ControlProtocolException>(() => f.Host.RevokeGrantDurablyAsync(f.ClientIdentity.DeviceId, f.GrantId).AsTask());
        Assert.Equal("CONTROL_REVOCATION_NOT_DURABLE", error.Code);
        await f.WaitForAsync(id, DurableJobState.Cancelled);
        Assert.Null(Assert.Single(f.DurableGrants!.ListLocally()).RevokedAt);
        await f.Host.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAnyAsync<Exception>(async () => { await using var _ = await f.ConnectAsync(); });
    }

    [Fact]
    public async Task RestartedSchedulerRechecksDurableRevocationBeforeQueuedExecution()
    {
        using var f = new ControlPolicyFixture(); var grant = f.Grant(); var id = Guid.NewGuid();
        var jobsPath = Path.Combine(f.Directory.FullName, "jobs.sqlite");
        var executor = new PolicyTestExecutor();
        using (var grants = f.Create())
        using (var jobs = DurableJobStore.CreateNew(jobsPath, f.Protector, clock: f.Clock))
        {
            grants.ApproveLocally(grant);
            await using (var runtime = new DurableJobRuntime(jobs, new PolicyTestAuthority(grants), executor, f.Clock))
                await runtime.SubmitAsync(new(id, "fixture.sensitive_permission", f.Owner, grant.GrantId,
                    f.Clock.GetUtcNow().AddMinutes(1), new byte[] { 1 }, allowDisconnected: true));
            await grants.RevokeAsync(f.Owner, grant.GrantId, default);
        }
        using var reopenedGrants = f.Open();
        using var reopenedJobs = new DurableJobStore(jobsPath, f.Protector, clock: f.Clock);
        await using var host = new CompanionControlHost(reopenedJobs, reopenedGrants, executor, f.Clock);
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (reopenedJobs.Get(id, f.Owner, grant.GrantId).State == DurableJobState.Queued) await Task.Delay(10, limit.Token);
        Assert.Equal(DurableJobState.Cancelled, reopenedJobs.Get(id, f.Owner, grant.GrantId).State);
        Assert.Equal(0, executor.Executions);
    }

    [Fact]
    public async Task NonDurableAuthorityCannotClaimDurableRevocation()
    {
        await using var f = new ControlFixture();
        var error = await Assert.ThrowsAsync<ControlProtocolException>(() => f.Host.RevokeGrantDurablyAsync(f.ClientIdentity.DeviceId, f.GrantId).AsTask());
        Assert.Equal("CONTROL_DURABLE_REVOCATION_UNAVAILABLE", error.Code);
    }

    [Fact]
    public async Task ReopenedQuarantinedLedgerCannotStartControlHostScheduler()
    {
        using var f = new ControlPolicyFixture(); using var grants = f.Create();
        var grant = f.Grant(); grants.ApproveLocally(grant);
        var path = Path.Combine(f.Directory.FullName, "jobs.sqlite"); var id = Guid.NewGuid();
        using (var jobs = DurableJobStore.CreateNew(path, f.Protector, clock: f.Clock))
        {
            await using var runtime = new DurableJobRuntime(jobs, new PolicyTestAuthority(grants), new UnknownExecutor(), f.Clock);
            await runtime.SubmitAsync(new(id, "fixture.sensitive_permission", f.Owner, grant.GrantId,
                f.Clock.GetUtcNow().AddMinutes(1), new byte[] { 1 }, allowDisconnected: true));
            Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", (await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.RunNextAsync())).Code);
        }
        using var reopened = new DurableJobStore(path, f.Protector, clock: f.Clock);
        var executor = new PolicyTestExecutor();
        Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", Assert.Throws<JobRuntimeException>(() =>
            new CompanionControlHost(reopened, grants, executor, f.Clock)).Code);
        Assert.Equal(0, executor.Executions);
        Assert.Equal(DurableJobState.Interrupted, reopened.Get(id, f.Owner, grant.GrantId).State);
    }

    private sealed class UnknownExecutor : IJobExecutor
    {
        public ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload,
            IJobOutputSink output, CancellationToken token) => throw new JobExecutionStateUnknownException();
    }

    private sealed class AfterCommitCancellation(DurableControlGrantStore store, CancellationTokenSource caller) : IDurableControlGrantProvider
    {
        public ValueTask<ControlGrant?> FindAsync(string owner, Guid id, CancellationToken token) => store.FindAsync(owner, id, token);
        public async ValueTask RevokeAsync(string owner, Guid id, CancellationToken token)
        { await store.RevokeAsync(owner, id, token); caller.Cancel(); }
    }
    private sealed class FailingRevocation(DurableControlGrantStore store) : IDurableControlGrantProvider
    {
        public ValueTask<ControlGrant?> FindAsync(string owner, Guid id, CancellationToken token) => store.FindAsync(owner, id, token);
        public ValueTask RevokeAsync(string owner, Guid id, CancellationToken token) => throw new IOException("test-only simulated disk failure");
    }
}
